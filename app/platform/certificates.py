"""Certificate inventory & management for the unified dashboard.

REAL operations only (the dashboard's Certificates page calls these):

* :func:`scan` — inventory every certificate under the panel data tree:
  issuer/subject, expiry countdown, self-signed detection, key pairing.
* :func:`import_cert` — validate + store a PEM cert/key pair
  (`<data>/certs/<name>/{fullchain,key}.pem`, strict permissions; the pair
  must actually match — a mismatched import is refused, not stored).
* :func:`self_signed` — generate a working self-signed RSA certificate
  (dev/LAN setups; the UI labels it accordingly).
* :func:`remove` — delete a managed certificate directory (path-safe).

ACME / Let's Encrypt automation is deliberately NOT claimed here — tracked
on the roadmap and honestly labeled in the UI.
"""
from __future__ import annotations

import os
import re
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from pydantic import BaseModel

_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$", re.IGNORECASE)


class CertificateInfo(BaseModel):
    name: str
    path: str
    subject: str
    issuer: str
    not_before: datetime
    not_after: datetime
    days_left: int
    expired: bool
    self_signed: bool
    has_key: bool
    serial: str = ""
    #: stable identifier = path relative to the panel data dir (posix). The
    #: inventory scans the WHOLE tree (core work dirs materialize certs too,
    #: e.g. <data>/cores/sing-box/certs/tuic.crt) — a bare NAME cannot
    #: address those, which is why Delete-by-name answered "not found"
    #:. Delete addresses certs by `id`.
    id: str = ""
    #: True when stored in the managed layout <data>/certs/<name>/ (import /
    #: self-signed) — those delete as a directory; scanned core certs delete
    #: as the single file (+ matching private key sibling).
    managed: bool = False


def _certs_root(data_dir: str) -> Path:
    return Path(data_dir) / "certs"


def _safe_name(name: str) -> str:
    if not _NAME_RE.match(name or ""):
        raise ValueError(
            "invalid certificate name — use letters, digits, '-', '_' and '.' "
            "(it becomes a directory under <data>/certs/)")
    return name


def _parse_cert(path: Path, pem: bytes | None = None) -> x509.Certificate:
    try:
        data = pem if pem is not None else path.read_bytes()
        return x509.load_pem_x509_certificate(data)
    except ValueError as exc:
        raise ValueError(f"'{path.name}' is not a valid PEM certificate") from exc


def _cn(name: x509.Name) -> str:
    attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    return attrs[0].value if attrs else name.rfc4514_string()


def certificate_covers(path: str | Path, hostname: str) -> bool:
    """Check DNS/IP SAN identity (with constrained left-most DNS wildcards)."""
    import ipaddress

    cert = _parse_cert(Path(path))
    dns_names: list[str] = []
    ip_names: list[str] = []
    try:
        extension = cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName).value
        dns_names = extension.get_values_for_type(x509.DNSName)
        ip_names = [str(value) for value in
                    extension.get_values_for_type(x509.IPAddress)]
    except x509.ExtensionNotFound:
        pass
    try:
        wanted_ip = str(ipaddress.ip_address(hostname))
    except ValueError:
        wanted_ip = ""
    if wanted_ip:
        # RFC 6125: an IP literal must match an iPAddress SAN, never CN text.
        return any(str(ipaddress.ip_address(value)) == wanted_ip
                   for value in ip_names)

    wanted = hostname.rstrip(".").encode("idna").decode("ascii").lower()
    if not dns_names:
        dns_names = [value.value for value in
                     cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)]
    for raw_pattern in dns_names:
        pattern = raw_pattern.rstrip(".").encode("idna").decode("ascii").lower()
        if pattern == wanted:
            return True
        if pattern.startswith("*."):
            suffix = pattern[1:]
            # Wildcard spans one label only and is valid only in the left-most
            # position (no partial-label or multi-level wildcard matching).
            if wanted.endswith(suffix) and wanted.count(".") == pattern.count("."):
                return True
    return False


def _info_from(path: Path, cert: x509.Certificate, name: str | None = None) -> CertificateInfo:
    now = datetime.now(timezone.utc)
    not_after = cert.not_valid_after_utc
    stem = path.with_suffix("")
    has_key = stem.with_suffix(".key").exists() or (path.parent / "key.pem").exists()
    return CertificateInfo(
        name=name or path.stem,
        path=str(path),
        subject=_cn(cert.subject),
        issuer=_cn(cert.issuer),
        not_before=cert.not_valid_before_utc,
        not_after=not_after,
        days_left=(not_after - now).days,
        expired=not_after <= now,
        self_signed=cert.issuer == cert.subject,
        has_key=has_key,
        serial=hex(cert.serial_number),
    )


def scan(data_dir: str, *, max_depth: int = 5,
         managed_only: bool = True) -> list[CertificateInfo]:
    """Inventory certificates under *data_dir* (depth-limited, read-only).

    managed_only=True (— the registry belongs to the
    OPERATOR): only the managed store ``<data>/certs/<name>/`` is listed.
    Core RUNTIME certs (self-signed material an inbound generated under
    ``cores/<core>/certs/``) are engine plumbing, NOT user-managed
    resources, and must never appear as if the user created them. Pass
    ``managed_only=False`` for diagnostics that intentionally want the
    whole tree (the delete-by-id path still reaches those files elsewhere).
    """
    root = Path(data_dir)
    if not root.is_dir():
        return []
    out: list[CertificateInfo] = []
    seen: set[Path] = set()
    emitted: set[str] = set()
    certs_root = _certs_root(data_dir)
    for pattern in ("*.crt", "*.pem"):
        for path in sorted(root.rglob(pattern)):
            try:
                if len(path.relative_to(root).parts) > max_depth or path in seen:
                    continue
            except ValueError:  # pragma: no cover - rglob stays under root
                continue
            seen.add(path)
            managed = path.parent.parent == certs_root  # certs/<name>/<file>
            if managed_only and not managed:
                continue  # runtime/generated material — not a registry entry
            try:
                info = _info_from(path, _parse_cert(path))
            except ValueError:
                continue  # PEM-shaped files that aren't certs (keys, bundles)
            info.managed = managed
            if managed:
                info.name = path.parent.name
            info.id = path.relative_to(root).as_posix()
            if info.name in emitted:
                continue  # one row per name (fullchain/ca variants collapse)
            emitted.add(info.name)
            out.append(info)
    # deterministic order: soonest-to-expire first (actionable)
    out.sort(key=lambda c: (c.expired is False, c.days_left, c.name))
    return out


def _store_pair(dest: Path, cert_pem: bytes, key_pem: bytes, *, overwrite: bool) -> None:
    if dest.exists() and any(dest.iterdir()) and not overwrite:
        raise FileExistsError(
            f"a certificate named '{dest.name}' already exists — choose another"
            " name or delete it first")
    dest.mkdir(parents=True, exist_ok=True)
    os.chmod(dest, 0o700)
    (dest / "fullchain.pem").write_bytes(cert_pem)
    (dest / "key.pem").write_bytes(key_pem)
    os.chmod(dest / "fullchain.pem", 0o644)
    os.chmod(dest / "key.pem", 0o600)


def import_cert(data_dir: str, name: str, cert_pem: str, key_pem: str,
                *, overwrite: bool = False) -> CertificateInfo:
    """Validate a PEM pair (cert parses, key parses, PAIR MATCHES) and store it."""
    name = _safe_name(name)
    cert = _parse_cert(Path("import.pem"), cert_pem.encode())
    try:
        key = serialization.load_pem_private_key(key_pem.encode(), password=None)
    except ValueError as exc:
        raise ValueError("the private key is not a valid unencrypted PEM key") from exc
    if cert.public_key().public_numbers() != key.public_key().public_numbers():
        raise ValueError("certificate and private key do NOT match — import refused")
    dest = _certs_root(data_dir) / name
    _store_pair(dest, cert_pem.encode(), key_pem.encode(), overwrite=overwrite)
    info = _info_from(dest / "fullchain.pem", cert, name=name)
    info.managed = True
    info.id = (dest / "fullchain.pem").relative_to(Path(data_dir)).as_posix()
    return info


def self_signed(data_dir: str, name: str, common_name: str, *,
                days: int = 3650, san_dns: list[str] | None = None,
                overwrite: bool = False) -> CertificateInfo:
    """Generate a working self-signed certificate (test/LAN use)."""
    if days < 1:
        raise ValueError("days must be >= 1")
    name = _safe_name(name)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc) - timedelta(minutes=5)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    sans = sorted({common_name, *(san_dns or [])})
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject).issuer_name(issuer).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now).not_valid_after(now + timedelta(days=days, minutes=10))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(d) for d in sans]),
                       critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                       critical=False)
    )
    cert = builder.sign(key, hashes.SHA256())
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption())
    dest = _certs_root(data_dir) / name
    _store_pair(dest, cert_pem, key_pem, overwrite=overwrite)
    info = _info_from(dest / "fullchain.pem", cert, name=name)
    info.managed = True
    info.id = (dest / "fullchain.pem").relative_to(Path(data_dir)).as_posix()
    return info


def remove(data_dir: str, ident: str) -> None:
    """Delete a certificate by IDENTIFIER (path-safe, always under data_dir).

    * managed name (no '/', e.g. ``panel.example.com``) → its whole
      ``<data>/certs/<name>/`` directory (legacy caller contract);
    * inventory ``id`` (``certs/<name>/fullchain.pem`` or a core-materialized
      file like ``cores/sing-box/certs/tuic.crt``) → exactly that file plus
      the matching private-key sibling, with the now-empty managed directory
      cleaned up as well. Anything else is refused, honestly.
    """
    data_root = Path(data_dir).resolve()
    if "/" not in ident and "\\" not in ident:
        name = _safe_name(ident)
        dest = (_certs_root(data_dir) / name).resolve()
        root = _certs_root(data_dir).resolve()
        if dest == root or root not in dest.parents:
            raise ValueError("refusing to delete outside the certificates directory")
        if not dest.exists():
            raise FileNotFoundError(f"certificate '{ident}' not found")
        shutil.rmtree(dest)
        return

    target = (data_root / ident).resolve()
    if data_root not in target.parents:
        raise ValueError("refusing to delete outside the panel data directory")
    if target.suffix.lower() not in (".crt", ".pem"):
        raise ValueError("certificate ids must address a .crt/.pem file")
    if not target.exists():
        raise FileNotFoundError(f"certificate '{ident}' not found")
    target.unlink()
    # matching key sibling of the same cert pair (managed: key.pem; scanned:
    # <stem>.key) — a half-deleted pair is a broken pair.
    for sibling in (target.parent / "key.pem",
                    target.with_suffix("").with_suffix(".key")):
        try:
            if sibling.exists():
                sibling.unlink()
        except OSError:
            pass
    # tidy: an emptied managed directory disappears as a unit
    try:
        managed_parent = (_certs_root(data_dir) / target.parent.name).resolve()
        if (target.parent.resolve() == managed_parent
                and managed_parent.is_dir() and not any(managed_parent.iterdir())):
            managed_parent.rmdir()
    except OSError:
        pass
