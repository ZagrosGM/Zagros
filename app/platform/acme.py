"""ACME / Let's Encrypt integration — REAL issuance.

Design: the panel adapts the battle-tested ACME clients the host already
trusts, instead of re-implementing the ACME protocol (and its failure
modes) from scratch:

* **certbot** (preferred; preinstalled in the panel image),
* **acme.sh** (detected in PATH or ``~/.acme.sh/acme.sh``),
* **lego** (detected in PATH).

Every operation is the tool's REAL command line (HTTP-01 standalone):

* :func:`issue` — validate domain → preflight port 80 → client issue →
  export the pair → validated import into the managed store
  (``<data>/certs/<domain>/``) + an ``.acme.json`` bookkeeping sidecar
  (provider, email, timestamps) so renew/delete/status are real too;
* :func:`renew` — client renew (idempotent: a not-yet-due cert copies the
  SAME material back; ``force=True`` passes the client's force flag);
* :func:`remove_acme` — managed-store removal is authoritative, the
  provider-side cleanup is best-effort and honestly reported;
* :func:`acme_status` — provider availability + per-entry overview.

An environment without ANY supported client reports ``available: False``
with an actionable hint — never a fake success. A provider failure surfaces
its own stderr tail, verbatim.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
import shutil
import socket
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)


class ACMEError(RuntimeError):
    """An ACME step failed — message carries the client's own words."""


@dataclass(frozen=True)
class ProviderInfo:
    id: str          # certbot | acme.sh | lego
    name: str
    path: str


_ISSUE_TIMEOUT = 300
_RENEW_TIMEOUT = 240
_DELETE_TIMEOUT = 90

_DOMAIN_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")


def validate_domain(domain: str) -> str:
    """Normalize + validate an issuance domain (HTTP-01 capable, IDNA-safe).

    Returns the ASCII (punycode) form. Wildcards need DNS-01 (not served by
    standalone HTTP-01) and IPs cannot be publicly validated — both are
    rejected loudly instead of failing inside the client run.
    """
    d = (domain or "").strip().rstrip(".").lower()
    if not d:
        raise ACMEError("domain is required")
    if d.startswith("*."):
        raise ACMEError(
            "wildcard certificates need DNS-01 automation — the standalone "
            "HTTP-01 flow cannot issue them (issue per-host FQDNs instead)")
    try:
        ipaddress.ip_address(d)
        raise ACMEError("an IP address cannot be issued by a public ACME CA "
                        "— use a FQDN pointing at this server")
    except ValueError:
        pass  # not an IP literal — the expected path
    try:
        ascii_d = d.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ACMEError(f"'{domain}' is not a valid DNS name: {exc}") from exc
    labels = ascii_d.split(".")
    if len(ascii_d) > 253 or len(labels) < 2 or any(
            not _DOMAIN_LABEL.match(lbl) for lbl in labels):
        raise ACMEError(f"'{domain}' is not a valid fully-qualified domain name")
    return ascii_d


def _default_run(argv: list[str], *, timeout: int) -> subprocess.CompletedProcess:
    env = {"PATH": os.environ.get("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"),
           "HOME": os.environ.get("HOME", "/root"),
           "LANG": "C", "LC_ALL": "C"}
    try:
        return subprocess.run(argv, capture_output=True, text=True,
                              timeout=timeout, env=env, shell=False, check=False)
    except subprocess.TimeoutExpired as exc:
        raise ACMEError(
            f"{Path(argv[0]).name} did not finish within {timeout}s — the CA "
            f"may be unreachable from this server (tail: "
            f"{(exc.stdout or '')[-400:]!r})") from exc
    except OSError as exc:
        raise ACMEError(f"cannot execute {argv[0]}: {exc}") from exc


def _tail(proc: subprocess.CompletedProcess) -> str:
    out = ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip()
    return out[-600:] if out else f"rc={proc.returncode} (no output)"


def _require_ok(proc: subprocess.CompletedProcess, what: str) -> None:
    if proc.returncode != 0:
        raise ACMEError(f"{what} failed: {_tail(proc)}")


# --------------------------------------------------------------------- #
# provider detection
# --------------------------------------------------------------------- #

def detect_providers() -> list[ProviderInfo]:
    """All supported clients present on this host (order = preference)."""
    found: list[ProviderInfo] = []
    path = shutil.which("certbot")
    if path:
        found.append(ProviderInfo("certbot", "certbot (EFF)", path))
    path = shutil.which("acme.sh")
    if not path:
        candidate = Path(os.environ.get("HOME", "/root")) / ".acme.sh" / "acme.sh"
        if candidate.is_file() and os.access(candidate, os.X_OK):
            path = str(candidate)
    if path:
        found.append(ProviderInfo("acme.sh", "acme.sh", path))
    path = shutil.which("lego")
    if path:
        found.append(ProviderInfo("lego", "lego (go-acme)", path))
    return found


def pick_provider(preferred: str | None = None) -> ProviderInfo | None:
    providers = detect_providers()
    if preferred:
        for p in providers:
            if p.id == preferred:
                return p
        return None
    return providers[0] if providers else None


def acme_available() -> dict:
    providers = detect_providers()
    return {
        "available": bool(providers),
        "providers": [{"id": p.id, "name": p.name, "path": p.path} for p in providers],
        "status": (
            f"{providers[0].name} detected — real issuance, renewal and status"
            if providers else
            "no ACME client found on this host (certbot/acme.sh/lego) — install "
            "certbot or use the official panel image, which ships one"),
    }


# --------------------------------------------------------------------- #
# preflight
# --------------------------------------------------------------------- #

def port80_probe() -> None:
    """Standalone HTTP-01 needs the client to bind port 80. Probe honestly —
    an occupied port would fail the run deep inside; say so upfront."""
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        probe.bind(("0.0.0.0", 80))
    except OSError as exc:
        raise ACMEError(
            f"port 80 is not available for the ACME HTTP-01 challenge "
            f"({exc}); stop the listener bound to it (or free it temporarily) "
            f"and retry") from exc
    finally:
        probe.close()


def _wait_port80_listening(timeout_s: float = 6.0) -> None:
    """Best-effort post-run sanity: after a standalone issue the port should
    be free again within seconds (never fatal — CA-side timing varies)."""
    import time

    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.bind(("0.0.0.0", 80))
            s.close()
            return
        except OSError:
            time.sleep(0.25)


# --------------------------------------------------------------------- #
# managed-store bookkeeping
# --------------------------------------------------------------------- #

def _sidecar_path(data_dir: str, domain: str) -> Path:
    return Path(data_dir) / "certs" / domain / ".acme.json"


def _read_sidecar(data_dir: str, domain: str) -> dict:
    try:
        return json.loads(_sidecar_path(data_dir, domain).read_text())
    except (OSError, json.JSONDecodeError):
        return {}


def has_sidecar(data_dir: str, domain: str) -> bool:
    """True when <data>/certs/<domain> carries an ACME sidecar — the marker
    that deletion must flow through remove_acme (provider cleanup), not the
    bare managed-store delete."""
    return _sidecar_path(data_dir, domain).is_file()


def _write_sidecar(data_dir: str, domain: str, **fields) -> None:
    data = _read_sidecar(data_dir, domain)
    data.update(fields)
    path = _sidecar_path(data_dir, domain)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")


def list_acme(data_dir: str) -> list[dict]:
    """ACME-managed entries (sidecar present) + their certificate facts."""
    from app.platform import certificates

    sidecars = sorted(Path(data_dir).glob("certs/*/.acme.json")) \
        if Path(data_dir).is_dir() else []
    infos = {c.name: c for c in certificates.scan(data_dir, managed_only=True)}
    out: list[dict] = []
    for sc in sidecars:
        try:
            data = json.loads(sc.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        domain = sc.parent.name
        info = infos.get(domain)
        out.append({
            "domain": domain,
            "provider": data.get("provider"),
            "email": data.get("email"),
            "issued_at": data.get("issued_at"),
            "renewed_at": data.get("renewed_at"),
            "cert_path": str(Path(data_dir) / "certs" / domain / "fullchain.pem"),
            "key_path": str(Path(data_dir) / "certs" / domain / "key.pem"),
            "days_left": info.days_left if info else None,
            "expired": info.expired if info else None,
            "renew_due": (info.days_left <= 30) if info else None,
        })
    return out


# --------------------------------------------------------------------- #
# provider command lines (the REAL tool invocations, per provider)
# --------------------------------------------------------------------- #

def _issue_commands(p: ProviderInfo, domain: str, email: str | None) -> list[list[str]]:
    """Command(s) a provider runs to ISSUE, in order (acme.sh registers the
    account first when a contact email is supplied)."""
    if p.id == "certbot":
        args = [p.path, "certonly", "--standalone", "--non-interactive",
                "--agree-tos", "--preferred-challenges", "http",
                "--http-01-port", "80", "-d", domain]
        args += ["-m", email] if email else ["--register-unsafely-without-email"]
        return [args]
    if p.id == "acme.sh":
        steps: list[list[str]] = []
        if email:
            steps.append([p.path, "--register-account", "-m", email,
                          "--server", "letsencrypt"])
        steps.append([p.path, "--issue", "--standalone", "-d", domain,
                      "--server", "letsencrypt", "--httpport", "80",
                      "--keylength", "2048"])
        return steps
    # lego REQUIRES an email; the caller enforces it before building args
    assert email, "lego issue without email"
    return [[p.path, "--accept-tos", "--email", email, "--domains", domain,
             "--http", "--http.port", ":80", "--key-type", "rsa2048",
             "--path", _lego_home(), "run"]]


def _lego_home(data_dir: str | None = None) -> str:
    # lego keeps registrations/certs under a panel-owned dir so renew state
    # survives and never mixes with an operator's own lego setup
    base = data_dir or os.environ.get("ZAGROS_ACME_HOME", "/var/lib/zagros")
    return str(Path(base) / "acme" / "lego")


def _export_paths(p: ProviderInfo, domain: str) -> tuple[Path, Path]:
    """Where the provider materialized (cert, key) after a successful run."""
    if p.id == "certbot":
        live = Path("/etc/letsencrypt/live") / domain
        return live / "fullchain.pem", live / "privkey.pem"
    if p.id == "acme.sh":
        # --install-cert exports deterministically (see issue())
        staging = Path(os.environ.get("HOME", "/root")) / ".acme.sh" / ".zagros-export" / domain
        return staging / "fullchain.pem", staging / "key.pem"
    home = Path(_lego_home()) / "certificates"
    return home / f"{domain}.crt", home / f"{domain}.key"


# --------------------------------------------------------------------- #
# issue / renew / delete
# --------------------------------------------------------------------- #

def issue(data_dir: str, domain: str, *, email: str | None = None,
          provider_id: str | None = None, force: bool = False,
          run=_default_run) -> dict:
    """Issue a REAL certificate and deploy it into the managed store.

    Existing ACME entries refuse duplicate issuance unless ``force`` (a
    re-issue converges by re-importing, never creates a second entry).
    """
    domain = validate_domain(domain)
    provider = pick_provider(provider_id)
    if provider is None:
        raise ACMEError(
            "no ACME client available on this host (looked for certbot, "
            "acme.sh, lego) — install certbot or use the official panel image")
    if provider.id == "lego" and not email:
        raise ACMEError("the lego client requires an account email — supply "
                        "'email' or let the panel use certbot/acme.sh instead")
    existing = _read_sidecar(data_dir, domain)
    if existing and not force:
        raise ACMEError(
            f"'{domain}' already has an ACME-managed certificate (provider "
            f"{existing.get('provider')}) — renew it, or re-issue with force")
    port80_probe()

    for step in _issue_commands(provider, domain, email):
        proc = run(step, timeout=_ISSUE_TIMEOUT)
        _require_ok(proc, f"{provider.name} run {step[1] if len(step) > 1 else ''} for {domain}")
    _wait_port80_listening()

    if provider.id == "acme.sh":
        staging = _export_paths(provider, domain)[0].parent
        staging.mkdir(parents=True, exist_ok=True)
        exp = run([provider.path, "--install-cert", "-d", domain,
                   "--key-file", str(staging / "key.pem"),
                   "--fullchain-file", str(staging / "fullchain.pem")],
                  timeout=120)
        _require_ok(exp, "acme.sh certificate export")
    cert_path, key_path = _export_paths(provider, domain)
    _deploy(data_dir, domain, cert_path, key_path, provider=provider.id,
            email=email, issued_at=datetime.now(timezone.utc).isoformat(),
            renewed_at=None)
    return {"ok": True, "domain": domain, "provider": provider.id,
            "message": f"issued by {provider.name} and deployed to the managed store"}


def _deploy(data_dir: str, domain: str, cert_path: Path, key_path: Path, **meta) -> None:
    from app.platform import certificates

    try:
        cert_pem = cert_path.read_bytes().decode()
        key_pem = key_path.read_bytes().decode()
    except OSError as exc:
        raise ACMEError(
            f"the ACME client reported success but its files are unreadable "
            f"({cert_path}, {key_path}): {exc}") from exc
    try:
        # import_cert validates the pair (parse/match) before storing — the
        # store never holds a broken ACME artifact
        certificates.import_cert(data_dir, domain, cert_pem, key_pem, overwrite=True)
    except ValueError as exc:
        raise ACMEError(f"ACME material failed validation on deploy: {exc}") from exc
    # meta carries renewed_at only on the renew path; issue() passes it as
    # None so a force re-issue resets the renewal timestamp (merge keeps any
    # key absent from meta untouched)
    _write_sidecar(data_dir, domain, **meta, cert_source=str(cert_path))


def renew(data_dir: str, domain: str, *, force: bool = False,
          run=_default_run) -> dict:
    """Renew one ACME entry (idempotent: not-due renewals simply re-deploy
    the SAME material — no duplicate anything)."""
    domain = validate_domain(domain)
    meta = _read_sidecar(data_dir, domain)
    if not meta:
        raise ACMEError(f"'{domain}' is not an ACME-managed certificate")
    provider = pick_provider(meta.get("provider"))
    if provider is None:
        raise ACMEError(
            f"the provider that issued '{domain}' ({meta.get('provider')}) is "
            f"no longer available — install it back to renew")
    if provider.id == "certbot":
        args = [provider.path, "renew", "--cert-name", domain, "--non-interactive"]
        if force:
            args.append("--force-renewal")
    elif provider.id == "acme.sh":
        args = [provider.path, "--renew", "-d", domain, "--server", "letsencrypt"]
        if force:
            args.append("--force")
    else:
        args = [provider.path, "--accept-tos", "--email", meta.get("email") or "",
                "--domains", domain, "--http", "--http.port", ":80",
                "--path", _lego_home(),
                "renew"] + (["--days", "0"] if force else [])
        if not meta.get("email"):
            raise ACMEError("lego renew needs the original account email (lost "
                            "from the sidecar) — re-issue instead")
    if provider.id != "acme.sh":
        port80_probe()
    proc = run(args, timeout=_RENEW_TIMEOUT)
    _require_ok(proc, f"{provider.name} renewal for {domain}")
    if provider.id == "acme.sh":
        staging = _export_paths(provider, domain)[0].parent
        staging.mkdir(parents=True, exist_ok=True)
        exp = run([provider.path, "--install-cert", "-d", domain,
                   "--key-file", str(staging / "key.pem"),
                   "--fullchain-file", str(staging / "fullchain.pem")],
                  timeout=120)
        _require_ok(exp, "acme.sh certificate export")
    cert_path, key_path = _export_paths(provider, domain)
    _deploy(data_dir, domain, cert_path, key_path, provider=provider.id,
            email=meta.get("email"), issued_at=meta.get("issued_at"),
            renewed_at=datetime.now(timezone.utc).isoformat())
    return {"ok": True, "domain": domain, "provider": provider.id,
            "message": f"renewed via {provider.name} and re-deployed"}


def remove_acme(data_dir: str, domain: str, *, run=_default_run) -> dict:
    """Delete an ACME entry: the managed-store removal is authoritative;
    provider-side cleanup is best-effort and honestly reported."""
    domain = validate_domain(domain)
    from app.platform import certificates

    meta = _read_sidecar(data_dir, domain)
    provider_note = "no provider-side registration found"
    if meta.get("provider"):
        provider = pick_provider(meta.get("provider"))
        if provider is not None:
            if provider.id == "certbot":
                args = [provider.path, "delete", "--cert-name", domain, "--non-interactive"]
            elif provider.id == "acme.sh":
                args = [provider.path, "--remove", "-d", domain]
            else:
                live = Path(_lego_home()) / "certificates"
                args = []
            try:
                if provider.id == "lego":
                    for f in (live / f"{domain}.crt", live / f"{domain}.key",
                              live / f"{domain}.json", live / f"{domain}.issuer.crt"):
                        try:
                            f.unlink()
                        except OSError:
                            pass
                    provider_note = "lego certificate files removed"
                else:
                    proc = run(args, timeout=_DELETE_TIMEOUT)
                    provider_note = ("provider registration removed"
                                     if proc.returncode == 0
                                     else f"provider cleanup failed: {_tail(proc)}")
            except ACMEError as exc:
                provider_note = f"provider cleanup failed: {exc}"
    certificates.remove(data_dir, domain)  # managed dir (FileNotFoundError → 404 upstream)
    return {"ok": True, "domain": domain, "provider_cleanup": provider_note}


# --------------------------------------------------------------------- #
# status & auto-renewal
# --------------------------------------------------------------------- #

def acme_status(data_dir: str) -> dict:
    avail = acme_available()
    return {**avail, "entries": list_acme(data_dir)}


def renew_due(data_dir: str, *, within_days: int = 30, run=_default_run) -> list[dict]:
    """Auto-maintenance sweep (scheduler): renew entries whose certificate
    expires soon. One failing entry never blocks the others; every outcome
    is logged. Returns per-domain results."""
    results: list[dict] = []
    for entry in list_acme(data_dir):
        if entry["days_left"] is None or entry["days_left"] > within_days:
            continue
        try:
            out = renew(data_dir, entry["domain"], run=run)
            results.append({"domain": entry["domain"], "ok": True,
                            "message": out["message"]})
            logger.info("acme auto-renew: %s renewed", entry["domain"])
        except ACMEError as exc:
            results.append({"domain": entry["domain"], "ok": False, "error": str(exc)})
            logger.warning("acme auto-renew: %s failed: %s", entry["domain"], exc)
    return results


def default_data_dir() -> str:
    url = os.environ.get("ZAGROS_DATABASE_URL", "")
    if url.startswith("sqlite:///"):
        return str(Path(url[10:]).parent)
    return "/var/lib/zagros"
