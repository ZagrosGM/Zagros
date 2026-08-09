"""ACME integration — domain validation, provider detection, issue / renew /
delete against scripted provider binaries (alpha.7.5 item 9).

Test doubles live at the SUBPROCESS boundary only (``run`` + provider
discovery): everything the panel itself does — validation, preflight,
export, managed-store deploy, sidecar bookkeeping, sweep scheduling — runs
for real. Real CA issuance needs DNS + port 80 against Let's Encrypt and is
verified on the VPS (external limitation, reported as such).
"""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from app.platform import acme, certificates


def _pair() -> dict:
    from app.utils.crypto import generate_certificate

    return generate_certificate()


def _scripted_provider(tmp_path, *, fail_issue: bool = False):
    """A fake acme.sh: export writes REAL pair material into the staging
    path the module expects; every argv is recorded."""
    home = tmp_path / "home"
    pair = _pair()
    calls: list[list[str]] = []

    def run(argv, timeout):
        calls.append(list(argv))
        cp = subprocess.CompletedProcess(argv, 0, "ok", "")
        if fail_issue and "issue" in argv[1]:
            cp.returncode, cp.stderr = 9, "Simulated CA refusal tail"
        if "--install-cert" in argv:
            staging = home / ".acme.sh" / ".zagros-export" / argv[argv.index("-d") + 1]
            staging.mkdir(parents=True, exist_ok=True)
            (staging / "fullchain.pem").write_text(pair["cert"])
            (staging / "key.pem").write_text(pair["key"])
        return cp

    provider = acme.ProviderInfo("acme.sh", "acme.sh", str(tmp_path / "acme.sh"))
    return home, pair, calls, run, provider


@pytest.fixture(autouse=True)
def _no_port_probe(monkeypatch):
    # OS capability (binding :80) is environment-dependent and belongs to
    # the VPS verification, not the logic tests
    monkeypatch.setattr(acme, "port80_probe", lambda: None)
    yield


# --------------------------------------------------------------------- #
# domain validation
# --------------------------------------------------------------------- #

def test_validate_domain_normal_and_idna():
    assert acme.validate_domain("Example.COM.") == "example.com"
    assert acme.validate_domain("vpn.münchen.de") == "vpn.xn--mnchen-3ya.de"


def test_validate_domain_refuses_wildcard_ip_and_bad_names():
    with pytest.raises(acme.ACMEError, match="wildcard"):
        acme.validate_domain("*.example.com")
    with pytest.raises(acme.ACMEError, match="IP address"):
        acme.validate_domain("203.0.113.10")
    with pytest.raises(acme.ACMEError, match="fully-qualified"):
        acme.validate_domain("not-a-domain")
    with pytest.raises(acme.ACMEError):
        acme.validate_domain("bad_name.example.com")


# --------------------------------------------------------------------- #
# detection
# --------------------------------------------------------------------- #

def test_detection_finds_acme_sh_under_home(monkeypatch, tmp_path):
    monkeypatch.setattr(acme.shutil, "which", lambda name: None)
    fake = tmp_path / ".acme.sh" / "acme.sh"
    fake.parent.mkdir(parents=True)
    fake.write_text("#!/bin/sh\n")
    fake.chmod(0o755)
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("ZAGROS_TEST_NO_HOME", raising=False)
    found = acme.detect_providers()
    assert [p.id for p in found] == ["acme.sh"]


def test_detection_reports_unavailability_honestly(monkeypatch, tmp_path):
    monkeypatch.setattr(acme.shutil, "which", lambda name: None)
    monkeypatch.setenv("HOME", str(tmp_path))
    avail = acme.acme_available()
    assert avail["available"] is False
    assert "no ACME client" in avail["status"]


# --------------------------------------------------------------------- #
# issue / renew / delete (scripted acme.sh)
# --------------------------------------------------------------------- #

def test_issue_deploys_pair_and_sidecar(monkeypatch, tmp_path):
    data = str(tmp_path / "data")
    home, pair, calls, run, provider = _scripted_provider(tmp_path)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setattr(acme, "pick_provider", lambda _pid=None: provider)

    out = acme.issue(data, "vpn.example.com", email="ops@example.com", run=run)
    assert out["ok"] and out["provider"] == "acme.sh"
    # the managed store got the REAL pair (validated on deploy)
    info = {c.name: c for c in certificates.scan(data)}
    assert "vpn.example.com" in info and info["vpn.example.com"].managed
    # account registration ran BEFORE issuance; export after
    flat = [" ".join(c) for c in calls]
    assert any("register-account" in c for c in flat)
    assert any("--issue --standalone -d vpn.example.com" in c for c in flat)
    assert any("--install-cert -d vpn.example.com" in c for c in flat)
    # sidecar drives renew/status/delete
    meta = acme._read_sidecar(data, "vpn.example.com")
    assert meta["provider"] == "acme.sh" and meta["email"] == "ops@example.com"
    status = acme.acme_status(data)
    assert status["entries"][0]["domain"] == "vpn.example.com"
    assert status["entries"][0]["expired"] is False


def test_issue_duplicate_refused_unless_force_and_failure_surfaces_tail(
        monkeypatch, tmp_path):
    data = str(tmp_path / "data")
    home, _pair_, _calls, run, provider = _scripted_provider(tmp_path)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setattr(acme, "pick_provider", lambda _pid=None: provider)
    acme.issue(data, "dup.example.com", run=run)
    with pytest.raises(acme.ACMEError, match="already has an ACME-managed"):
        acme.issue(data, "dup.example.com", run=run)
    # force re-issue converges into the SAME entry (idempotent, no duplicate)
    acme.issue(data, "dup.example.com", force=True, run=run)
    assert [c.name for c in certificates.scan(data)] == ["dup.example.com"]

    _h2, _p2, _c2, run_fail, _pv = _scripted_provider(tmp_path, fail_issue=True)
    with pytest.raises(acme.ACMEError, match="Simulated CA refusal tail"):
        acme.issue(data, "fail.example.com", run=run_fail)
    # a failed run must leave NO managed entry and NO sidecar
    assert {c.name for c in certificates.scan(data)} == {"dup.example.com"}
    assert acme._read_sidecar(data, "fail.example.com") == {}


def test_renew_redeploys_and_marks_sidecar(monkeypatch, tmp_path):
    data = str(tmp_path / "data")
    home, _pair_, calls, run, provider = _scripted_provider(tmp_path)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setattr(acme, "pick_provider", lambda _pid=None: provider)
    acme.issue(data, "renew.example.com", run=run)
    calls_before_renew = len(calls)
    out = acme.renew(data, "renew.example.com", run=run)
    assert out["ok"]
    renew_calls = [" ".join(c) for c in calls[calls_before_renew:]]
    assert any("--renew -d renew.example.com" in c for c in renew_calls)
    meta = acme._read_sidecar(data, "renew.example.com")
    assert meta["renewed_at"]

    with pytest.raises(acme.ACMEError, match="not an ACME-managed"):
        acme.renew(data, "ghost.example.com", run=run)


def test_remove_acme_local_removal_authoritative(monkeypatch, tmp_path):
    data = str(tmp_path / "data")
    home, _pair_, calls, run, provider = _scripted_provider(tmp_path)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setattr(acme, "pick_provider", lambda _pid=None: provider)
    acme.issue(data, "gone.example.com", run=run)

    out = acme.remove_acme(data, "gone.example.com", run=run)
    assert out["ok"] and "removed" in out["provider_cleanup"]
    assert {c.name for c in certificates.scan(data)} == set()
    assert acme.list_acme(data) == []
    assert any("--remove -d gone.example.com" in " ".join(c) for c in calls)

    # provider cleanup failure is reported but local deletion STILL lands
    def bad_run(argv, timeout):
        cp = subprocess.CompletedProcess(argv, 3, "", "boom")
        if "--install-cert" in argv:
            return run(argv, timeout)
        if "--remove" in argv:
            return cp
        return run(argv, timeout)

    acme.issue(data, "gone2.example.com", run=run)
    out2 = acme.remove_acme(data, "gone2.example.com", run=bad_run)
    assert out2["ok"] and "failed" in out2["provider_cleanup"]
    assert {c.name for c in certificates.scan(data)} == set()


def test_sweep_renews_only_due_entries(monkeypatch, tmp_path):
    data = str(tmp_path / "data")
    home, pair, _calls, run, provider = _scripted_provider(tmp_path)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setattr(acme, "pick_provider", lambda _pid=None: provider)

    # due entry: 10 days left
    certificates.import_cert(data, "soon.example.com", pair["cert"], pair["key"])
    acme._write_sidecar(data, "soon.example.com", provider="acme.sh",
                        email=None, issued_at="2026-01-01T00:00:00+00:00")
    # trick the listing into calling it due: generate a fresh 90-day pair
    # instead and hand the module an entry whose days_left<=30 via import of
    # a short-lived cert
    from cryptography import x509 as _x
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    from datetime import datetime, timedelta, timezone

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = _x.Name([_x.NameAttribute(NameOID.COMMON_NAME, "soon.example.com")])
    cert = (_x.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(_x.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=10))
            .sign(key, hashes.SHA256()))
    certificates.import_cert(
        data, "soon.example.com",
        cert.public_bytes(serialization.Encoding.PEM).decode(),
        key.private_bytes(serialization.Encoding.PEM,
                          serialization.PrivateFormat.TraditionalOpenSSL,
                          serialization.NoEncryption()).decode(),
        overwrite=True)

    # not-due entry beside it
    certificates.import_cert(data, "far.example.com", pair["cert"], pair["key"])
    acme._write_sidecar(data, "far.example.com", provider="acme.sh",
                        issued_at="2026-01-01T00:00:00+00:00")

    results = acme.renew_due(data, within_days=30, run=run)
    domains = {r["domain"] for r in results if r["ok"]}
    assert "soon.example.com" in domains
    assert "far.example.com" not in domains


def test_generic_delete_refuses_acme_managed_material(tmp_path):
    """The store-level DELETE endpoint must not silently delete ACME material
    (sidecar would point at missing files and provider cleanup never runs) —
    it answers 409 pointing at the ACME endpoint; plain certs still delete."""
    import asyncio
    from types import SimpleNamespace

    from fastapi import HTTPException

    from app.platform import admin_api

    data = str(tmp_path / "data")
    runtime = SimpleNamespace(database_url=f"sqlite:///{data}/platform.db")

    info = certificates.self_signed(data, "plain.example.com", "plain.example.com")
    assert info.name == "plain.example.com"
    certificates.self_signed(data, "acme.example.com", "acme.example.com")
    acme._write_sidecar(data, "acme.example.com", provider="acme.sh",
                        issued_at="2026-01-01T00:00:00+00:00")
    assert acme.has_sidecar(data, "acme.example.com")
    assert not acme.has_sidecar(data, "plain.example.com")

    with pytest.raises(HTTPException) as err:
        asyncio.run(admin_api.certificates_remove("acme.example.com", runtime))
    assert err.value.status_code == 409
    # the ACME entry survived the refused delete
    assert acme.has_sidecar(data, "acme.example.com")
    assert "acme.example.com" in {e["domain"] for e in acme.list_acme(data)}

    out = asyncio.run(admin_api.certificates_remove("plain.example.com", runtime))
    assert out["ok"]
    assert not (Path(data) / "certs" / "plain.example.com").exists()


if __name__ == "__main__":
    import sys

    sys.exit(pytest.main([__file__, "-q"]))
