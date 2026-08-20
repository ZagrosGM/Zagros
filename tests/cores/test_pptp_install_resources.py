import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_accel_ppp_pin_and_checksum_are_exact():
    manifest = json.loads((ROOT / "vendor/accel-ppp/manifest.json").read_text())
    assert manifest["version"] == "1.14.0"
    assert manifest["commit"] == "048d31cb446879e0d1a1471b4ab99135a92bf289"
    assert manifest["sha256"] == "ee391e34b237e3e2c12d037bc1c36d23bdb9ec76956d771e4a9425c9193a193d"
    assert manifest["source"].endswith(manifest["commit"])


def test_runtime_module_allowlist_is_exact_and_docker_verifies_checksum():
    manifest = json.loads((ROOT / "vendor/accel-ppp/manifest.json").read_text())
    assert set(manifest["runtime_modules"]) == {
        "libpptp.so", "libauth_mschap_v2.so", "libchap-secrets.so", "libippool.so",
        "libsigchld.so", "libpppd_compat.so", "liblog_file.so",
    }
    dockerfile = (ROOT / "Dockerfile").read_text()
    assert "sha256sum -c" in dockerfile
    assert "BUILD_PPTP_DRIVER=FALSE" in dockerfile  # obsolete kernel driver not needed
    assert "auth_pap.so" not in dockerfile
    assert "/opt/zagros/accel-ppp/1.14.0" in dockerfile
    assert "accel-ppp-${version}-source.tar.gz" in dockerfile


def test_compose_has_least_required_pptp_device_and_caps():
    compose = (ROOT / "docker-compose.yml").read_text()
    assert "NET_ADMIN" in compose and "NET_RAW" in compose
    assert "/dev/ppp:/dev/ppp" in compose
    assert "privileged: true" not in compose
    assert "/var/run/docker.sock" not in compose
