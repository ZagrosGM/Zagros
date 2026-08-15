"""Release image must contain tools invoked by real core lifecycle paths."""
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_runtime_image_includes_wireguard_sysctl_provider() -> None:
    dockerfile = (ROOT / "Dockerfile").read_text()
    runtime_install = dockerfile.split("# Runtime network tooling", 1)[1]
    assert "wireguard-tools" in runtime_install
    assert "procps" in runtime_install, "wg-quick requires the sysctl executable"
    assert "openssh-client" in runtime_install
    assert "openssh-server" in runtime_install
