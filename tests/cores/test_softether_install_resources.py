"""SoftEther installer resource/caching/atomicity regressions.

These are production-path tests around the real LocalSoftEtherBackend methods;
only network and the final linker are substituted with deterministic fixtures.
"""
from __future__ import annotations

import io
import os
import tarfile
import threading
import time
from pathlib import Path

import pytest

from app.cores import github_install
from app.cores.drivers.softether.backend import LocalSoftEtherBackend
from app.cores.exceptions import CoreError


def _bundle_bytes() -> bytes:
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w:gz") as tar:
        for name, data in {
            "vpnserver/Makefile": b"main:\n\ttrue\n",
            "vpnserver/code/vpnserver.a": b"precompiled-server",
            "vpnserver/code/vpncmd.a": b"precompiled-command",
            "vpnserver/hamcore.se2": b"resources",
        }.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return out.getvalue()


def _release() -> dict:
    return {
        "tag_name": "v4.44-9807-rtm",
        "prerelease": False,
        "assets": [{
            "name": "softether-vpnserver-v4.44-9807-rtm-linux-x64-64bit.tar.gz",
            "browser_download_url": "https://example.invalid/softether.tar.gz",
        }],
    }


def _fixture_backend(tmp_path: Path, monkeypatch):
    cache, root = tmp_path / "cache", tmp_path / "install"
    monkeypatch.setenv("ZAGROS_SOFTETHER_SRC_CACHE", str(cache))
    monkeypatch.setattr(github_install, "fetch_release_list",
                        lambda repo, limit=10: [_release()])
    # imported inside the method, so module monkeypatch is authoritative
    monkeypatch.setattr(github_install, "host_os", lambda: "linux")
    monkeypatch.setattr(github_install, "host_arch", lambda: "amd64")
    backend = LocalSoftEtherBackend({})
    backend._INSTALL_ROOT = str(root)
    monkeypatch.setattr(backend, "_link_on_path", lambda _root: None)
    monkeypatch.setattr(backend, "_ensure_bundle_deps", lambda: None)
    calls = {"download": 0, "build": 0}

    def download(_url, dest, **_kwargs):
        calls["download"] += 1
        Path(dest).write_bytes(_bundle_bytes())
        return Path(dest).stat().st_size

    def build(argv, *, timeout):
        calls["build"] += 1
        source = Path(argv[argv.index("-C") + 1])
        (source / "vpnserver").write_bytes(b"server-bin")
        (source / "vpncmd").write_bytes(b"cmd-bin")
        return "linked"

    monkeypatch.setattr(backend, "_download", download)
    monkeypatch.setattr(backend, "_run_streamed", build)
    return backend, cache, root, calls


def test_fresh_install_then_cache_hit(tmp_path, monkeypatch):
    backend, cache, root, calls = _fixture_backend(tmp_path, monkeypatch)
    result = backend._install_from_github()
    assert "stable bundle" in result
    assert calls == {"download": 1, "build": 1}
    assert (root / "vpnserver").read_bytes() == b"server-bin"
    assert (root / "vpncmd").read_bytes() == b"cmd-bin"
    assert (cache / "stable" / "v4.44-9807-rtm" / "x64-64bit" / ".complete").exists()

    # Simulate repair on a fresh live root: cache must skip both expensive
    # stages and atomically materialize the known-complete artifacts.
    import shutil
    shutil.rmtree(root)
    backend._install_from_github()
    assert calls == {"download": 1, "build": 1}
    assert (root / "vpnserver").exists()


def test_bundle_build_failure_never_replaces_live_root(tmp_path, monkeypatch):
    backend, _cache, root, _calls = _fixture_backend(tmp_path, monkeypatch)
    root.mkdir()
    (root / "keep.txt").write_text("old-live-install")
    monkeypatch.setattr(
        backend, "_run_streamed",
        lambda *a, **k: (_ for _ in ()).throw(CoreError("link failed")),
    )
    with pytest.raises(CoreError, match="link failed"):
        backend._install_from_github()
    assert (root / "keep.txt").read_text() == "old-live-install"
    assert not list(tmp_path.glob("install.part.*"))


def test_interrupted_download_leaves_no_final_or_part(tmp_path, monkeypatch):
    backend = LocalSoftEtherBackend({})

    class Interrupted:
        def __enter__(self): return self
        def __exit__(self, *args): return False
        def read(self, _size=-1):
            if getattr(self, "sent", False):
                raise OSError("connection reset")
            self.sent = True
            return b"partial"

    monkeypatch.setattr("urllib.request.urlopen", lambda *a, **k: Interrupted())
    dest = tmp_path / "bundle.tar.gz"
    with pytest.raises(OSError, match="connection reset"):
        backend._download("https://example.invalid/a", str(dest))
    assert not dest.exists()
    assert not Path(str(dest) + ".part").exists()


def test_concurrent_installs_share_one_build_lock(tmp_path, monkeypatch):
    cache = tmp_path / "cache"
    installed = tmp_path / "installed.marker"
    monkeypatch.setenv("ZAGROS_SOFTETHER_SRC_CACHE", str(cache))
    count = 0
    count_lock = threading.Lock()
    backends = [LocalSoftEtherBackend({}), LocalSoftEtherBackend({})]

    def build_once():
        nonlocal count
        with count_lock:
            count += 1
        time.sleep(0.12)  # hold the real flock while the second worker enters
        installed.write_text("done")
        return "installed once"

    for backend in backends:
        monkeypatch.setattr(backend, "server_binary",
                            lambda p=installed: str(p) if p.exists() else None)
        monkeypatch.setattr(backend, "_install_from_github", build_once)

    results: list[str] = []
    threads = [threading.Thread(target=lambda b=b: results.append(b.install_packages()))
               for b in backends]
    for thread in threads: thread.start()
    for thread in threads: thread.join(timeout=5)
    assert all(not thread.is_alive() for thread in threads)
    assert count == 1
    assert len(results) == 2
    assert any("already installed" in result for result in results)
