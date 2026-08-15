"""Release-blocking dashboard dependency floors from the alpha.8.3 audit.

The live ``npm audit`` remains a final gate. These lockfile assertions prevent a
future install from silently reintroducing the exact vulnerable ranges after
that network-backed gate has passed.
"""
from __future__ import annotations

import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DASHBOARD = ROOT / "app" / "dashboard"


def _version(value: str) -> tuple[int, int, int]:
    match = re.match(r"^(\d+)\.(\d+)\.(\d+)", value)
    assert match, f"unexpected semver: {value}"
    return tuple(int(part) for part in match.groups())


def test_audited_dashboard_dependencies_stay_outside_vulnerable_ranges() -> None:
    package = json.loads((DASHBOARD / "package.json").read_text())
    lock = json.loads((DASHBOARD / "package-lock.json").read_text())
    packages = lock["packages"]

    assert package["dependencies"]["react-router-dom"] == "7.18.2"
    assert package["devDependencies"]["vite"] == "8.2.1"
    assert package["devDependencies"]["@vitejs/plugin-react"] == "6.0.5"

    assert _version(packages["node_modules/react-router"]["version"]) >= (7, 18, 0)
    assert _version(packages["node_modules/react-router-dom"]["version"]) >= (7, 18, 0)
    assert _version(packages["node_modules/vite"]["version"]) > (6, 4, 2)
    assert _version(packages["node_modules/nanoid"]["version"]) >= (3, 3, 18)
    assert _version(packages["node_modules/picomatch"]["version"]) >= (2, 3, 2)

    # Vite 8 no longer pulls the vulnerable esbuild dev server or the old
    # optional Sass/Immutable chain into this lockfile.
    assert "node_modules/esbuild" not in packages
    immutable = packages.get("node_modules/immutable")
    assert immutable is None or _version(immutable["version"]) >= (4, 3, 9)
