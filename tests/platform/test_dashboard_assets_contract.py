"""Dashboard assets must remain reachable beside root-level subscription paths."""
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_dashboard_uses_relative_nested_assets_not_root_two_segment_paths() -> None:
    vite = (ROOT / "app/dashboard/vite.config.ts").read_text()
    layout = (ROOT / "app/dashboard/src/layouts/AppLayout.tsx").read_text()
    login = (ROOT / "app/dashboard/src/pages/Login.tsx").read_text()
    index = (ROOT / "app/dashboard/index.html").read_text()
    assert 'base: "./"' in vite
    assert './statics/zagros.svg' in layout
    assert './statics/zagros.svg' in login
    assert 'href="./statics/zagros.svg"' in index
    assert (ROOT / "app/dashboard/public/statics/zagros.svg").is_file()
    assert not (ROOT / "app/dashboard/public/zagros.svg").exists()
