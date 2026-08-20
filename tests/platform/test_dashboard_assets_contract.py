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


def test_routing_page_has_contextual_targets_without_obsolete_global_warnings() -> None:
    routing = (ROOT / "app/dashboard/src/pages/Routing.tsx").read_text()
    assert "SoftEther architecture: L2TP" not in routing
    assert "Application-only outbounds are excluded" not in routing
    assert 'priority {rule.priority}' in routing
    assert '"/zagros/routing/targets"' in routing
    assert '"/zagros/routing/sources"' in routing
    assert "targetVerdicts" in routing
    assert "trafficNetworks" in routing
    assert "sourceCores" in routing
    assert "set network to tcp" in routing
    assert "InboundTagSelector" in routing
    assert 'data-testid="inbound-tag-selector"' in routing
    assert 'type="checkbox"' in routing
    assert "duplicate tag — rename before use" in routing
    assert 'data-testid="selected-inbound-tags"' in routing
    assert "Deleted/unknown selections" in routing
