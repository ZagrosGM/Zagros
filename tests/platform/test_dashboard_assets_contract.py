"""Dashboard assets must remain reachable beside root-level subscription paths."""
from pathlib import Path

from fastapi import FastAPI
from fastapi.testclient import TestClient


ROOT = Path(__file__).resolve().parents[2]


def test_dashboard_mounts_precede_greedy_subscription_route(
    monkeypatch, tmp_path: Path,
) -> None:
    from app import dashboard

    build = tmp_path / "build"
    statics = build / "statics"
    statics.mkdir(parents=True)
    (build / "index.html").write_text("dashboard")
    (statics / "index-test.js").write_text("asset-ok")

    fake = FastAPI()

    @fake.get("/{sub_path:path}/{token}")
    def subscription_catchall(sub_path: str, token: str):
        return {"caught": [sub_path, token]}

    monkeypatch.setattr(dashboard, "app", fake)
    monkeypatch.setattr(dashboard, "build_dir", build)
    monkeypatch.setattr(dashboard, "statics_dir", statics)
    monkeypatch.setattr(dashboard, "DASHBOARD_PATH", "/dashboard")
    dashboard.run_build()

    with TestClient(fake) as client:
        response = client.get("/dashboard/statics/index-test.js")
        assert response.status_code == 200
        assert response.text == "asset-ok"
        assert client.get("/one/two/token").json() == {
            "caught": ["one/two", "token"]}


def test_dashboard_uses_relative_nested_assets_not_root_two_segment_paths() -> None:
    vite = (ROOT / "app/dashboard/vite.config.ts").read_text()
    branding = (ROOT / "app/dashboard/src/lib/branding.ts").read_text()
    index = (ROOT / "app/dashboard/index.html").read_text()
    assert 'base: "./"' in vite
    # f-branding-1: the default logo path lives in ONE place (lib/branding.ts);
    # the sidebar/login render brandLogo(branding) which falls back to it.
    assert './statics/zagros.svg' in branding
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


def test_monitoring_statistics_navigation_and_lazy_user_contract() -> None:
    src = ROOT / "app/dashboard/src"
    app = (src / "App.tsx").read_text()
    layout = (src / "layouts/AppLayout.tsx").read_text()
    monitoring = (src / "pages/Monitoring.tsx").read_text()
    statistics = (src / "pages/Statistics.tsx").read_text()
    users = (src / "pages/Users.tsx").read_text()
    drawer = (src / "components/UserStatisticsDrawer.tsx").read_text()
    logs = (src / "pages/Logs.tsx").read_text()

    assert 'to: "/sessions"' not in layout
    assert 'to: "/devices"' not in layout
    assert 'to: "/logs"' not in layout
    assert "nav.section.observe" not in layout
    assert 'to: "/monitoring"' in layout and 'to: "/statistics"' in layout
    assert 'path="monitoring"' in app and 'path="statistics"' in app
    for tab in ("connections", "devices", "ips", "logs"):
        assert f'id: "{tab}"' in monitoring
    assert "<LiveConnections embedded" in monitoring
    assert "<Devices embedded" in monitoring
    assert "<IPActivity embedded" in monitoring
    assert "<Logs embedded" in monitoring and "!embedded ?" in logs

    assert '"/zagros/statistics/overview"' in statistics
    assert "/zagros/statistics/traffic-history?" in statistics
    assert '"/api/users"' not in statistics and '"/users"' not in statistics
    assert "usageUser && <UserStatisticsDrawer" in users
    assert "setUsageUser(mu)" in users
    assert "/statistics/users/by-username/${username}" in drawer
    assert "enabled: customReady" in drawer
    # The selected-user component is mounted only by its row action; system
    # Statistics cannot accidentally fetch or render the complete user list.
    assert "UserStatisticsDrawer" not in statistics
    assert "max-w-xl" in (src / "components/overlays.tsx").read_text()
