"""Certificate inventory/delete lifecycle (alpha.7.4, item 18).

The inventory scan covers the WHOLE panel data tree (core work-dirs
materialize listener certs there — e.g. a sing-box ``tuic.crt``), but
delete used to address only the managed ``<data>/certs/<name>/`` layout by
display name — every scanned core cert answered "not found". These tests
pin the identifier scheme (stable ``id`` = data-dir-relative path) and the
delete semantics for both layouts, incl. path-escape refusals.
"""
from __future__ import annotations

import pytest

from app.platform import certificates


def _core_materialized_cert(tmp_path, tag: str = "tuic"):
    from app.utils.crypto import generate_certificate

    core_dir = tmp_path / "cores" / "sing-box" / "certs"
    core_dir.mkdir(parents=True)
    pair = generate_certificate()
    (core_dir / f"{tag}.crt").write_text(pair["cert"])
    (core_dir / f"{tag}.key").write_text(pair["key"])
    return core_dir, pair


def test_scanned_core_cert_is_addressable_and_deletable(tmp_path):
    data = str(tmp_path)
    core_dir, _ = _core_materialized_cert(tmp_path)
    managed = certificates.self_signed(data, "panel-x", "panel.example.com", days=90)
    assert managed.managed and managed.id == "certs/panel-x/fullchain.pem"

    # alpha.7.5 item 8: the REGISTRY lists managed certs ONLY — runtime
    # material a core generated must never appear as if the user created it
    registry = {c.name: c for c in certificates.scan(data)}
    assert "tuic" not in registry
    assert list(registry) == ["panel-x"]

    # the item-18 whole-tree inventory stays available for diagnostics, and
    # delete-by-id still reaches those files (no 404-by-name regression)
    inv = {c.name: c for c in certificates.scan(data, managed_only=False)}
    assert "tuic" in inv and not inv["tuic"].managed
    assert inv["tuic"].id == "cores/sing-box/certs/tuic.crt"
    certificates.remove(data, inv["tuic"].id)
    assert not (core_dir / "tuic.crt").exists()
    assert not (core_dir / "tuic.key").exists(), "the key sibling must go too"
    # managed layout keeps its legacy by-name contract
    certificates.remove(data, "panel-x")
    assert not (tmp_path / "certs" / "panel-x").exists()


def test_runtime_only_tree_yields_an_empty_registry_not_a_runtime_listing(tmp_path):
    """item 8, exact field complaint: creating TLS inbounds generated a cert
    that showed up in Certificates — with NOTHING user-managed, the page
    must be empty, not full of engine plumbing."""
    data = str(tmp_path)
    _core_materialized_cert(tmp_path, tag="sstp")
    assert certificates.scan(data) == []
    whole = {c.name for c in certificates.scan(data, managed_only=False)}
    assert "sstp" in whole


def test_remove_refuses_escapes_and_ghosts(tmp_path):
    data = str(tmp_path)
    certificates.self_signed(data, "panel-y", "panel.example.com", days=90)
    with pytest.raises(ValueError, match="outside"):
        certificates.remove(data, "../../etc/passwd.crt")
    with pytest.raises(FileNotFoundError):
        certificates.remove(data, "ghost")
    with pytest.raises(FileNotFoundError):
        certificates.remove(data, "certs/panel-y/nonexistent.pem")
    # the real one still deletes by full id
    certificates.remove(data, "certs/panel-y/fullchain.pem")
    assert not (tmp_path / "certs" / "panel-y").exists(), \
        "emptied managed dir is cleaned up as a unit"


def test_managed_pair_import_reports_stable_id(tmp_path):
    from app.utils.crypto import generate_certificate

    data = str(tmp_path)
    pair = generate_certificate()
    info = certificates.import_cert(data, "rt-import", pair["cert"], pair["key"])
    assert info.managed and info.id == "certs/rt-import/fullchain.pem"
    certificates.remove(data, info.id)
    assert not (tmp_path / "certs" / "rt-import").exists()
