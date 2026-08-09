"""Inbound lifecycle — identity, atomicity, idempotency (alpha.7.5 item 5).

Field reports this module pins shut:

* create sometimes answered "request failed (500)" while the inbound WAS
  created (persist happened before the core ever saw the document);
* one inbound created several times (double click / retry / timeout-retry);
* DUPLICATE inbounds with identical port/settings;
* deleting one inbound removed the WRONG one (the frontend computed an
  INDEX on a stale snapshot and patched positionally).

Root fixes under test here: stable tag identity + per-core mutation lock +
stage → materialize → persist (a refused candidate never reaches the store)
+ idempotent replay + 404/409 lifecycle mapping.

Run: pytest tests/studio/test_inbound_lifecycle.py -q
"""
from __future__ import annotations

import asyncio
import sys
import traceback
import types as _types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
if "app" not in sys.modules:
    _pkg = _types.ModuleType("app")
    _pkg.__path__ = [str(ROOT / "app")]
    sys.modules["app"] = _pkg

import pytest  # noqa: E402

from app.cores.types import Capability, CoreMetadata  # noqa: E402
from app.studio.jsonpatch import PatchOperation  # noqa: E402
from app.studio.service import (  # noqa: E402
    ConfigStudioService,
    InboundSpec,
    InMemoryStudioStore,
    StudioConflictError,
    StudioNotFoundError,
)


class _StubDriver:
    """Metadata-only driver stand-in; ``apply_studio_document`` optionally
    rejects to pin the stage→materialize→persist atomicity."""

    def __init__(self, core_id: str = "stubcore", *, max_inbounds=None,
                 reject: str | None = None):
        self.metadata = CoreMetadata(
            id=core_id, name=core_id, description="",
            protocols=["vless"], capabilities=set(Capability),
            config_schema={},
            studio_inbounds_path="/inbounds",
        )
        if max_inbounds is not None:
            self.metadata.studio_max_inbounds = max_inbounds
        self._reject = reject
        self.applied: list[dict] = []

    async def apply_studio_document(self, doc):
        if self._reject:
            from app.cores.exceptions import CoreError

            raise CoreError(self._reject)
        self.applied.append(doc)


def _svc(seed: dict | None = None, *, driver: _StubDriver | None = None):
    driver = driver or _StubDriver()
    store = InMemoryStudioStore()
    if seed is not None:
        asyncio.run(store.save_document(driver.metadata.id, seed))
    return ConfigStudioService(store), store, driver


def _spec(tag="wg-1", port=1443, **settings):
    settings.setdefault("transport", "tcp")
    settings.setdefault("security", "none")
    return InboundSpec(tag=tag, listen="0.0.0.0", port=port,
                       protocol="vless", settings=settings)


def _tags(store, core_id="stubcore"):
    doc = asyncio.run(store.get_document(core_id))
    return [e["tag"] for e in (doc or {}).get("inbounds", [])]


# --------------------------------------------------------------------- #
# create once / idempotent replay / conflict
# --------------------------------------------------------------------- #

def test_create_once_persists_exactly_one():
    service, store, driver = _svc({"inbounds": []})
    result = asyncio.run(service.wizard_create(driver, _spec()))
    assert result.valid and result.changed
    assert _tags(store) == ["wg-1"]


def test_double_click_create_is_idempotent_no_duplicate():
    service, store, driver = _svc({"inbounds": []})
    first = asyncio.run(service.wizard_create(driver, _spec()))
    assert first.changed
    # the exact replay the frontend would send on a double click
    second = asyncio.run(service.wizard_create(driver, _spec()))
    assert second.valid and not second.changed
    assert "idempotent" in (second.detail or "")
    assert _tags(store) == ["wg-1"]  # still exactly one


def test_timeout_retry_after_success_does_not_duplicate():
    """The scary one from the field: the request timed out client-side but
    the server HAD completed; the retry must be a no-op, not a twin."""
    service, store, driver = _svc({"inbounds": []})
    first = asyncio.run(service.wizard_create(driver, _spec()))
    assert first.changed  # server actually done
    retry = asyncio.run(service.wizard_create(driver, _spec()))
    assert retry.valid and not retry.changed
    assert _tags(store) == ["wg-1"]


def test_same_tag_different_settings_is_a_loud_conflict():
    service, store, driver = _svc({"inbounds": []})
    asyncio.run(service.wizard_create(driver, _spec()))
    with pytest.raises(StudioConflictError) as ei:
        asyncio.run(service.wizard_stage_create(driver, _spec(port=2443)))
    assert "DIFFERENT settings" in str(ei.value)
    assert _tags(store) == ["wg-1"]  # refusal forked nothing


def test_concurrent_create_same_spec_serializes_to_one():
    service, store, driver = _svc({"inbounds": []})

    async def go():
        return await asyncio.gather(
            service.wizard_create(driver, _spec()),
            service.wizard_create(driver, _spec()),
        )

    r1, r2 = asyncio.run(go())
    assert r1.valid and r2.valid
    assert [r.changed for r in (r1, r2)].count(True) == 1  # one wrote, one replayed
    assert _tags(store) == ["wg-1"]


def test_concurrent_create_different_tags_both_survive():
    service, store, driver = _svc({"inbounds": []})

    async def go():
        return await asyncio.gather(
            service.wizard_create(driver, _spec("a-1", port=1001)),
            service.wizard_create(driver, _spec("b-1", port=1002)),
        )

    asyncio.run(go())
    assert sorted(_tags(store)) == ["a-1", "b-1"]


# --------------------------------------------------------------------- #
# delete — exactly the addressed identity, ghost ≠ success
# --------------------------------------------------------------------- #

def test_delete_removes_exactly_the_addressed_tag():
    seed = {"inbounds": [
        {"tag": "keep-1", "protocol": "vless", "port": 1111, "listen": "0.0.0.0",
         "transport": "tcp", "security": "none"},
        {"tag": "drop-1", "protocol": "vless", "port": 2222, "listen": "0.0.0.0",
         "transport": "tcp", "security": "none"},
        {"tag": "keep-2", "protocol": "vless", "port": 3333, "listen": "0.0.0.0",
         "transport": "tcp", "security": "none"},
    ]}
    service, store, driver = _svc(seed)
    result = asyncio.run(service.wizard_delete(driver, "drop-1"))
    assert result.valid
    assert _tags(store) == ["keep-1", "keep-2"]  # middle gone, order kept


def test_concurrent_deletes_of_two_tags_never_collide():
    """Two admins delete two different inbounds at once: with positional
    patches computed on the same snapshot the second delete hit the WRONG
    index (or lost). The lock + tag identity must land both exactly."""
    seed = {"inbounds": [
        {"tag": t, "protocol": "vless", "port": 1000 + i, "listen": "0.0.0.0",
         "transport": "tcp", "security": "none"}
        for i, t in enumerate(["t1", "t2", "t3", "t4"])
    ]}
    service, store, driver = _svc(seed)

    async def go():
        return await asyncio.gather(
            service.wizard_delete(driver, "t2"),
            service.wizard_delete(driver, "t4"),
        )

    asyncio.run(go())
    assert _tags(store) == ["t1", "t3"]


def test_delete_ghost_is_not_found_not_success():
    service, _store, driver = _svc({"inbounds": [
        {"tag": "real-1", "protocol": "vless", "port": 443, "listen": "0.0.0.0",
         "transport": "tcp", "security": "none"},
    ]})
    with pytest.raises(StudioNotFoundError) as ei:
        asyncio.run(service.wizard_stage_delete(driver, "ghost-9"))
    assert "ghost-9" in str(ei.value)


def test_delete_with_duplicate_tags_refuses_ambiguous_identity():
    """A document broken by an older version may carry twin tags — deleting
    by tag would be a coin flip; refuse loudly (409), delete nothing."""
    seed = {"inbounds": [
        {"tag": "twin", "protocol": "vless", "port": 1111, "listen": "0.0.0.0"},
        {"tag": "twin", "protocol": "vless", "port": 2222, "listen": "0.0.0.0"},
    ]}
    service, _store, driver = _svc(seed)
    with pytest.raises(StudioConflictError) as ei:
        asyncio.run(service.wizard_stage_delete(driver, "twin"))
    assert "ambiguous" in str(ei.value)


def test_delete_then_recreate_works():
    service, store, driver = _svc({"inbounds": []})
    asyncio.run(service.wizard_create(driver, _spec()))
    asyncio.run(service.wizard_delete(driver, "wg-1"))
    assert _tags(store) == []
    again = asyncio.run(service.wizard_create(driver, _spec()))
    assert again.valid and again.changed
    assert _tags(store) == ["wg-1"]


# --------------------------------------------------------------------- #
# update — ghost 404, rename clash 409, identical replay no-op
# --------------------------------------------------------------------- #

def test_update_ghost_is_not_found():
    service, _store, driver = _svc({"inbounds": []})
    with pytest.raises(StudioNotFoundError):
        asyncio.run(service.wizard_update(driver, "ghost", _spec("ghost")))


def test_update_rename_must_not_fork_a_twin():
    seed = {"inbounds": [
        {"tag": "a", "protocol": "vless", "port": 1111, "listen": "0.0.0.0",
         "transport": "tcp", "security": "none"},
        {"tag": "b", "protocol": "vless", "port": 2222, "listen": "0.0.0.0",
         "transport": "tcp", "security": "none"},
    ]}
    service, _store, driver = _svc(seed)
    with pytest.raises(StudioConflictError) as ei:
        asyncio.run(service.wizard_stage_update(driver, "a", _spec("b")))
    assert "clash" in str(ei.value)


# --------------------------------------------------------------------- #
# atomicity — a refused candidate must never reach the store
# --------------------------------------------------------------------- #

def test_materialize_failure_leaves_the_store_untouched():
    """candidate → materialize raises → NO persist (the '500 but created
    anyway' split). Route-shaped: wizard_create with a rejecting hook."""
    from app.cores.exceptions import CoreError

    service, store, driver = _svc({"inbounds": []})

    async def _reject(_doc):
        raise CoreError("core refused the doc")

    with pytest.raises(CoreError) as ei:
        asyncio.run(service.wizard_create(driver, _spec(), materialize=_reject))
    assert "core refused the doc" in str(ei.value)
    # the store still holds the ORIGINAL document — nothing half-created
    assert _tags(store) == []
    # and the identity check never saw a phantom: the retry can proceed
    from app.studio.service import InboundSpec as _IS
    ok = asyncio.run(service.wizard_create(driver, _IS(
        tag="wg-1", listen="0.0.0.0", port=1443, protocol="vless",
        settings={"transport": "tcp", "security": "none"})))
    assert ok.valid and ok.changed
    assert _tags(store) == ["wg-1"]


def test_single_listener_replace_semantics_kept_under_lock():
    driver = _StubDriver(max_inbounds=1)
    service, store, _ = _svc({"inbounds": [
        {"tag": "old", "protocol": "vless", "port": 1, "listen": "0.0.0.0",
         "transport": "udp", "security": "none"},
    ]}, driver=driver)
    result = asyncio.run(service.wizard_create(driver, _spec("new-tune")))
    assert result.valid and result.changed
    assert _tags(store) == ["new-tune"]  # ONE listener, reconfigured


def test_single_listener_identical_replay_is_a_noop():
    driver = _StubDriver(max_inbounds=1)
    seed = {"inbounds": [
        {"tag": "wg-1", "protocol": "vless", "port": 1443, "listen": "0.0.0.0",
         "transport": "tcp", "security": "none"},
    ]}
    service, _store, _ = _svc(seed, driver=driver)
    result = asyncio.run(service.wizard_stage_create(driver, _spec()))
    assert result.valid and not result.changed


# --------------------------------------------------------------------- #
# misc parity — generic apply stays atomic & staged
# --------------------------------------------------------------------- #

def test_stage_apply_persists_nothing_until_committed():
    service, store, driver = _svc({"inbounds": [], "log": {"loglevel": "warning"}})
    result = asyncio.run(service.stage_apply(driver, [
        PatchOperation(op="replace", path="/log/loglevel", value="debug"),
    ]))
    assert result.valid and result.document["log"]["loglevel"] == "debug"
    doc = asyncio.run(store.get_document("stubcore"))
    assert doc["log"]["loglevel"] == "warning"  # not persisted yet
    asyncio.run(service.persist(driver, result.document))
    doc = asyncio.run(store.get_document("stubcore"))
    assert doc["log"]["loglevel"] == "debug"


def test_apply_operations_materialize_hook_gates_persistence():
    from app.cores.exceptions import CoreError

    service, store, driver = _svc({"inbounds": [], "log": {"loglevel": "warning"}})

    async def _reject(_doc):
        raise CoreError("engine down")

    with pytest.raises(CoreError):
        asyncio.run(service.apply_operations(driver, [
            PatchOperation(op="replace", path="/log/loglevel", value="debug"),
        ], materialize=_reject))
    doc = asyncio.run(store.get_document("stubcore"))
    assert doc["log"]["loglevel"] == "warning"  # refused candidate never stored
    # without a hook the same patch commits
    ok = asyncio.run(service.apply_operations(driver, [
        PatchOperation(op="replace", path="/log/loglevel", value="debug"),
    ]))
    assert ok.valid
    doc = asyncio.run(store.get_document("stubcore"))
    assert doc["log"]["loglevel"] == "debug"


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
