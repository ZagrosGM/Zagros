"""Config Studio tests — RFC 6902 patches, schema validation, wizard, diffs.

Run: pytest tests/studio/test_studio.py -v   OR   python tests/studio/test_studio.py
"""
from __future__ import annotations

import asyncio
import sys
import traceback
import types as _types
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
if "app" not in sys.modules:
    _pkg = _types.ModuleType("app")
    _pkg.__path__ = [str(ROOT / "app")]
    sys.modules["app"] = _pkg

from app.cores.types import Capability, CoreMetadata  # noqa: E402
from app.studio.jsonpatch import JsonPatchError, PatchOperation, apply_patches  # noqa: E402
from app.studio.service import (  # noqa: E402
    ConfigStudioService,
    InboundSpec,
    InMemoryStudioStore,
    WizardUnsupportedError,
)
from app.studio.validate import validate_against_schema  # noqa: E402


class _StubDriver:
    """Metadata-only driver stand-in (studio consumes only metadata)."""

    def __init__(self, *, inbounds_path: str | None = "/inbounds",
                 schema: dict | None = None):
        self.metadata = CoreMetadata(
            id="stubcore", name="StubCore", description="",
            protocols=["vless"], capabilities=set(Capability),
            config_schema=schema or {},
            studio_inbounds_path=inbounds_path,
        )


_SCHEMA = {
    "type": "object",
    "required": ["log", "inbounds"],
    "properties": {
        "log": {"type": "object", "properties": {"loglevel": {"type": "string",
                                                              "enum": ["debug", "info", "warning", "error"]}}},
        "inbounds": {"type": "array", "items": {
            "type": "object",
            "required": ["tag", "protocol", "port"],
            "properties": {
                "tag": {"type": "string", "minLength": 1},
                "protocol": {"type": "string"},
                "port": {"type": "integer", "minimum": 1, "maximum": 65535},
            },
        }},
        "remarks": {"type": ["string", "null"]},
    },
}

_DOC = {"log": {"loglevel": "warning"}, "inbounds": [{"tag": "in-1", "protocol": "vless", "port": 443}]}


# ---------------------------------------------------------------------- #
# jsonpatch
# ---------------------------------------------------------------------- #

def test_jsonpatch_all_operations() -> None:
    doc = {"a": {"b": [1, 2, 3]}, "x": 1, "esc~key": True, "esc/slash": 2}
    out = apply_patches(doc, [
        PatchOperation(op="add", path="/a/b/-", value=4),
        PatchOperation(op="replace", path="/a/b/0", value=10),
        PatchOperation(op="copy", from_="/a", path="/c"),
        PatchOperation(op="move", from_="/x", path="/y"),
        PatchOperation(op="test", path="/esc~0key", value=True),
        PatchOperation(op="replace", path="/esc~1slash", value=20),
        PatchOperation(op="remove", path="/c"),
    ])
    assert out["a"]["b"] == [10, 2, 3, 4]
    assert "x" not in out and out["y"] == 1
    assert out["esc/slash"] == 20 and "c" not in out
    assert doc["a"]["b"] == [1, 2, 3] and "c" not in doc  # input not mutated


def test_jsonpatch_errors_carry_pointer() -> None:
    for patches, needle in (
        ([PatchOperation(op="replace", path="/missing", value=1)], "/missing"),
        ([PatchOperation(op="remove", path="/a/b/9", value=None)], "/a/b/9"),
        ([PatchOperation(op="test", path="/x", value=999)], "/x"),
        ([PatchOperation(op="add", path="no-slash", value=1)], "no-slash"),
        ([PatchOperation(op="move", path="/z", value=None)], "move requires 'from'"),
    ):
        try:
            apply_patches({"a": {"b": [1]}, "x": 1}, patches)
            raise AssertionError(f"patch accepted: {patches}")
        except JsonPatchError as exc:
            assert needle in str(exc) or needle in (exc.pointer or "")


# ---------------------------------------------------------------------- #
# schema validation
# ---------------------------------------------------------------------- #

def test_schema_validation_reports_all_errors_with_paths() -> None:
    doc = {"log": {"loglevel": "verbose"}, "inbounds": [{"protocol": "vless", "port": 70000}],
           "remarks": 5}
    errors = validate_against_schema(doc, _SCHEMA)
    blob = "\n".join(f"{e.path}: {e}" for e in errors)
    assert "/log/loglevel" in blob and "enum" in blob
    assert "/inbounds/0" in blob and "required property 'tag'" in blob
    assert "/inbounds/0/port" in blob and "maximum" in blob
    assert "/remarks" in blob and "type" in blob
    assert validate_against_schema(_DOC, _SCHEMA) == []


# ---------------------------------------------------------------------- #
# studio service: preview / apply / wizard
# ---------------------------------------------------------------------- #

def _service() -> tuple[ConfigStudioService, InMemoryStudioStore, _StubDriver]:
    store = InMemoryStudioStore()
    driver = _StubDriver(schema=_SCHEMA)
    asyncio.run(store.save_document("stubcore", dict(_DOC)))
    return ConfigStudioService(store), store, driver


def test_preview_shows_diff_without_writing() -> None:
    service, store, driver = _service()
    result = asyncio.run(service.preview(driver, [
        PatchOperation(op="replace", path="/log/loglevel", value="debug"),
        PatchOperation(op="add", path="/inbounds/-", value={"tag": "in-2", "protocol": "trojan", "port": 8443}),
    ]))
    assert result.valid and "debug" in result.diff and '-    "loglevel": "warning"' in result.diff
    current = asyncio.run(store.get_document("stubcore"))
    assert current["log"]["loglevel"] == "warning"  # preview did not write


def test_invalid_patch_and_schema_rejection_are_atomic() -> None:
    service, store, driver = _service()
    bad = asyncio.run(service.apply(driver, [
        PatchOperation(op="replace", path="/log/loglevel", value="loud"),  # enum violation
    ]))
    assert not bad.valid and any("enum" in e for e in bad.errors)
    really_bad = asyncio.run(service.apply(driver, [
        PatchOperation(op="replace", path="/no/such/path", value=1),
    ]))
    assert not really_bad.valid
    assert asyncio.run(store.get_document("stubcore")) == _DOC  # untouched


def test_apply_persists_document() -> None:
    service, store, driver = _service()
    result = asyncio.run(service.apply(driver, [
        PatchOperation(op="replace", path="/log/loglevel", value="error"),
    ]))
    assert result.valid
    assert asyncio.run(store.get_document("stubcore"))["log"]["loglevel"] == "error"


def test_wizard_adds_inbound_structurally() -> None:
    service, store, driver = _service()
    spec = InboundSpec(tag="wg-in", protocol="vless", port=443,
                       settings={"security": "reality", "clients": []})
    result = asyncio.run(service.wizard_add_inbound(driver, spec))
    assert result.valid, result.errors
    doc = asyncio.run(store.get_document("stubcore"))
    assert len(doc["inbounds"]) == 2
    assert doc["inbounds"][1]["tag"] == "wg-in"
    assert doc["inbounds"][1]["security"] == "reality"


def test_wizard_unsupported_core_reported_honestly() -> None:
    driver = _StubDriver(inbounds_path=None)
    service = ConfigStudioService(InMemoryStudioStore())
    try:
        service.wizard_patch(driver, InboundSpec(tag="x", protocol="vless", port=1))
        raise AssertionError("wizard worked on an unsupported core")
    except WizardUnsupportedError as exc:
        assert "studio_inbounds_path" in str(exc)


def test_raw_text_is_sorted_pretty_json() -> None:
    service, _, driver = _service()
    raw = asyncio.run(service.raw_text("stubcore"))
    assert raw.startswith("{") and '"inbounds"' in raw and raw.count("\n") > 3


if __name__ == "__main__":
    tests = [(k, v) for k, v in sorted(globals().items()) if k.startswith("test_")]
    failed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"PASS {name}")
        except Exception:  # noqa: BLE001
            failed += 1
            print(f"FAIL {name}")
            traceback.print_exc()
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    sys.exit(1 if failed else 0)
