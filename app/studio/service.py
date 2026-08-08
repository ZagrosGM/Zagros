"""Config Studio service — validated patches, diff preview, inbound wizard."""
from __future__ import annotations

import asyncio
import difflib
import json
from typing import Any, Protocol

from pydantic import BaseModel, Field

from app.cores.base import BaseCoreDriver
from app.studio.jsonpatch import JsonPatchError, PatchOperation, apply_patches
from app.studio.validate import SchemaError, validate_against_schema


class StudioError(ValueError):
    pass


class WizardUnsupportedError(StudioError):
    """The core's driver did not declare a studio_inbounds_path — reported
    honestly instead of guessing where inbounds live in its config."""


class PreviewResult(BaseModel):
    core_id: str
    valid: bool
    errors: list[str] = Field(default_factory=list)
    diff: str = ""
    document: dict[str, Any] | None = None


class StudioStore(Protocol):
    """Port: per-core config document persistence (SQL adapter: settings KV)."""

    async def get_document(self, core_id: str) -> dict[str, Any] | None: ...
    async def save_document(self, core_id: str, document: dict[str, Any]) -> None: ...


class InMemoryStudioStore:
    def __init__(self) -> None:
        self._docs: dict[str, dict[str, Any]] = {}
        self._lock = asyncio.Lock()

    async def get_document(self, core_id: str) -> dict[str, Any] | None:
        import copy

        async with self._lock:
            doc = self._docs.get(core_id)
            return None if doc is None else copy.deepcopy(doc)

    async def save_document(self, core_id: str, document: dict[str, Any]) -> None:
        import copy

        async with self._lock:
            self._docs[core_id] = copy.deepcopy(document)


def unified_diff(old: dict[str, Any], new: dict[str, Any], *,
                 from_name: str = "current", to_name: str = "proposed") -> str:
    old_text = json.dumps(old, indent=2, ensure_ascii=False, sort_keys=True).splitlines()
    new_text = json.dumps(new, indent=2, ensure_ascii=False, sort_keys=True).splitlines()
    return "\n".join(difflib.unified_diff(old_text, new_text,
                                          fromfile=from_name, tofile=to_name,
                                          lineterm=""))


class InboundSpec(BaseModel):
    """Structured wizard input — what the visual Inbound editor produces.

    The wizard maps this onto a native inbound entry appended (via patch)
    to the core's declared ``studio_inbounds_path``; only generic fields the
    spec model knows are produced, everything core-specific goes through
    ``settings`` verbatim (and is covered by driver-side validation later).
    """

    tag: str
    protocol: str
    listen: str | None = None
    port: int = Field(ge=1, le=65535)
    settings: dict[str, Any] = Field(default_factory=dict)


class ConfigStudioService:
    """Graphical-first config management; Advanced Mode = raw + diff."""

    def __init__(self, store: StudioStore) -> None:
        self._store = store

    async def get_document(self, core_id: str,
                           driver: BaseCoreDriver | None = None) -> dict[str, Any]:
        doc = await self._store.get_document(core_id)
        if doc is not None:
            return doc
        # seed from the driver's live default template when available
        if driver is not None:
            default = getattr(driver, "export_config_document", None)
            if callable(default):
                seeded = default()
                if isinstance(seeded, dict):
                    await self._store.save_document(core_id, seeded)
                    return seeded
        return {}

    async def raw_text(self, core_id: str,
                       driver: BaseCoreDriver | None = None) -> str:
        """Advanced Mode: pretty raw JSON of the current document."""
        doc = await self.get_document(core_id, driver)
        return json.dumps(doc, indent=2, ensure_ascii=False, sort_keys=True)

    def _validate(self, driver: BaseCoreDriver, document: dict[str, Any]) -> list[SchemaError]:
        schema = driver.metadata.config_schema
        if not schema:
            return []
        return validate_against_schema(document, schema)

    async def preview(self, driver: BaseCoreDriver,
                      operations: list[PatchOperation]) -> PreviewResult:
        """Dry-run: patched copy + schema validation + unified diff (no write)."""
        current = await self.get_document(driver.metadata.id, driver)
        try:
            patched = apply_patches(current, operations)
        except JsonPatchError as exc:
            return PreviewResult(core_id=driver.metadata.id, valid=False,
                                 errors=[str(exc)])
        errors = self._validate(driver, patched)
        return PreviewResult(
            core_id=driver.metadata.id,
            valid=not errors,
            errors=[f"{e.path}: {e}" for e in errors],
            diff=unified_diff(current, patched),
            document=patched,
        )

    async def apply(self, driver: BaseCoreDriver,
                    operations: list[PatchOperation]) -> PreviewResult:
        """Validate then persist; invalid patches never touch the document."""
        result = await self.preview(driver, operations)
        if not result.valid:
            return result
        await self._store.save_document(driver.metadata.id, result.document or {})
        return result

    # ------------------------------------------------------------------ #
    # Inbound Wizard
    # ------------------------------------------------------------------ #
    def wizard_patch(self, driver: BaseCoreDriver, spec: InboundSpec) -> list[PatchOperation]:
        """Translate the structured wizard input into patch operations."""
        path = driver.metadata.studio_inbounds_path
        if not path:
            raise WizardUnsupportedError(
                f"core '{driver.metadata.id}' does not expose an inbound list to "
                "the studio (no studio_inbounds_path declared by its driver) — "
                "edit its raw document in Advanced Mode instead."
            )
        entry: dict[str, Any] = {
            "tag": spec.tag,
            "listen": spec.listen,
            "port": spec.port,
            "protocol": spec.protocol,
        }
        entry.update(spec.settings)
        return [PatchOperation(op="add", path=f"{path}/-", value=entry)]

    @staticmethod
    def _path_missing(doc: dict[str, Any], pointer: str) -> bool:
        """True when a JSON-Pointer's parent chain is absent (patch would 422)."""
        node: Any = doc
        for seg in (s for s in pointer.split("/") if s):
            if not isinstance(node, dict) or seg not in node:
                return True
            node = node[seg]
        return False

    async def _wizard_ops(self, driver: BaseCoreDriver,
                          spec: InboundSpec) -> list[PatchOperation]:
        """The patch set a wizard inbound would produce — shared by the
        dry-run (preview) and the real apply so both see EXACTLY the same
        document mutation."""
        path = driver.metadata.studio_inbounds_path
        entry_ops = self.wizard_patch(driver, spec)
        if not path:
            return entry_ops
        doc = await self.get_document(driver.metadata.id, driver)
        # getattr: third-party/metadata-mock drivers predate the field —
        # absence must read as "unlimited", never AttributeError.
        max_inbounds = getattr(driver.metadata, "studio_max_inbounds", None)
        if self._path_missing(doc, path):
            return [PatchOperation(op="add", path=path, value=[])] + entry_ops
        if max_inbounds is not None:
            existing = doc.get(path.strip("/"), [])
            count = len(existing) if isinstance(existing, list) else 0
            if count >= max_inbounds:
                # replace the ONLY listener (wizard = configure-the-listener)
                return [PatchOperation(op="replace", path=f"{path}/0",
                                       value=entry_ops[0].value)]
        return entry_ops

    async def wizard_preview_inbound(self, driver: BaseCoreDriver,
                                     spec: InboundSpec) -> PreviewResult:
        """Item 6 Preview gate: the wizard's exact patch + schema validation
        + unified diff WITHOUT persisting or materializing anything."""
        return await self.preview(driver, await self._wizard_ops(driver, spec))

    async def wizard_add_inbound(self, driver: BaseCoreDriver,
                                 spec: InboundSpec) -> PreviewResult:
        """Full wizard flow: build patch → validate → apply → return diff.

        Tolerant seeding: an empty document (core never started, store fresh)
        gets the inbound-list parent created first instead of 422ing.

        Single-listener engines (``studio_max_inbounds == 1``: wireguard,
        openvpn, ssh) physically bind ONE socket — the wizard
        replaces that listener instead of appending a second entry the
        engine could never serve (the old flow appended; the driver's
        cardinality guard then died as an opaque 500).
        """
        return await self.apply(driver, await self._wizard_ops(driver, spec))

    async def wizard_update_inbound(self, driver: BaseCoreDriver, tag: str,
                                    spec: InboundSpec) -> PreviewResult:
        """Item 11 — Edit an EXISTING inbound through the wizard: replace its
        document entry with the wizard-built one (the SAME entry builder as
        create, so shape stays identical); every earlier value must ride in
        the spec — nothing is silently reset. A missing tag is a loud 404,
        never a silent append."""
        path = driver.metadata.studio_inbounds_path
        if not path:
            raise StudioError(f"core '{driver.metadata.id}' exposes no studio inbounds")
        doc = await self.get_document(driver.metadata.id, driver)
        items = doc.get(path.strip("/"), []) if isinstance(doc, dict) else []
        idx = next(
            (i for i, e in enumerate(items)
             if isinstance(e, dict) and e.get("tag") == tag),
            None,
        )
        if idx is None:
            raise StudioError(
                f"core '{driver.metadata.id}' has no inbound tagged '{tag}'")
        entry = self.wizard_patch(driver, spec)[0].value
        return await self.apply(driver, [PatchOperation(
            op="replace", path=f"{path}/{idx}", value=entry)])
