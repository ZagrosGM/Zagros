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


class StudioConflictError(StudioError):
    """Identity clash — the requested inbound tag already exists with
    DIFFERENT settings (mapped to HTTP 409, so a create retry after a
    timeout can never forklift a second, conflicting inbound in)."""


class StudioNotFoundError(StudioError):
    """The addressed inbound (stable identity = its tag) does not exist —
    mapped to HTTP 404; deleting/editing a ghost is never a success."""


class PreviewResult(BaseModel):
    core_id: str
    valid: bool
    errors: list[str] = Field(default_factory=list)
    diff: str = ""
    document: dict[str, Any] | None = None
    # alpha.7.5 item 5: ``changed=False`` marks an IDEMPOTENT REPLAY — the
    # desired state already exists exactly, so no mutation/materialize is
    # required (a double-click or a retry-after-timeout stays harmless).
    changed: bool = True
    detail: str | None = None


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


def _entry_fingerprint(entry: Any) -> str:
    """Stable deep-compare token for an inbound entry (order-insensitive) —
    the idempotency check for create retries (alpha.7.5 item 5)."""
    return json.dumps(entry, sort_keys=True, ensure_ascii=False, default=str)


class ConfigStudioService:
    """Graphical-first config management; Advanced Mode = raw + diff.

    Mutation lifecycle (alpha.7.5 item 5): create/update/delete STAGE a
    validated candidate under a per-core lock (dup-identity + concurrency
    rules enforced here); the ROUTE then materializes the candidate into
    the core and only persists on success — a failed live apply never moves
    the stored document to a state the core refused.
    """

    def __init__(self, store: StudioStore) -> None:
        self._store = store
        self._locks: dict[str, asyncio.Lock] = {}

    def _lock_for(self, core_id: str) -> asyncio.Lock:
        lock = self._locks.get(core_id)
        if lock is None:
            lock = asyncio.Lock()
            self._locks[core_id] = lock
        return lock

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

    async def stage_apply(self, driver: BaseCoreDriver,
                          operations: list[PatchOperation]) -> PreviewResult:
        """Atomic lifecycle (alpha.7.5 item 5): a VALIDATED CANDIDATE under
        the per-core mutation lock — nothing persisted yet. The caller
        materializes ``result.document`` into the core and only then calls
        :meth:`persist`."""
        async with self._lock_for(driver.metadata.id):
            return await self.preview(driver, operations)

    async def persist(self, driver: BaseCoreDriver, document: dict[str, Any]) -> None:
        """Store a candidate the core has already accepted (stage →
        materialize → persist). Direct persistence of un-materialized
        documents stays available via :meth:`apply` for headless flows."""
        await self._store.save_document(driver.metadata.id, document)

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

    def _inbound_items(self, doc: dict[str, Any], path: str) -> list[Any]:
        items = doc.get(path.strip("/"), []) if isinstance(doc, dict) else []
        return items if isinstance(items, list) else []

    async def _wizard_create_candidate(self, driver: BaseCoreDriver,
                                       spec: InboundSpec) -> PreviewResult:
        """Lock-INTERNAL staging — call only while holding the core lock
        (see :meth:`wizard_create`)."""
        path = driver.metadata.studio_inbounds_path
        if not path:
            raise WizardUnsupportedError(
                f"core '{driver.metadata.id}' does not expose an inbound list to "
                "the studio (no studio_inbounds_path declared by its driver) — "
                "edit its raw document in Advanced Mode instead."
            )
        doc = await self.get_document(driver.metadata.id, driver)
        items = self._inbound_items(doc, path)
        entry = self.wizard_patch(driver, spec)[0].value
        max_inbounds = getattr(driver.metadata, "studio_max_inbounds", None)
        existing = next((e for e in items
                         if isinstance(e, dict) and e.get("tag") == spec.tag), None)
        if existing is not None:
            if _entry_fingerprint(existing) == _entry_fingerprint(entry):
                return PreviewResult(
                    core_id=driver.metadata.id, valid=True, changed=False,
                    document=doc,
                    detail=f"inbound '{spec.tag}' already exists exactly as "
                           f"requested — idempotent replay, nothing changed")
            raise StudioConflictError(
                f"core '{driver.metadata.id}' already has an inbound tagged "
                f"'{spec.tag}' with DIFFERENT settings — edit it, clone it "
                f"under a new tag, or delete it first (refusing to append a "
                f"conflicting twin)")
        if max_inbounds == 1 and items:
            # configure-the-listener: replacing the one listener IS the
            # create on a single-socket engine (its own semantic, kept)
            if _entry_fingerprint(items[0]) == _entry_fingerprint(entry):
                return PreviewResult(
                    core_id=driver.metadata.id, valid=True, changed=False,
                    document=doc,
                    detail=f"the {driver.metadata.id} listener already matches "
                           f"this spec exactly — idempotent replay")
        return await self.preview(driver, await self._wizard_ops(driver, spec))

    async def _wizard_update_candidate(self, driver: BaseCoreDriver, tag: str,
                                       spec: InboundSpec) -> PreviewResult:
        """Lock-INTERNAL staging for edits."""
        path = driver.metadata.studio_inbounds_path
        if not path:
            raise StudioError(f"core '{driver.metadata.id}' exposes no studio inbounds")
        doc = await self.get_document(driver.metadata.id, driver)
        items = self._inbound_items(doc, path)
        idx = next(
            (i for i, e in enumerate(items)
             if isinstance(e, dict) and e.get("tag") == tag),
            None,
        )
        if idx is None:
            raise StudioNotFoundError(
                f"core '{driver.metadata.id}' has no inbound tagged '{tag}' "
                f"(valid: {sorted(str(e.get('tag')) for e in items if isinstance(e, dict) and e.get('tag')) or '— none configured'})")
        entry = self.wizard_patch(driver, spec)[0].value
        if spec.tag != tag:
            # a rename must not fork a conflicting twin either
            twin = next((e for e in items
                         if isinstance(e, dict) and e.get("tag") == spec.tag), None)
            if twin is not None:
                raise StudioConflictError(
                    f"renaming '{tag}' to '{spec.tag}' clashes with an existing "
                    f"inbound — pick a unique tag")
        if _entry_fingerprint(items[idx]) == _entry_fingerprint(entry):
            return PreviewResult(
                core_id=driver.metadata.id, valid=True, changed=False,
                document=doc,
                detail=f"inbound '{tag}' already matches — nothing to update")
        return await self.preview(driver, [PatchOperation(
            op="replace", path=f"{path}/{idx}", value=entry)])

    async def _wizard_delete_candidate(self, driver: BaseCoreDriver,
                                       tag: str) -> PreviewResult:
        """Lock-INTERNAL staging for deletes."""
        path = driver.metadata.studio_inbounds_path
        if not path:
            raise StudioError(f"core '{driver.metadata.id}' exposes no studio inbounds")
        doc = await self.get_document(driver.metadata.id, driver)
        items = self._inbound_items(doc, path)
        idxs = [i for i, e in enumerate(items)
                if isinstance(e, dict) and e.get("tag") == tag]
        if not idxs:
            raise StudioNotFoundError(
                f"core '{driver.metadata.id}' has no inbound tagged '{tag}' "
                f"— nothing to delete")
        if len(idxs) > 1:
            raise StudioConflictError(
                f"core '{driver.metadata.id}' has {len(idxs)} inbounds tagged "
                f"'{tag}' — the identity is ambiguous; refusing to delete. "
                f"Fix the duplicate tags in Advanced Mode first.")
        return await self.preview(driver, [PatchOperation(
            op="remove", path=f"{path}/{idxs[0]}")])

    async def _wizard_execute(self, driver: BaseCoreDriver, stage,
                              materialize=None) -> PreviewResult:
        """THE atomic wizard transaction (alpha.7.5 item 5): the per-core
        lock covers candidate-build → core-materialize → persist, so
        concurrent lifecycle calls fully serialize; a failure inside
        ``materialize`` propagates WITHOUT persisting (the 'request failed
        but the inbound was created anyway' split is gone); an identical
        replay short-circuits inside the lock."""
        async with self._lock_for(driver.metadata.id):
            result = await stage()
            if not result.valid or not result.changed:
                return result
            if materialize is not None:
                await materialize(result.document)
            await self.persist(driver, result.document)
            return result

    async def wizard_create(self, driver: BaseCoreDriver, spec: InboundSpec,
                            materialize=None) -> PreviewResult:
        """Atomic CREATE (the routed flow): identity + idempotency rules of
        the staging step, executed under the transaction lock."""
        return await self._wizard_execute(
            driver, lambda: self._wizard_create_candidate(driver, spec), materialize)

    async def wizard_update(self, driver: BaseCoreDriver, tag: str,
                            spec: InboundSpec, materialize=None) -> PreviewResult:
        """Atomic EDIT-in-place (item 11 + item 5)."""
        return await self._wizard_execute(
            driver, lambda: self._wizard_update_candidate(driver, tag, spec),
            materialize)

    async def wizard_delete(self, driver: BaseCoreDriver, tag: str,
                            materialize=None) -> PreviewResult:
        """Atomic DELETE by stable identity — exactly one entry, ghost ≠
        success, ambiguous twin-tags refused."""
        return await self._wizard_execute(
            driver, lambda: self._wizard_delete_candidate(driver, tag), materialize)

    async def apply_operations(self, driver: BaseCoreDriver,
                               operations: list[PatchOperation],
                               materialize=None) -> PreviewResult:
        """Atomic raw-patch apply (Advanced Mode routed flow): preview →
        materialize → persist under the per-core lock; an engine refusal
        stops before persistence, exactly like the wizard flows."""
        return await self._wizard_execute(
            driver, lambda: self.preview(driver, operations), materialize)

    async def wizard_stage_create(self, driver: BaseCoreDriver,
                                  spec: InboundSpec) -> PreviewResult:
        """Stage a wizard CREATE (candidate only — no materialize/persist).

        Rules (alpha.7.5 item 5 — the field-reported duplicate/500 storm):

        * STABLE IDENTITY = the tag. An identical create replay (double
          click / retry after a timed-out request that actually succeeded)
          returns ``changed=False`` — success WITHOUT a duplicate;
        * same tag with DIFFERENT settings raises :class:`StudioConflictError`
          (HTTP 409) instead of silently appending a twin;
        * single-listener engines (``studio_max_inbounds == 1``) keep their
          configure-the-listener replace semantics — that IS the edit path
          for them, under the same lock.

        NOTE: for the committing flow use :meth:`wizard_create` — staging
        alone does not guard the full transaction.
        """
        async with self._lock_for(driver.metadata.id):
            return await self._wizard_create_candidate(driver, spec)

    async def wizard_stage_update(self, driver: BaseCoreDriver, tag: str,
                                  spec: InboundSpec) -> PreviewResult:
        """Stage a wizard EDIT (candidate only): ghost tag →
        :class:`StudioNotFoundError`, rename clash →
        :class:`StudioConflictError`, identical replay → ``changed=False``."""
        async with self._lock_for(driver.metadata.id):
            return await self._wizard_update_candidate(driver, tag, spec)

    async def wizard_stage_delete(self, driver: BaseCoreDriver,
                                  tag: str) -> PreviewResult:
        """Stage a wizard DELETE (candidate only — see :meth:`wizard_delete`)."""
        async with self._lock_for(driver.metadata.id):
            return await self._wizard_delete_candidate(driver, tag)

    async def wizard_add_inbound(self, driver: BaseCoreDriver,
                                 spec: InboundSpec) -> PreviewResult:
        """Headless convenience (tests/CLI): atomic stage + persist in one
        call — the ROUTED flow passes a ``materialize`` hook so a refused
        live apply never moves the document.

        Single-listener engines (``studio_max_inbounds == 1``: wireguard,
        openvpn, ssh) physically bind ONE socket — the wizard
        replaces that listener instead of appending a second entry the
        engine could never serve.
        """
        return await self.wizard_create(driver, spec)

    async def wizard_update_inbound(self, driver: BaseCoreDriver, tag: str,
                                    spec: InboundSpec) -> PreviewResult:
        """Item 11 — headless convenience: atomic edit + persist (the routed
        flow materializes between the two, inside the same lock)."""
        return await self.wizard_update(driver, tag, spec)
