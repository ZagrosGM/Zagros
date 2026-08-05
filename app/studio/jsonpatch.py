"""RFC 6902 JSON Patch — minimal, strict implementation.

Supported ops: add / remove / replace / move / copy / test, with full JSON
Pointer (RFC 6901) unescaping (``~0`` → ``~``, ``~1`` → ``/``) and the
array ``-`` (append) index. Errors carry the failing pointer so the UI can
highlight the exact location.
"""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class JsonPatchError(ValueError):
    def __init__(self, message: str, *, pointer: str = "", op: str = "") -> None:
        super().__init__(message)
        self.pointer = pointer
        self.op = op


class PatchOperation(BaseModel):
    op: str = Field(pattern=r"^(add|remove|replace|move|copy|test)$")
    path: str
    from_: str | None = Field(default=None, alias="from")
    value: Any = None

    model_config = {"populate_by_name": True}


def _split(pointer: str) -> list[str]:
    if pointer == "":
        return []
    if not pointer.startswith("/"):
        raise JsonPatchError(f"JSON pointer must start with '/': {pointer!r}", pointer=pointer)
    return [seg.replace("~1", "/").replace("~0", "~") for seg in pointer[1:].split("/")]


def _resolve(doc: Any, segments: list[str], *, create_missing: bool = False) -> Any:
    node = doc
    for seg in segments:
        if isinstance(node, dict):
            if seg not in node:
                if create_missing:
                    node[seg] = {}
                else:
                    raise JsonPatchError(f"missing key '{seg}'", pointer="/" + "/".join(segments))
            node = node[seg]
        elif isinstance(node, list):
            if seg == "-":
                raise JsonPatchError("'-' only valid as final segment", pointer="/" + "/".join(segments))
            try:
                idx = int(seg)
            except ValueError as exc:
                raise JsonPatchError(f"bad array index '{seg}'", pointer="/" + "/".join(segments)) from exc
            if not 0 <= idx < len(node):
                raise JsonPatchError(f"array index {idx} out of range", pointer="/" + "/".join(segments))
            node = node[idx]
        else:
            raise JsonPatchError(f"cannot descend into scalar at '{seg}'",
                                 pointer="/" + "/".join(segments))
    return node


def _get(doc: Any, pointer: str) -> Any:
    return _resolve(doc, _split(pointer))


def _add(doc: Any, pointer: str, value: Any) -> Any:
    segments = _split(pointer)
    if not segments:
        return value
    parent = _resolve(doc, segments[:-1], create_missing=False)
    key = segments[-1]
    if isinstance(parent, dict):
        parent[key] = value
    elif isinstance(parent, list):
        if key == "-":
            parent.append(value)
        else:
            try:
                idx = int(key)
            except ValueError as exc:
                raise JsonPatchError(f"bad array index '{key}'", pointer=pointer) from exc
            if not 0 <= idx <= len(parent):
                raise JsonPatchError(f"array index {idx} out of range", pointer=pointer)
            parent.insert(idx, value)
    else:
        raise JsonPatchError("add target parent is not a container", pointer=pointer)
    return doc


def _remove(doc: Any, pointer: str) -> tuple[Any, Any]:
    segments = _split(pointer)
    if not segments:
        raise JsonPatchError("cannot remove the document root", pointer=pointer)
    parent = _resolve(doc, segments[:-1])
    key = segments[-1]
    if isinstance(parent, dict):
        if key not in parent:
            raise JsonPatchError(f"missing key '{key}'", pointer=pointer)
        return doc, parent.pop(key)
    if isinstance(parent, list):
        try:
            idx = int(key)
        except ValueError as exc:
            raise JsonPatchError(f"bad array index '{key}'", pointer=pointer) from exc
        if not 0 <= idx < len(parent):
            raise JsonPatchError(f"array index {idx} out of range", pointer=pointer)
        return doc, parent.pop(idx)
    raise JsonPatchError("remove target parent is not a container", pointer=pointer)


def _replace(doc: Any, pointer: str, value: Any) -> Any:
    segments = _split(pointer)
    if not segments:
        return value
    parent = _resolve(doc, segments[:-1])
    key = segments[-1]
    if isinstance(parent, dict):
        if key not in parent:
            raise JsonPatchError(f"missing key '{key}'", pointer=pointer)
        parent[key] = value
    elif isinstance(parent, list):
        try:
            idx = int(key)
        except ValueError as exc:
            raise JsonPatchError(f"bad array index '{key}'", pointer=pointer) from exc
        if not 0 <= idx < len(parent):
            raise JsonPatchError(f"array index {idx} out of range", pointer=pointer)
        parent[idx] = value
    else:
        raise JsonPatchError("replace target parent is not a container", pointer=pointer)
    return doc


def _deep_equal(a: Any, b: Any) -> bool:
    return a == b


def apply_patches(document: Any, operations: list[PatchOperation]) -> Any:
    """Apply RFC 6902 operations in order; returns the patched document.

    Input is deep-copied first — callers' documents are never mutated.
    Failed `test` ops abort before any later op runs (atomicity is the
    caller's job: work on the copy until apply succeeds).
    """
    import copy

    doc = copy.deepcopy(document)
    for i, operation in enumerate(operations):
        op = operation.op
        try:
            if op == "add":
                doc = _add(doc, operation.path, operation.value)
            elif op == "remove":
                doc, _ = _remove(doc, operation.path)
            elif op == "replace":
                doc = _replace(doc, operation.path, operation.value)
            elif op == "move":
                if not operation.from_:
                    raise JsonPatchError("move requires 'from'", op=op)
                doc, value = _remove(doc, operation.from_)
                doc = _add(doc, operation.path, value)
            elif op == "copy":
                if not operation.from_:
                    raise JsonPatchError("copy requires 'from'", op=op)
                doc = _add(doc, operation.path, copy.deepcopy(_get(doc, operation.from_)))
            elif op == "test":
                if not _deep_equal(_get(doc, operation.path), operation.value):
                    raise JsonPatchError("test failed: value mismatch", pointer=operation.path)
        except JsonPatchError as exc:
            exc.op = exc.op or op
            if not exc.pointer:
                exc.pointer = operation.path
            raise JsonPatchError(f"patch #{i} ({op}) failed: {exc}",
                                 pointer=exc.pointer, op=exc.op) from exc
    return doc
