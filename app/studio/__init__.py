"""Zagros Config Studio — graphical config management without hand-edited JSON.

Admins work with structured operations (RFC 6902 patches, wizards); the
studio validates them against the driver's declared ``config_schema``,
shows a unified *diff preview* (also powering Advanced Mode's diff viewer)
and only then applies. Drivers declare where their inbound list lives via
``CoreMetadata.studio_inbounds_path`` — the studio hardcodes nothing about
core config layouts.
"""
from app.studio.jsonpatch import JsonPatchError, PatchOperation, apply_patches
from app.studio.service import (
    ConfigStudioService,
    InboundSpec,
    InMemoryStudioStore,
    PreviewResult,
    StudioError,
    StudioStore,
    WizardUnsupportedError,
)
from app.studio.validate import SchemaError, validate_against_schema

__all__ = [
    "JsonPatchError",
    "PatchOperation",
    "apply_patches",
    "ConfigStudioService",
    "InboundSpec",
    "InMemoryStudioStore",
    "PreviewResult",
    "StudioError",
    "StudioStore",
    "WizardUnsupportedError",
    "SchemaError",
    "validate_against_schema",
]
