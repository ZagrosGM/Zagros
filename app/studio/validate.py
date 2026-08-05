"""JSON Schema subset validator for driver config documents.

Implements the subset drivers actually declare in ``CoreMetadata.config_schema``:
``type`` (object/array/string/integer/number/boolean/null), ``properties``,
``required``, ``items``, ``enum``, ``default`` (documentation only),
``minimum``/``maximum``, ``minLength``. Unknown keywords are ignored by
design (forward-compatible subset), documented in the docstring and tests.
"""
from __future__ import annotations

from typing import Any


class SchemaError(ValueError):
    def __init__(self, message: str, *, path: str = "") -> None:
        super().__init__(message)
        self.path = path


_TYPE_CHECKS = {
    "object": lambda v: isinstance(v, dict),
    "array": lambda v: isinstance(v, list),
    "string": lambda v: isinstance(v, str),
    "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
    "number": lambda v: isinstance(v, (int, float)) and not isinstance(v, bool),
    "boolean": lambda v: isinstance(v, bool),
    "null": lambda v: v is None,
}


def validate_against_schema(value: Any, schema: dict[str, Any], *,
                            path: str = "") -> list[SchemaError]:
    """Validate ``value``; returns a list of errors (empty = valid)."""
    errors: list[SchemaError] = []
    if not schema:
        return errors

    expected = schema.get("type")
    if expected:
        types = [expected] if isinstance(expected, str) else list(expected)
        if not any(_TYPE_CHECKS[t](value) for t in types):
            errors.append(SchemaError(
                f"expected type {'/'.join(types)}, got {type(value).__name__}",
                path=path or "/",
            ))
            return errors  # deeper checks are meaningless on a type mismatch

    if "enum" in schema and value not in schema["enum"]:
        errors.append(SchemaError(f"value {value!r} not in enum {schema['enum']!r}",
                                  path=path or "/"))

    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            errors.append(SchemaError(f"{value} < minimum {schema['minimum']}",
                                      path=path or "/"))
        if "maximum" in schema and value > schema["maximum"]:
            errors.append(SchemaError(f"{value} > maximum {schema['maximum']}",
                                      path=path or "/"))

    if isinstance(value, str) and "minLength" in schema \
            and len(value) < schema["minLength"]:
        errors.append(SchemaError(f"string shorter than minLength {schema['minLength']}",
                                  path=path or "/"))

    if isinstance(value, dict):
        for key in schema.get("required", []):
            if key not in value:
                errors.append(SchemaError(f"missing required property '{key}'",
                                          path=path or "/"))
        properties = schema.get("properties", {})
        for key, subschema in properties.items():
            if key in value:
                errors.extend(validate_against_schema(
                    value[key], subschema, path=f"{path}/{key}"
                ))

    if isinstance(value, list) and "items" in schema:
        for i, item in enumerate(value):
            errors.extend(validate_against_schema(
                item, schema["items"], path=f"{path}/{i}"
            ))

    return errors
