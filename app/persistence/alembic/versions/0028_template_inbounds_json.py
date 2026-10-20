"""Verbatim xray inbound selection on user templates.

Revision ID: 0028_template_inbounds_json
Revises: 0027_template_link

f-tplsel-1 (v1.1.3 bugfix 1): a template's xray inbound selection used to be
re-derived from the ``template_inbounds_association`` rows joined against the
LIVE xray config registry on every read. Two real deployments broke it:
a panel whose xray core is not running (or whose listeners were renamed)
returned ``{}`` for every template — and "create user from template"
pre-selected nothing, forcing the operator to pick inbounds by hand.
``user_templates.inbounds_json`` stores the operator's exact selection
(``{protocol: [tags]}``, ``[]`` = every inbound of that protocol) the same
way ``core_access`` already is; the association stays in sync best-effort
for older readers (the Telegram bot) but is no longer the source of truth.

Existing rows keep ``NULL`` — the response falls back to the association
derivation until the template is saved again, which backfills the JSON.
"""
from __future__ import annotations

from alembic import op  # noqa: F401  (kept for tooling parity; P3 bind unused)

revision = "0028_template_inbounds_json"
down_revision = "0027_template_link"
branch_labels = None
depends_on = None

_COLUMN = "inbounds_json"


def _existing_columns(conn, table: str) -> set[str]:
    from sqlalchemy import inspect

    return {c["name"] for c in inspect(conn).get_columns(table)}


def upgrade() -> None:
    from sqlalchemy import create_engine, text

    engine = create_engine(_legacy_url())
    tname = "user_templates"
    try:
        with engine.begin() as conn:
            from app.persistence.alembic._legacy import table as _t
            existing = _existing_columns(conn, _t(tname))
            if _COLUMN not in existing:
                conn.execute(text(
                    f"ALTER TABLE {_t(tname)} ADD COLUMN {_COLUMN} JSON"))
                print(f"{tname}.{_COLUMN} added")
    finally:
        engine.dispose()


def downgrade() -> None:
    from sqlalchemy import create_engine, text

    engine = create_engine(_legacy_url())
    tname = "user_templates"
    try:
        with engine.begin() as conn:
            from app.persistence.alembic._legacy import table as _t
            existing = _existing_columns(conn, _t(tname))
            if _COLUMN in existing:
                conn.execute(text(
                    f"ALTER TABLE {_t(tname)} DROP COLUMN {_COLUMN}"))
    finally:
        engine.dispose()


def _legacy_url() -> str:
    from app.persistence.alembic._legacy import legacy_url as _shared
    return _shared()
