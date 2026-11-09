"""dbmerge copies rows WITH their ids — PostgreSQL sequences must follow.

v1.1.4 field report: after the merge ``legacy_admins_id_seq`` was still at 1
while a copied admin had id=1, so the first admin created afterwards failed
with a misleading 409 "Admin already exists". The merge must move each
serial sequence past the copied ids on PostgreSQL, and do nothing elsewhere.
"""
from __future__ import annotations

from types import SimpleNamespace

from sqlalchemy import Column, Integer, MetaData, String, Table

from app import dbmerge


class _Result:
    def __init__(self, value):
        self._value = value

    def scalar(self):
        return self._value


class _RecordingConn:
    def __init__(self, dialect: str):
        self.dialect = SimpleNamespace(name=dialect)
        self.statements: list[tuple[str, dict]] = []

    def execute(self, statement, params=None):
        sql = str(statement)
        self.statements.append((sql, dict(params or {})))
        if "pg_get_serial_sequence" in sql:
            return _Result(f"public.{params['t']}_{params['c']}_seq")
        return _Result(None)


def _tables():
    meta = MetaData()
    admins = Table("legacy_admins", meta,
                   Column("id", Integer, primary_key=True),
                   Column("username", String(32)))
    assoc = Table("template_inbounds_association", meta,
                  Column("user_template_id", Integer, primary_key=True),
                  Column("inbound_tag", String(256), primary_key=True))
    keyed = Table("system_kv", meta, Column("key", String(64), primary_key=True))
    return admins, assoc, keyed


def test_postgres_sequences_are_moved_past_copied_ids():
    conn = _RecordingConn("postgresql")
    dbmerge._reset_pg_sequences(conn, list(_tables()))
    setvals = [(sql, p) for sql, p in conn.statements if "setval" in sql]
    # only the single-column integer PK gets a setval; composite / text
    # primary keys have no sequence to move
    assert len(setvals) == 1
    sql, params = setvals[0]
    assert params == {"s": "public.legacy_admins_id_seq"}
    assert 'MAX("id") FROM "legacy_admins"' in sql
    assert "false" in sql  # next nextval() == max(id) + 1


def test_other_dialects_are_left_alone():
    for dialect in ("sqlite", "mysql", "mariadb"):
        conn = _RecordingConn(dialect)
        dbmerge._reset_pg_sequences(conn, list(_tables()))
        assert conn.statements == []
