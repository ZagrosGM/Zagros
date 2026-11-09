"""PostgreSQL returns ``settings.value_json`` already decoded (a ``dict``).

v1.1.4 field report: on a fresh ``--database postgresql`` install the v2
marker was written, but both readers ``json.loads``-ed the dict, hit
TypeError and treated the marker as v1/absent. dbmerge then re-ran on every
boot and retired (dropped) the legacy tables while ``app.db.base`` kept the
legacy engine on the empty legacy database: every Marzban-compat endpoint
(/api/users, /api/admins, /api/inbounds, ...) answered 500 and Xray could not
start ("relation \"users\" does not exist").

The existing marker tests replay on SQLite, which returns TEXT, so they could
not see this. These tests feed the readers what psycopg really returns.
"""
from __future__ import annotations

import json
from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from app import dbmerge


class _Result:
    def __init__(self, value):
        self._value = value

    def scalar(self):
        return self._value


class _Conn:
    def __init__(self, value, dialect="postgresql"):
        self._value = value
        self.dialect = SimpleNamespace(name=dialect)

    def execute(self, *_a, **_k):
        return _Result(self._value)

    def rollback(self):
        pass


@pytest.mark.parametrize("raw", [
    {"v": 2, "merged_at": "2026-11-09T16:21:39+00:00",
     "tables": {"schema_only_legacy": True}},          # psycopg json → dict
    json.dumps({"v": 2}),                               # sqlite / mysql → str
    json.dumps({"v": 2}).encode(),                      # some drivers → bytes
])
def test_marker_reader_accepts_every_driver_shape(raw):
    payload = dbmerge.read_marker_value(_Conn(raw))
    assert isinstance(payload, str)
    assert json.loads(payload)["v"] == 2
    assert dbmerge._marker_version(payload) == dbmerge.MARKER_VERSION


def test_absent_marker_stays_absent():
    assert dbmerge.read_marker_value(_Conn(None)) is None
    assert dbmerge._marker_version(None) == 0


def test_legacy_engine_switch_sees_a_decoded_v2_marker(monkeypatch):
    """``app.db.base._marker_present`` must honour the PostgreSQL shape."""
    import app.db.base as base

    conn = _Conn({"v": dbmerge.MARKER_VERSION})

    class _Engine:
        @contextmanager
        def connect(self):
            yield conn

        def dispose(self):
            pass

    monkeypatch.setattr(base, "create_engine", lambda *_a, **_k: _Engine())
    assert base._marker_present("postgresql+psycopg://u:p@db/zagros") is True


def test_legacy_engine_switch_rejects_a_decoded_v1_marker(monkeypatch):
    import app.db.base as base

    conn = _Conn({"v": 1})

    class _Engine:
        @contextmanager
        def connect(self):
            yield conn

        def dispose(self):
            pass

    monkeypatch.setattr(base, "create_engine", lambda *_a, **_k: _Engine())
    assert base._marker_present("postgresql+psycopg://u:p@db/zagros") is False
