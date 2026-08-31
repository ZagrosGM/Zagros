"""A missing JWT secret must explain itself (alpha.9.3+ follow-up).

The ``init_jwt_table`` migration seeds the row. When it has not run, the old
code did ``db.query(JWT).first().secret_key`` and died with
``AttributeError: 'NoneType' object has no attribute 'secret_key'`` — a
traceback that names neither JWT nor migrations, and that only showed up in
one test-file ordering because the full suite seeds the row first.

Two rules this locks in:

* the data accessor returns ``None`` instead of dereferencing ``None``;
* the caller turns that into a message that says what to run.

Inventing a secret on the spot is NOT an option: it would silently
invalidate every token already issued.

Run: pytest tests/platform/test_jwt_secret_missing.py -q
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

import pytest  # noqa: E402

from app.db import crud  # noqa: E402


class _Result:
    def __init__(self, row):
        self._row = row

    def first(self):
        return self._row


class _Query:
    def __init__(self, row):
        self._row = row

    def query(self, _model):
        return _Result(self._row)


class _Row:
    def __init__(self, secret_key):
        self.secret_key = secret_key


class _Session:
    """Stands in for ``GetDB()``: a context manager yielding the query stub."""

    def __init__(self, row=None):
        self._row = row

    def __enter__(self):
        return _Query(self._row)

    def __exit__(self, *_exc):
        return False


def test_unseeded_table_returns_none_instead_of_dereferencing_it():
    assert crud.get_jwt_secret_key(_Query(None)) is None


def test_seeded_table_returns_its_secret():
    assert crud.get_jwt_secret_key(_Query(_Row("abc"))) == "abc"


def test_get_secret_key_explains_what_to_run(monkeypatch):
    from app.utils import jwt as jwt_utils

    import app.db as db_pkg

    monkeypatch.setattr(db_pkg, "get_jwt_secret_key", lambda _db: None)
    monkeypatch.setattr(db_pkg, "GetDB", lambda: _Session(None))
    jwt_utils.get_secret_key.cache_clear()
    try:
        with pytest.raises(RuntimeError) as excinfo:
            jwt_utils.get_secret_key()
    finally:
        jwt_utils.get_secret_key.cache_clear()
    message = str(excinfo.value)
    assert "migration" in message
    assert "init_jwt_table" in message


def test_a_failed_lookup_is_not_cached():
    """lru_cache does not memoise exceptions, so fixing the database and
    retrying must work without restarting the panel."""
    from app.utils import jwt as jwt_utils

    import app.db as db_pkg

    calls = {"n": 0}

    def _flaky(_db):
        calls["n"] += 1
        return "secret" if calls["n"] > 1 else None

    monkeypatch = pytest.MonkeyPatch()
    try:
        monkeypatch.setattr(db_pkg, "get_jwt_secret_key", _flaky)
        monkeypatch.setattr(db_pkg, "GetDB", lambda: _Session(None))
        jwt_utils.get_secret_key.cache_clear()
        with pytest.raises(RuntimeError):
            jwt_utils.get_secret_key()
        assert jwt_utils.get_secret_key() == "secret"
    finally:
        monkeypatch.undo()
        jwt_utils.get_secret_key.cache_clear()


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
