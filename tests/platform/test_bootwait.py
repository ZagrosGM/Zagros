"""Container boot must wait for the SQL server(s) and retry only what time fixes.

Field report (v1.0.1): ``zagros install --database mysql|mariadb`` sat at
"Waiting for the panel" for 60-90 s on every fresh install. The image ran
``alembic upgrade head`` the instant the container started, lost the race
against the initialising database (connection refused → nothing migrated),
and the panel then burned its whole 30 × 2 s retry budget on "schema is
incomplete" — an error no amount of waiting can fix — before it would bind.

These tests pin the three contracts that close the gap:

* ``app.bootwait.wait_for_databases`` blocks (bounded) on transient
  connection errors and gives up at once on non-transient answers;
* ``app.bootwait.build_with_retries`` retries the runtime build only on
  transient database errors;
* the image CMD runs the wait before Alembic and the server.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest
import sqlalchemy.exc as sa_exc

from app import bootwait

ROOT = Path(__file__).resolve().parents[2]


# ----------------------------------------------------------------- helpers --

def _operational(message: str, cause: BaseException | None = None) -> sa_exc.OperationalError:
    exc = sa_exc.OperationalError("SELECT 1", {}, cause or Exception(message))
    return exc


class _Clock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += seconds


# --------------------------------------------------- error classification --

@pytest.mark.parametrize("exc", [
    _operational("", ConnectionRefusedError(111, "Connection refused")),
    _operational("(2003, \"Can't connect to MySQL server on '127.0.0.1' ([Errno 111] Connection refused)\")"),
    _operational("(2013, 'Lost connection to MySQL server during query')"),
    _operational("connection failed: server closed the connection unexpectedly"),
    _operational("FATAL:  the database system is starting up"),
    ConnectionResetError(104, "Connection reset by peer"),
    TimeoutError("timed out"),
    OSError(113, "No route to host"),
])
def test_transient_errors_are_retried(exc):
    assert bootwait.is_transient_db_error(exc) is True


@pytest.mark.parametrize("exc", [
    _operational("(1045, \"Access denied for user 'zagros'@'127.0.0.1' (using password: YES)\")"),
    _operational("(1044, \"Access denied for user 'zagros'@'%' to database 'nope'\")"),
    _operational("(1049, \"Unknown database 'nope'\")"),
    _operational("FATAL:  password authentication failed for user \"zagros\""),
    _operational("FATAL:  database \"nope\" does not exist"),
    sa_exc.ProgrammingError("SELECT", {}, Exception("(1146, \"Table 'zagros.users' doesn't exist\")")),
    RuntimeError("Zagros schema is incomplete (missing tables: admins, users)"),
    RuntimeError("ZAGROS_SECRET_KEY is missing or shorter than 16 characters"),
    ValueError("plain bug"),
    None,
])
def test_non_transient_errors_are_not_retried(exc):
    assert bootwait.is_transient_db_error(exc) is False


def test_transient_cause_is_found_through_the_exception_chain():
    inner = ConnectionRefusedError(111, "Connection refused")
    try:
        try:
            raise inner
        except ConnectionRefusedError as first:
            raise RuntimeError("wrapped") from first
    except RuntimeError as outer:
        assert bootwait.is_transient_db_error(outer) is True


# ------------------------------------------------------------ wait loop ----

def test_sqlite_urls_never_wait():
    calls: list[str] = []
    result = bootwait.wait_for_databases(
        ["sqlite:////var/lib/zagros/zagros.db", "sqlite:///legacy.db"],
        timeout=30, probe_fn=lambda url: calls.append(url) or None)
    assert result == {"sqlite:////var/lib/zagros/zagros.db": True, "sqlite:///legacy.db": True}
    assert calls == []


def test_waits_through_refused_connections_then_succeeds():
    clock = _Clock()
    attempts = {"n": 0}

    def probe(url: str):
        attempts["n"] += 1
        return None if attempts["n"] >= 4 else _operational(
            "", ConnectionRefusedError(111, "Connection refused"))

    logs: list[str] = []
    url = "mysql+pymysql://zagros:secret@127.0.0.1:3306/zagros"
    result = bootwait.wait_for_databases(
        [url], timeout=60, poll=1.0, probe_fn=probe, clock=clock,
        sleep=clock.sleep, log=logs.append)
    assert result == {url: True}
    assert attempts["n"] == 4
    assert clock.now == pytest.approx(3.0)
    assert any("database reachable" in line for line in logs)
    # the password never reaches the log
    assert all("secret" not in line for line in logs)
    assert any("zagros:***@127.0.0.1" in line for line in logs)


def test_duplicate_urls_are_probed_once_per_round():
    calls: list[str] = []
    url = "mysql+pymysql://u:p@127.0.0.1:3306/zagros"
    result = bootwait.wait_for_databases(
        [url, url], timeout=10, probe_fn=lambda u: calls.append(u) or None)
    assert result == {url: True}
    assert calls == [url]


def test_gives_up_immediately_on_a_non_transient_answer():
    clock = _Clock()
    calls: list[str] = []
    url = "mysql+pymysql://zagros:bad@127.0.0.1:3306/zagros"
    logs: list[str] = []
    result = bootwait.wait_for_databases(
        [url], timeout=120, probe_fn=lambda u: calls.append(u) or _operational(
            "(1045, \"Access denied for user 'zagros'@'127.0.0.1'\")"),
        clock=clock, sleep=clock.sleep, log=logs.append)
    assert result == {url: False}
    assert len(calls) == 1
    assert clock.now == 0.0
    assert any("waiting cannot fix" in line for line in logs)


def test_deadline_ends_the_wait_and_reports_unreachable():
    clock = _Clock()
    url = "postgresql+psycopg://zagros:pw@127.0.0.1:5432/zagros"
    logs: list[str] = []
    result = bootwait.wait_for_databases(
        [url], timeout=5, poll=1.0,
        probe_fn=lambda u: _operational("", ConnectionRefusedError(111, "refused")),
        clock=clock, sleep=clock.sleep, log=logs.append)
    assert result == {url: False}
    assert clock.now == pytest.approx(5.0)
    assert any("still unreachable after 5s" in line for line in logs)


def test_progress_is_logged_every_ten_seconds_not_every_poll():
    clock = _Clock()
    url = "mysql+pymysql://u:p@127.0.0.1:3306/zagros"
    logs: list[str] = []
    bootwait.wait_for_databases(
        [url], timeout=30, poll=1.0,
        probe_fn=lambda u: _operational("", ConnectionRefusedError(111, "refused")),
        clock=clock, sleep=clock.sleep, log=logs.append)
    waiting = [line for line in logs if line.startswith("waiting for database")]
    # one line per ten seconds (t=0, 10, 20 and the final probe at 30) —
    # not one per one-second poll
    assert 3 <= len(waiting) <= 4
    assert len(logs) < 10


def test_independent_urls_finish_independently():
    clock = _Clock()
    ok_url = "mysql+pymysql://u:p@127.0.0.1:3306/zagros"
    bad_url = "mysql+pymysql://u:p@127.0.0.1:3306/nope"

    def probe(url: str):
        if url == ok_url:
            return None
        return _operational("(1049, \"Unknown database 'nope'\")")

    result = bootwait.wait_for_databases(
        [ok_url, bad_url], timeout=30, probe_fn=probe, clock=clock, sleep=clock.sleep)
    assert result == {ok_url: True, bad_url: False}


# ------------------------------------------------- runtime build retries ---

def test_build_with_retries_retries_only_transient_errors():
    slept: list[float] = []
    calls = {"n": 0}

    def builder():
        calls["n"] += 1
        if calls["n"] < 3:
            return None, _operational("", ConnectionRefusedError(111, "refused"))
        return object(), None

    runtime, error = bootwait.build_with_retries(
        builder, attempts=30, delay=2.0, sleep=slept.append)
    assert runtime is not None and error is None
    assert calls["n"] == 3
    assert slept == [2.0, 2.0]


def test_build_with_retries_does_not_wait_on_an_incomplete_schema():
    slept: list[float] = []
    calls = {"n": 0}

    def builder():
        calls["n"] += 1
        return None, RuntimeError("Zagros schema is incomplete (missing tables: admins)")

    runtime, error = bootwait.build_with_retries(
        builder, attempts=30, delay=2.0, sleep=slept.append)
    assert runtime is None
    assert "schema is incomplete" in str(error)
    assert calls["n"] == 1
    assert slept == []


def test_build_with_retries_does_not_wait_on_a_missing_secret():
    slept: list[float] = []
    runtime, error = bootwait.build_with_retries(
        lambda: (None, RuntimeError("ZAGROS_SECRET_KEY is missing")),
        attempts=30, delay=2.0, sleep=slept.append)
    assert runtime is None and slept == []


def test_build_with_retries_respects_the_attempt_budget():
    slept: list[float] = []
    calls = {"n": 0}

    def builder():
        calls["n"] += 1
        return None, _operational("", ConnectionRefusedError(111, "refused"))

    runtime, _error = bootwait.build_with_retries(
        builder, attempts=5, delay=1.0, sleep=slept.append)
    assert runtime is None
    assert calls["n"] == 5
    assert slept == [1.0] * 4


def test_build_with_retries_logs_once():
    logged: list[tuple] = []
    calls = {"n": 0}

    def builder():
        calls["n"] += 1
        if calls["n"] < 4:
            return None, _operational("", ConnectionRefusedError(111, "refused"))
        return object(), None

    bootwait.build_with_retries(builder, attempts=10, delay=0.0,
                                sleep=lambda _s: None, log=lambda *a: logged.append(a))
    assert len(logged) == 1
    assert "not ready yet" in logged[0][0]


# --------------------------------------------------- env / url resolution --

def test_configured_urls_follow_the_env_contract():
    env = {
        "ZAGROS_DATABASE_URL": "mysql+pymysql://z:p@127.0.0.1:3306/zagros",
        "SQLALCHEMY_DATABASE_URL": "mysql+pymysql://z:p@127.0.0.1:3306/zagros_legacy",
    }
    assert bootwait.configured_database_urls(env) == [
        "mysql+pymysql://z:p@127.0.0.1:3306/zagros",
        "mysql+pymysql://z:p@127.0.0.1:3306/zagros_legacy",
    ]
    # legacy-only deployments: the platform URL falls back to the legacy one
    env = {"SQLALCHEMY_DATABASE_URL": "postgresql+psycopg://z:p@127.0.0.1:5432/legacy"}
    assert bootwait.configured_database_urls(env) == [
        "postgresql+psycopg://z:p@127.0.0.1:5432/legacy"]
    # nothing configured → the sqlite defaults of config.py / alembic env
    assert bootwait.configured_database_urls({}) == ["sqlite:///zagros.db", "sqlite:///db.sqlite3"]


@pytest.mark.parametrize("raw, expected", [
    ("", 180.0), ("abc", 180.0), ("45", 45.0), ("0", 0.0), ("-5", 0.0), (" 30 ", 30.0),
])
def test_wait_seconds_from_env(raw, expected):
    assert bootwait.wait_seconds_from_env({"ZAGROS_DB_WAIT_SECONDS": raw}) == expected


def test_main_is_a_noop_for_sqlite(monkeypatch):
    monkeypatch.setattr(bootwait, "configured_database_urls",
                        lambda: ["sqlite:///a.db", "sqlite:///b.db"])
    monkeypatch.setattr(bootwait, "wait_for_databases",
                        lambda *a, **k: pytest.fail("must not probe sqlite"))
    assert bootwait.main([]) == 0


def test_main_exit_code_reflects_reachability(monkeypatch):
    url = "mysql+pymysql://z:p@127.0.0.1:3306/zagros"
    monkeypatch.setattr(bootwait, "configured_database_urls", lambda: [url])
    monkeypatch.setattr(bootwait, "wait_seconds_from_env", lambda: 1.0)
    monkeypatch.setattr(bootwait, "wait_for_databases", lambda *a, **k: {url: True})
    assert bootwait.main([]) == 0
    monkeypatch.setattr(bootwait, "wait_for_databases", lambda *a, **k: {url: False})
    assert bootwait.main([]) == 1


def test_redact_hides_the_password():
    assert "hunter2" not in bootwait.redact("mysql+pymysql://z:hunter2@127.0.0.1:3306/zagros")
    assert bootwait.redact("not a url at all ://") in ("<database url>", "not a url at all ://")


# ------------------------------------------------------- image contract ----

def test_image_cmd_waits_for_the_database_before_migrating():
    dockerfile = (ROOT / "Dockerfile").read_text()
    cmd = re.search(r'^CMD \["bash", "-c", "(.+)"\]\s*$', dockerfile, re.M)
    assert cmd, "Dockerfile CMD not found"
    line = cmd.group(1)
    # f-instlock-1 (v1.1.1): the boot-time dbmerge+alembic section holds the
    # same in-container flock the management CLI's exec migrations take —
    # unsynchronized, a fresh install raced (observed: the CLI's 0004
    # inspected the legacy schema right after the boot dbmerge dropped it).
    assert "exec 9>/.zagros-migrate.lock; flock 9;" in line, (
        "boot migration must run under the shared install lock")
    # f-dbmerge: the one-time legacy→main merge runs after bootwait and
    # before the migrations (idempotent; marker-driven); serving is last.
    assert line.index("python3 -m app.bootwait;") < line.index("app.dbmerge") \
        < line.index("alembic upgrade head") < line.rindex("python main.py"), (
        "boot order must be bootwait → dbmerge → alembic → main")


def test_app_boot_uses_the_transient_only_retry_policy():
    source = (ROOT / "app" / "__init__.py").read_text()
    assert "build_with_retries(" in source
    assert "for attempt in range(30)" not in source
