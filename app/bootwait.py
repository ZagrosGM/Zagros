"""Container boot: wait for the SQL server(s) before migrating and booting.

The image used to run ``alembic upgrade head; python main.py`` the instant
the container started. With a managed MySQL/MariaDB/PostgreSQL service that
is still initialising next to it, that meant on every fresh install:

* the migration died on *connection refused* (nothing was migrated),
* the panel then spent a full minute retrying the runtime build — first
  against a refused connection, then against an **empty schema**, which no
  amount of waiting creates (the installer only migrates once the panel is
  healthy, and the panel is not healthy while it waits: a dead lock that
  simply timed out),
* and the operator watched ``Waiting for the panel`` for well over a minute.

The image now runs ``python3 -m app.bootwait`` first. It blocks — bounded
by ``ZAGROS_DB_WAIT_SECONDS`` (default 180) — until every configured SQL
server accepts connections, so the migration that follows runs against a
live database and the panel boots with a complete schema on the first try.
Errors that time cannot fix (bad credentials, unknown database) end the wait
for that URL at once: the server *is* up, the problem is configuration, and
Alembic reports it far better than a timeout would.

The module is deliberately light (no ``app.platform`` import): it is a
one-shot pre-flight that runs before the heavy application import.
"""
from __future__ import annotations

import errno
import os
import socket
import sys
import time
from typing import Callable, Iterable, Iterator

DEFAULT_WAIT_SECONDS = 180
WAIT_SECONDS_ENV = "ZAGROS_DB_WAIT_SECONDS"
POLL_SECONDS = 1.0
PROGRESS_EVERY_SECONDS = 10.0
CONNECT_TIMEOUT_SECONDS = 5

#: Substrings of driver messages that mean "the server answered, and said no".
#: Waiting longer cannot change these; surface them immediately instead.
_NON_TRANSIENT_MARKERS = (
    "access denied",          # MySQL/MariaDB 1045
    "unknown database",       # MySQL/MariaDB 1049
    "authentication failed",  # PostgreSQL
    "does not exist",         # PostgreSQL unknown database / role
    "no such table",          # SQLite schema
    "unable to open database",  # SQLite file/path problem
    "permission denied",
)

_TRANSIENT_ERRNOS = frozenset({
    errno.ECONNREFUSED, errno.ECONNRESET, errno.ECONNABORTED,
    errno.EHOSTUNREACH, errno.ENETUNREACH, errno.ETIMEDOUT, errno.EPIPE,
})


def _chain(exc: BaseException | None) -> Iterator[BaseException]:
    seen: set[int] = set()
    while exc is not None and id(exc) not in seen:
        seen.add(id(exc))
        yield exc
        exc = exc.__cause__ or exc.__context__


def is_transient_db_error(exc: BaseException | None) -> bool:
    """True when *exc* means "the server is not accepting connections (yet)".

    Connection-level failures (refused, reset, timed out, "server is
    starting up", lost connection) are transient. A schema that is missing,
    a rejected password, an unknown database or a missing secret are not —
    retrying those only delays the honest error.
    """
    if exc is None:
        return False
    text = " ".join(str(item) for item in _chain(exc)).lower()
    if any(marker in text for marker in _NON_TRANSIENT_MARKERS):
        return False
    try:
        from sqlalchemy import exc as sa_exc
    except ImportError:  # pragma: no cover - sqlalchemy is a hard dependency
        sa_exc = None
    for item in _chain(exc):
        if sa_exc is not None:
            if isinstance(item, (sa_exc.OperationalError, sa_exc.InterfaceError)):
                return True
            if isinstance(item, sa_exc.DBAPIError) and item.connection_invalidated:
                return True
        if isinstance(item, (ConnectionError, socket.timeout, TimeoutError)):
            return True
        if isinstance(item, OSError) and item.errno in _TRANSIENT_ERRNOS:
            return True
    return False


def is_server_url(url: str | None) -> bool:
    """SQLite is a file — there is never anything to wait for."""
    return bool(url) and not str(url).strip().lower().startswith("sqlite")


def redact(url: str) -> str:
    try:
        from sqlalchemy.engine import make_url

        return make_url(url).render_as_string(hide_password=True)
    except Exception:  # noqa: BLE001 - never leak a password through a log line
        return "<database url>"


def brief(exc: BaseException) -> str:
    """First line of the driver message (SQLAlchemy appends a help URL)."""
    return str(exc).strip().splitlines()[0] if str(exc).strip() else exc.__class__.__name__


def probe(url: str) -> BaseException | None:
    """One connection attempt + ``SELECT 1``; returns the exception (None = ok)."""
    from sqlalchemy import create_engine, text
    from sqlalchemy.pool import NullPool

    connect_args = {}
    if is_server_url(url):
        connect_args["connect_timeout"] = CONNECT_TIMEOUT_SECONDS
    try:
        engine = create_engine(url, poolclass=NullPool, connect_args=connect_args)
    except Exception as exc:  # noqa: BLE001 - malformed URL / missing driver
        return exc
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return None
    except Exception as exc:  # noqa: BLE001 - classified by the caller
        return exc
    finally:
        engine.dispose()


def wait_for_databases(
    urls: Iterable[str],
    *,
    timeout: float,
    poll: float = POLL_SECONDS,
    probe_fn: Callable[[str], BaseException | None] = probe,
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
    log: Callable[[str], None] = lambda _msg: None,
) -> dict[str, bool]:
    """Block until each SQL server in *urls* accepts a connection.

    Returns ``{url: reachable}``. Duplicate URLs are probed once; SQLite URLs
    are reported reachable without probing. A non-transient answer ends the
    wait for that URL immediately (reported as ``False``); the deadline ends
    it for whatever is still pending.
    """
    ordered = list(dict.fromkeys(u for u in urls if u))
    result: dict[str, bool] = {u: True for u in ordered if not is_server_url(u)}
    pending = [u for u in ordered if is_server_url(u)]
    if not pending:
        return result
    start = clock()
    deadline = start + max(float(timeout), 0.0)
    last_report: dict[str, float] = {}
    while pending:
        for url in list(pending):
            exc = probe_fn(url)
            now = clock()
            if exc is None:
                log(f"database reachable: {redact(url)} (after {now - start:.0f}s)")
                result[url] = True
                pending.remove(url)
                continue
            if not is_transient_db_error(exc):
                log(f"database {redact(url)} answered with an error that waiting "
                    f"cannot fix — not waiting for it: {brief(exc)}")
                result[url] = False
                pending.remove(url)
                continue
            if url not in last_report or now - last_report[url] >= PROGRESS_EVERY_SECONDS:
                log(f"waiting for database {redact(url)} "
                    f"({now - start:.0f}s of {timeout:.0f}s): {brief(exc)}")
                last_report[url] = now
        if not pending:
            break
        if clock() >= deadline:
            for url in pending:
                log(f"database {redact(url)} still unreachable after {timeout:.0f}s "
                    "— continuing so the panel can boot degraded and recover later")
                result[url] = False
            break
        sleep(poll)
    return result


def build_with_retries(
    builder: Callable[[], tuple[object | None, BaseException | None]],
    *,
    attempts: int = 30,
    delay: float = 2.0,
    sleep: Callable[[float], None] = time.sleep,
    log: Callable[..., None] | None = None,
) -> tuple[object | None, BaseException | None]:
    """Call *builder* (→ ``(runtime, error)``) until it succeeds or gives up.

    Only transient database errors are retried. A missing schema or secret is
    not something time fixes — the request-path recovery owns those — so the
    panel no longer sits through the whole retry budget before booting.
    """
    runtime, error = builder()
    for attempt in range(1, max(int(attempts), 1)):
        if runtime is not None or not is_transient_db_error(error):
            break
        if attempt == 1 and log is not None:
            log("Zagros platform runtime not ready yet (%s) - retrying", error)
        sleep(delay)
        runtime, error = builder()
    return runtime, error


def configured_database_urls(environ: dict | None = None) -> list[str]:
    """The platform URL and the legacy URL, resolved exactly like the app.

    Mirrors ``app/persistence/alembic/env.py`` (platform) and ``config.py``
    (legacy). The mounted ``.env`` is merged first because compose only
    mounts the file — nothing is injected into the environment.
    """
    if environ is None:
        from app.env_loader import load_zagros_env

        load_zagros_env()
        environ = os.environ
    platform = (environ.get("ZAGROS_DATABASE_URL")
                or environ.get("SQLALCHEMY_DATABASE_URL")
                or "sqlite:///zagros.db")
    legacy = environ.get("SQLALCHEMY_DATABASE_URL") or "sqlite:///db.sqlite3"
    return list(dict.fromkeys([platform, legacy]))


def wait_seconds_from_env(environ: dict | None = None) -> float:
    raw = (environ if environ is not None else os.environ).get(WAIT_SECONDS_ENV, "")
    try:
        value = float(str(raw).strip())
    except (TypeError, ValueError):
        return float(DEFAULT_WAIT_SECONDS)
    return max(value, 0.0)


def _stderr(message: str) -> None:
    sys.stderr.write(f"[zagros boot] {message}\n")
    sys.stderr.flush()


def main(argv: list[str] | None = None) -> int:
    del argv  # no options — everything comes from the .env contract
    urls = configured_database_urls()
    if not any(is_server_url(u) for u in urls):
        return 0
    timeout = wait_seconds_from_env()
    result = wait_for_databases(urls, timeout=timeout, log=_stderr)
    return 0 if all(result.values()) else 1


if __name__ == "__main__":  # pragma: no cover - exercised by the image CMD
    sys.exit(main(sys.argv[1:]))
