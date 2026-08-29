import time
import traceback

from app import app, logger, scheduler, xray
from config import JOB_CORE_HEALTH_CHECK_INTERVAL


def _schema_has_users() -> bool:
    """True when the alembic schema exists far enough to touch `users`.

    On a fresh install the panel must still boot (Zagros product-layer
    contract); merging DB users into the xray config on an unmigrated
    schema raises OperationalError and kills the whole startup sequence.
    """
    try:
        from sqlalchemy import inspect

        from app.db.base import engine

        return inspect(engine).has_table("users")
    except Exception:  # noqa: BLE001 - unreachable DB = not migratable yet
        return False


def _startup_config():
    """include_db_users() when the schema is ready, the plain file config
    otherwise (loudly logged, never a startup crash)."""
    if _schema_has_users():
        return xray.config.include_db_users()
    logger.critical(
        "Database schema not migrated (no 'users' table) — starting Xray with "
        "the file config only; run `alembic upgrade head` and restart the "
        "panel so DB users are provisioned."
    )
    return xray.config


def core_health_check():
    config = None

    # main core
    if not xray.core.started:
        if not config:
            config = _startup_config()
        xray.core.restart(config)


@app.on_event("startup")
def start_core():
    logger.info("Generating Xray core config")

    start_time = time.time()
    config = _startup_config()
    logger.info(f"Xray core config generated in {(time.time() - start_time):.2f} seconds")

    # main core
    logger.info("Starting main Xray core")
    try:
        xray.core.start(config)
    except Exception:
        traceback.print_exc()

    scheduler.add_job(core_health_check, 'interval',
                      seconds=JOB_CORE_HEALTH_CHECK_INTERVAL,
                      coalesce=True, max_instances=1)


@app.on_event("shutdown")
def app_shutdown():
    logger.info("Stopping main Xray core")
    xray.core.stop()
