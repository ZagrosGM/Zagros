"""Zagros panel — HTTP application entry point (lazy).

The FastAPI application is constructed on first attribute access
(:pep:`562`) so lightweight entry points — Alembic's env, the CLI, the
multicore subsystem, tests — can import subpackages (``app.cores``,
``app.persistence``, ``app.portal`` ...) without pulling the entire HTTP
stack (fastapi/apscheduler/xray singletons) into their interpreter.
"""
import asyncio
import logging

__version__ = "1.0.0-alpha.8.7"  # Zagros begins a new version line after the rebrand


_building = False


def _ensure_scheduler():
    """Return the process-wide APScheduler instance, creating it on demand.

    The scheduler is intentionally independent from the FastAPI app build:
    legacy modules (``app.utils.system``, ``app.jobs.*``) touch
    ``from app import scheduler`` at import time, and those imports can be
    reached from inside a partially-imported ``app.db.models``. If touching
    the scheduler built the whole app, job modules would then try to import
    model classes from the partially-initialised module and crash — the
    classic circular-import landmine. A bare ``BackgroundScheduler`` has no
    app-level dependencies, so constructing it is always safe.
    """
    if "scheduler" not in globals():
        from apscheduler.schedulers.background import BackgroundScheduler

        globals()["scheduler"] = BackgroundScheduler(
            {"apscheduler.job_defaults.max_instances": 20}, timezone="UTC"
        )
    return globals()["scheduler"]


def _build_app():
    global _building
    # Legacy sub-packages do `from app import app/scheduler` at their own
    # import time; they must see REAL attributes (PEP-562 __getattr__ is only
    # invoked for *missing* attributes), so construct + preseed first and
    # guard against re-entrant builds (circular legacy imports).
    if "app" in globals() and "scheduler" in globals():
        return globals()["app"], globals()["scheduler"]
    if _building:
        raise RuntimeError(
            "re-entrant Zagros app build aborted (circular legacy import); "
            "attributes app/scheduler are preseeded before sub-imports, "
            "so this should never happen — report it."
        )
    _building = True
    try:
        return _build_app_inner()
    finally:
        _building = False


def _build_app_inner():
    from fastapi import FastAPI, Request, status
    from fastapi.encoders import jsonable_encoder
    from fastapi.exceptions import RequestValidationError
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.middleware.trustedhost import TrustedHostMiddleware
    from fastapi.responses import JSONResponse
    from fastapi.routing import APIRoute

    from config import (
        ALLOWED_ORIGINS, DOCS, TRUSTED_HOSTS,
        ZAGROS_HSTS, ZAGROS_REDIRECT_HTTP_TO_HTTPS,
    )

    app = FastAPI(
        title="Zagros API",
        description="Zagros — Enterprise Multi-Core VPN Management Platform",
        version=__version__,
        docs_url="/docs" if DOCS else None,
        redoc_url="/redoc" if DOCS else None,
    )

    scheduler = _ensure_scheduler()  # single process-wide instance

    app.add_middleware(
        CORSMiddleware,
        allow_origins=ALLOWED_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    # Host-header allow-list stays opt-in: with an empty TRUSTED_HOSTS the
    # middleware is simply not installed (zero behavior change).
    if TRUSTED_HOSTS:
        app.add_middleware(TrustedHostMiddleware, allowed_hosts=TRUSTED_HOSTS)

    @app.middleware("http")
    async def panel_network_headers(request: Request, call_next):
        if ZAGROS_REDIRECT_HTTP_TO_HTTPS and request.url.scheme != "https":
            from fastapi.responses import RedirectResponse

            return RedirectResponse(str(request.url.replace(scheme="https")),
                                    status_code=308)
        response = await call_next(request)
        if ZAGROS_HSTS and request.url.scheme == "https":
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains")
        return response

    # Preseed BEFORE importing the legacy sub-packages (dashboard, jobs,
    # routers, telegram): they execute `from app import app` / `from app
    # import scheduler` at import time and must find real attributes,
    # otherwise a second nested _build_app() call would crash on partially
    # initialised modules (import cycle).
    globals()["app"] = app
    globals()["scheduler"] = scheduler

    from app import dashboard, jobs, routers, telegram  # noqa: F401
    from app.routers import api_router

    app.include_router(api_router)

    # ------------------------------------------------------------------ #
    # Zagros product layer: subscription portal, client (app) API,       #
    # Config Studio and the admin dashboard snapshot API.                #
    #                                                                    #
    # The runtime is optional-by-design: if the environment is not       #
    # configured yet (missing ZAGROS_SECRET_KEY, schema not migrated via #
    # `alembic upgrade head`), the panel still boots and every Zagros    #
    # endpoint answers an honest 503 instead of crashing the process.    #
    # ------------------------------------------------------------------ #
    try:
        from app.platform.runtime import PlatformRuntime
        from app.platform.routers import zagros_admin_router, zagros_router
        from app.platform import admin_api as _zagros_admin_api  # noqa: F401
        # (registers the unified-dashboard admin endpoints on the same router)

        zagros_runtime = None
        try:
            zagros_runtime = PlatformRuntime.from_env()
            zagros_runtime.verify_schema()
        except Exception as exc:  # noqa: BLE001 - degrade, never crash boot
            logging.getLogger("uvicorn.error").critical(
                "Zagros platform runtime disabled: %s "
                "(set ZAGROS_SECRET_KEY and run `alembic upgrade head`)", exc)
            zagros_runtime = None
        if zagros_runtime is not None:
            app.state.zagros = zagros_runtime
        app.include_router(zagros_router)
        app.include_router(zagros_admin_router)

        @app.on_event("startup")
        async def zagros_boot_cores():
            runtime = getattr(app.state, "zagros", None)
            if runtime is not None:
                await runtime.boot_cores()
                # Converge the optional dedicated subscription listener from
                # SQL desired state. It shares this ASGI app with lifespan off,
                # so schedulers/cores are never started twice.
                try:
                    portal_settings = await runtime.portal_settings.get_portal_settings()
                    await runtime.subscription_listener.apply(
                        portal_settings, runtime, app)
                except Exception as _exc:  # panel must stay reachable for repair
                    logging.getLogger("uvicorn.error").error(
                        "dedicated subscription listener failed: %s", _exc)
                # hand persisted usage baselines back to driver trackers so a
                # panel restart never re-reports whole counters (exactly-once)
                try:
                    from app.platform.usage_recorder import restore_baselines

                    await restore_baselines(runtime)
                except Exception as _exc:  # noqa: BLE001 - never block boot
                    logging.getLogger("uvicorn.error").warning(
                        "usage baseline restore failed: %s", _exc)

        @app.on_event("shutdown")
        async def zagros_stop_managed_cores():
            runtime = getattr(app.state, "zagros", None)
            if runtime is not None:
                # Drain every live cumulative/session counter before stopping
                # the processes/interfaces that own that generation. The
                # scheduler is paused first and the recorder's process lock
                # waits out an already-running tick.
                try:
                    scheduler.pause()
                    from app.platform.usage_recorder import flush_before_shutdown

                    await flush_before_shutdown(runtime)
                except Exception as _exc:  # noqa: BLE001 — continue teardown
                    logging.getLogger("uvicorn.error").warning(
                        "final usage flush before shutdown failed: %s", _exc)
                try:
                    await runtime.subscription_listener.stop()
                except Exception as _exc:  # noqa: BLE001
                    logging.getLogger("uvicorn.error").warning(
                        "subscription listener cleanup failed: %s", _exc)
                # Policy outbounds own additional TUN/WireGuard interfaces,
                # ip rules and nftables state. Tear those down before service
                # inbounds so a replacement image cannot inherit stale marks.
                try:
                    await asyncio.to_thread(runtime.policy_router.stop)
                except Exception as _exc:  # noqa: BLE001 — continue core cleanup
                    logging.getLogger("uvicorn.error").warning(
                        "policy routing cleanup failed: %s", _exc)
                # Host-network processes/interfaces outlive ordinary Python
                # object state. A graceful container replacement must tear
                # them down so the next image cannot inherit stale wg-quick
                # Address/NAT or listener processes.
                await runtime.core_manager.stop_all()
    except Exception as exc:  # noqa: BLE001 - import-level failure
        logging.getLogger("uvicorn.error").critical(
            "Zagros product layer unavailable: %s", exc)

    # NOTE: the Zagros ops UI and Config Studio were separate pages in
    # earlier alphas (/zagros/dashboard, /zagros/studio). As of 1.0.0-alpha.5
    # there is exactly ONE management UI: the unified dashboard SPA served
    # at /dashboard (Config Studio lives inside it as "Advanced Mode").

    for route in app.routes:
        if isinstance(route, APIRoute):
            route.operation_id = route.name

    @app.on_event("startup")
    def on_startup():
        # alpha.7.2: the legacy xray-only subscription endpoint (/<XRAY_SUBSCRIPTION_PATH>/<token>)
        # was REMOVED — the multi-core portal (/zagros/sub/<token>) is the
        # only subscription surface; no reserved-path guard is needed here.
        scheduler.start()

    @app.on_event("shutdown")
    def on_shutdown():
        scheduler.shutdown()

    @app.exception_handler(RequestValidationError)
    def validation_exception_handler(request: Request, exc: RequestValidationError):
        details = {}
        for error in exc.errors():
            details[error["loc"][-1]] = error.get("msg")
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content=jsonable_encoder({"detail": details}),
        )

    return app, scheduler


def __getattr__(name: str):
    if name == "logger":
        value = logging.getLogger("uvicorn.error")
        globals()["logger"] = value
        return value
    if name == "scheduler":
        # Independent of the app build on purpose (see _ensure_scheduler).
        return _ensure_scheduler()
    if name == "app":
        app_obj, _ = _build_app()
        globals()["app"] = app_obj
        return globals()[name]
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
