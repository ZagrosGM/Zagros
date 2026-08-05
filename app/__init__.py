"""Zagros panel — HTTP application entry point (lazy).

The FastAPI application is constructed on first attribute access
(:pep:`562`) so lightweight entry points — Alembic's env, the CLI, the
multicore subsystem, tests — can import subpackages (``app.cores``,
``app.persistence``, ``app.portal`` ...) without pulling the entire HTTP
stack (fastapi/apscheduler/xray singletons) into their interpreter.
"""
import logging

__version__ = "1.0.0-alpha.3"  # Zagros begins a new version line after the rebrand


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
    from fastapi.responses import JSONResponse
    from fastapi.routing import APIRoute

    from config import ALLOWED_ORIGINS, DOCS, XRAY_SUBSCRIPTION_PATH

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
    except Exception as exc:  # noqa: BLE001 - import-level failure
        logging.getLogger("uvicorn.error").critical(
            "Zagros product layer unavailable: %s", exc)

    # Brand-new Zagros dashboard + Config Studio (self-contained UIs).
    @app.get("/zagros/dashboard", include_in_schema=False)
    def zagros_dashboard_page():
        return _serve_ui("dashboard.html")

    @app.get("/zagros/studio", include_in_schema=False)
    def zagros_studio_page():
        return _serve_ui("studio.html")

    def _serve_ui(name: str):
        from pathlib import Path

        from fastapi.responses import FileResponse, PlainTextResponse

        page = Path(__file__).resolve().parent.parent / "ui" / name
        if page.is_file():
            return FileResponse(page, media_type="text/html")
        return PlainTextResponse(
            f"Zagros UI asset (ui/{name}) is missing.", status_code=404)

    for route in app.routes:
        if isinstance(route, APIRoute):
            route.operation_id = route.name

    @app.on_event("startup")
    def on_startup():
        # Newer Starlette wraps included routers in _IncludedRouter objects
        # (no .path). Walk the route tree defensively instead of assuming
        # every entry is a plain route.
        def _all_paths(routes):
            for route in routes:
                pth = getattr(route, "path", None)
                if pth:
                    yield pth
                nested = getattr(route, "routes", None)
                if nested:
                    yield from _all_paths(nested)

        paths = [f"{p}/" for p in _all_paths(app.routes)]
        paths.append("/api/")
        if f"/{XRAY_SUBSCRIPTION_PATH}/" in paths:
            raise ValueError(
                f"you can't use /{XRAY_SUBSCRIPTION_PATH}/ as subscription path, "
                f"it is reserved for {app.title}"
            )
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
