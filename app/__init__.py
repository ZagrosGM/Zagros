"""Zagros panel — HTTP application entry point (lazy).

The FastAPI application is constructed on first attribute access
(:pep:`562`) so lightweight entry points — Alembic's env, the CLI, the
multicore subsystem, tests — can import subpackages (``app.cores``,
``app.persistence``, ``app.portal`` ...) without pulling the entire HTTP
stack (fastapi/apscheduler/xray singletons) into their interpreter.
"""
import logging

__version__ = "1.0.0-alpha.2"  # Zagros begins a new version line after the rebrand


def _build_app():
    from apscheduler.schedulers.background import BackgroundScheduler
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

    scheduler = BackgroundScheduler(
        {"apscheduler.job_defaults.max_instances": 20}, timezone="UTC"
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=ALLOWED_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

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
        paths = [f"{r.path}/" for r in app.routes]
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
    if name in ("app", "scheduler"):
        app_obj, scheduler_obj = _build_app()
        globals()["app"] = app_obj
        globals()["scheduler"] = scheduler_obj
        return globals()[name]
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
