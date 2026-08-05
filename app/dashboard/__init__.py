import atexit
import logging
import os
import subprocess
from pathlib import Path

from app import app
from config import DEBUG, VITE_BASE_API, DASHBOARD_PATH
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

logger = logging.getLogger("uvicorn.error")

base_dir = Path(__file__).parent
build_dir = base_dir / 'build'
statics_dir = build_dir / 'statics'


def build():
    proc = subprocess.Popen(
        ['npm', 'run', 'build', '--',  '--outDir', build_dir, '--assetsDir', 'statics'],
        env={**os.environ, 'VITE_BASE_API': VITE_BASE_API},
        cwd=base_dir
    )
    proc.wait()
    with open(build_dir / 'index.html', 'r') as file:
        html = file.read()
    with open(build_dir / '404.html', 'w') as file:
        file.write(html)


def run_dev():
    proc = subprocess.Popen(
        ['npm', 'run', 'dev', '--', '--host', '0.0.0.0', '--clearScreen', 'false', '--base', os.path.join(DASHBOARD_PATH, '')],
        env={**os.environ, 'VITE_BASE_API': VITE_BASE_API},
        cwd=base_dir
    )

    atexit.register(proc.terminate)


def run_build():
    if not build_dir.is_dir():
        try:
            build()
        except (OSError, subprocess.SubprocessError) as exc:
            # Deployment robustness: a missing frontend bundle must never
            # prevent the panel API from booting (the Docker image ships the
            # bundle; source checkouts may not have node available).
            logger.warning(
                "dashboard bundle unavailable and could not be built (%s); "
                "the panel API stays up and %s returns 503 until assets exist.",
                exc, DASHBOARD_PATH)

    if build_dir.is_dir():
        app.mount(
            DASHBOARD_PATH,
            StaticFiles(directory=build_dir, html=True),
            name="dashboard"
        )
        app.mount(
            '/statics/',
            StaticFiles(directory=statics_dir, html=True),
            name="statics"
        )
        return

    dash_path = DASHBOARD_PATH.rstrip('/')

    @app.get(dash_path, include_in_schema=False)
    @app.get(dash_path + "/{full_path:path}", include_in_schema=False)
    def dashboard_unavailable(full_path: str = ""):
        return JSONResponse(
            status_code=503,
            content={"detail": "dashboard frontend bundle is not installed on "
                               "this deployment; the API and ops endpoints are "
                               "fully functional (image builds include the bundle)."},
        )


@app.on_event("startup")
def startup():
    if DEBUG:
        run_dev()
    else:
        run_build()
