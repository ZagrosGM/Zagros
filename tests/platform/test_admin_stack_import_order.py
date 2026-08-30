"""Admin endpoints must not depend on which module python imported first.

``app.models.admin`` and ``app.db`` import each other, so the admin model is
only importable once the DB package has been initialised. ``routers.py`` used
to try the model import and swallow whatever came out of it — which meant a
circular ImportError bound every admin endpoint to a 503 dependency, with no
log line and no failing test. Only the import order decided.

The check has to run in a FRESH interpreter: import state is process-wide, so
in-process assertions would pass or fail depending on what ran before them.

Run: pytest tests/platform/test_admin_stack_import_order.py -q
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

PROBE = """
import sys
sys.path.insert(0, {root!r})
import app.platform.{first}
from app.platform import routers
name = routers._SUDO_DEPS[0].dependency.__name__
print(name)
"""

_FALLBACK = "_no_admin_stack"


def _dependency_name(first: str) -> str:
    result = subprocess.run(
        [sys.executable, "-c", PROBE.format(root=str(ROOT), first=first)],
        capture_output=True, text=True, timeout=180, cwd=str(ROOT))
    assert result.returncode == 0, (
        f"importing app.platform.{first} first crashed:\n{result.stderr[-1500:]}")
    return result.stdout.strip().splitlines()[-1].strip()


def test_admin_api_imported_first_still_gets_the_real_auth_stack():
    """The regression: this used to resolve to the 503 fallback."""
    assert _dependency_name("admin_api") != _FALLBACK
    assert _dependency_name("admin_api") == "check_sudo_admin"


def test_routers_imported_first_still_gets_the_real_auth_stack():
    assert _dependency_name("routers") == "check_sudo_admin"


def test_every_order_agrees():
    """Whichever platform module leads, one dependency comes out — never the
    fallback, and never a silent difference between them."""
    names = {_dependency_name(mod) for mod in ("admin_api", "routers", "certificates")}
    assert names == {"check_sudo_admin"}


if __name__ == "__main__":
    sys.exit(subprocess.run(
        [sys.executable, "-m", "pytest", __file__, "-q"]).returncode)
