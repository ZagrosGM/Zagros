"""Release dependency constraints that close the alpha.8.3 pip audit."""
from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_python_security_floors_and_unused_jose_removal() -> None:
    lines = {
        line.split("#", 1)[0].strip().lower()
        for line in (ROOT / "requirements.txt").read_text().splitlines()
        if line.split("#", 1)[0].strip()
    }
    assert "aiohttp>=3.14.3,<4" in lines
    assert "pillow>=12.3.0,<13" in lines
    assert "jose" not in lines
    assert "python-jose" not in lines

    # Zagros uses PyJWT directly. The removed jose/python-jose pair was an
    # unused upstream remnant and pulled the no-fixed-version `ecdsa` advisory.
    product_imports = "\n".join(
        path.read_text(errors="ignore")
        for path in (ROOT / "app").rglob("*.py")
    )
    assert "import jose" not in product_imports
    assert "from jose" not in product_imports
    assert "import jwt" in product_imports
