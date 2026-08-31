"""Password hashing — deliberately dependency-free.

This module must stay a leaf: it is imported by ``app.models.admin`` (which
pulls in ``app.db``) *and* by ``app.persistence.migration``, which runs while
the app is still wiring itself up. Defining the context here breaks what would
otherwise be a circular import (admin → db → crud → admin).
"""
from __future__ import annotations

from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(plain: str) -> str:
    return pwd_context.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    if not hashed:
        return False
    try:
        return bool(pwd_context.verify(plain, hashed))
    except (ValueError, TypeError):  # malformed hash in a legacy row
        return False
