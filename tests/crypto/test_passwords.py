"""scrypt password hasher tests.

Run: pytest tests/crypto/test_passwords.py  OR  python tests/crypto/test_passwords.py
"""
from __future__ import annotations

import sys
import traceback
import types as _types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
if "app" not in sys.modules:
    _pkg = _types.ModuleType("app")
    _pkg.__path__ = [str(ROOT / "app")]
    sys.modules["app"] = _pkg

from app.crypto.passwords import PasswordHasher, PasswordHashError  # noqa: E402


def test_hash_and_verify() -> None:
    hasher = PasswordHasher()
    serial = hasher.hash("Correct Horse Battery Staple")
    assert serial.startswith("$zg-scrypt$v1$")
    assert hasher.verify("Correct Horse Battery Staple", serial)
    assert not hasher.verify("wrong", serial)
    assert not hasher.needs_rehash(serial)


def test_hashes_are_salted() -> None:
    hasher = PasswordHasher()
    assert hasher.hash("pw") != hasher.hash("pw"), "salts must randomize hashes"


def test_unicode_passwords() -> None:
    hasher = PasswordHasher()
    serial = hasher.hash("پسورد-فارسی-۱۳")
    assert hasher.verify("پسورد-فارسی-۱۳", serial)
    assert not hasher.verify("پسورد-فارسی-۱۴", serial)


def test_tampered_hash_rejected() -> None:
    hasher = PasswordHasher()
    serial = hasher.hash("pw123")
    parts = serial.split("$")
    parts[-1] = ("A" + parts[-1][1:]) if not parts[-1].startswith("A") else ("B" + parts[-1][1:])
    assert not hasher.verify("pw123", "$".join(parts))


def test_garbage_inputs_never_raise_on_verify() -> None:
    hasher = PasswordHasher()
    for bad in ("", "garbage", "$zg-scrypt$v1$", "$zg-scrypt$v2$1$1$1$aa$bb",
                "$zg-scrypt$v1$16384$8$1$!!!$%%%", "$zg-scrypt$v1$abc$8$1$aa$bb",
                "$zg-scrypt$v1$3$8$1$aa$bb"):
        assert hasher.verify("pw", bad) is False
        # needs_rehash of garbage is True (it needs re-hashing, by definition)
        assert hasher.needs_rehash(bad) is True


def test_needs_rehash_for_weaker_params() -> None:
    strong = PasswordHasher(n=2**14)
    weak = PasswordHasher(n=2**14)
    old_serial = strong.hash("pw")
    upgraded = PasswordHasher(n=2**15)
    assert upgraded.verify("pw", old_serial), "verification must still honor stored params"
    assert upgraded.needs_rehash(old_serial)
    assert not weak.needs_rehash(old_serial)


def test_parameter_validation() -> None:
    for kwargs in ({"n": 100}, {"n": 2**30}, {"n": 2**14, "r": 0}, {"n": 2**14, "p": -1}):
        try:
            PasswordHasher(**kwargs)
            raise AssertionError(f"accepted bad params {kwargs}")
        except PasswordHashError:
            pass
    try:
        PasswordHasher().hash("")
        raise AssertionError("empty password hashed")
    except PasswordHashError:
        pass


if __name__ == "__main__":
    tests = [(k, v) for k, v in sorted(globals().items()) if k.startswith("test_")]
    failed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"PASS {name}")
        except Exception:  # noqa: BLE001
            failed += 1
            print(f"FAIL {name}")
            traceback.print_exc()
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    sys.exit(1 if failed else 0)
