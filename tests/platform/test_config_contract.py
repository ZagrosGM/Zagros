"""Contract tests for config.py + the .env integration.

Runs ``import config`` in a REAL subprocess (fresh interpreter, like the
panel process itself) against a temporary .env file pointed to by
ZAGROS_ENV_FILE — verifying canonical/legacy aliases, DOMAIN derivation and
the file-over-defaults precedence exactly as operators experience it.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

_PROBE = """
import json, config
print(json.dumps({
    "DOMAIN": config.DOMAIN,
    "PANEL_BASE_URL": config.PANEL_BASE_URL,
    "APP_BASE_URL": config.APP_BASE_URL,
    "SUBSCRIPTION_URL_PREFIX": config.SUBSCRIPTION_URL_PREFIX,
    "SUBSCRIPTION_PATH": config.SUBSCRIPTION_PATH,
    "XRAY_SUBSCRIPTION_URL_PREFIX": config.XRAY_SUBSCRIPTION_URL_PREFIX,
    "XRAY_SUBSCRIPTION_PATH": config.XRAY_SUBSCRIPTION_PATH,
    "SUBSCRIPTION_TEMPLATE": config.SUBSCRIPTION_TEMPLATE,
    "UVICORN_HOST": config.UVICORN_HOST,
    "UVICORN_PORT": config.UVICORN_PORT,
    "TLS_MODE": config.TLS_MODE,
    "TRUSTED_HOSTS": config.TRUSTED_HOSTS,
    "ALLOWED_ORIGINS": config.ALLOWED_ORIGINS,
    "XRAY_JSON": config.XRAY_JSON,
    "XRAY_EXECUTABLE_PATH": config.XRAY_EXECUTABLE_PATH,
    "XRAY_ASSETS_PATH": config.XRAY_ASSETS_PATH,
}))
"""


def _read_config(tmp_path: Path, env_text: str = "",
                 extra_env: dict[str, str] | None = None) -> dict:
    env_file = tmp_path / ".env"
    env_file.write_text(env_text, encoding="utf-8")
    env = os.environ.copy()
    # Isolate from the surrounding test session entirely.
    for key in list(env):
        if key.startswith(("ZAGROS_", "UVICORN_", "SUBSCRIPTION_", "XRAY_",
                           "DOMAIN", "PANEL_BASE_URL", "APP_BASE_URL",
                           "TLS_MODE", "TRUSTED_HOSTS", "ALLOWED_ORIGINS")):
            env.pop(key)
    env[sys.intern("ZAGROS_ENV_FILE")] = str(env_file)
    env["PYTHONPATH"] = str(ROOT)
    if extra_env:
        env.update(extra_env)
    out = subprocess.run(
        [sys.executable, "-c", _PROBE],
        env=env, cwd=tmp_path,  # CWD deliberately NOT the repo root
        capture_output=True, text=True, timeout=60,
    )
    assert out.returncode == 0, f"config import failed:\n{out.stderr}"
    return json.loads(out.stdout.strip().splitlines()[-1])


def test_domain_derives_panel_app_and_subscription_urls(tmp_path):
    cfg = _read_config(tmp_path, 'DOMAIN = "panel.example.com"\n')
    assert cfg["DOMAIN"] == "panel.example.com"
    assert cfg["PANEL_BASE_URL"] == "https://panel.example.com"
    assert cfg["APP_BASE_URL"] == "https://panel.example.com"
    # subscription links become absolute automatically (better than Marzban)
    assert cfg["XRAY_SUBSCRIPTION_URL_PREFIX"] == "https://panel.example.com"
    assert cfg["SUBSCRIPTION_PATH"] == "sub"


def test_explicit_prefix_wins_over_domain_derivation(tmp_path):
    cfg = _read_config(
        tmp_path,
        'DOMAIN = "panel.example.com"\n'
        'SUBSCRIPTION_URL_PREFIX = "https://cdn.example.com"\n',
    )
    assert cfg["SUBSCRIPTION_URL_PREFIX"] == "https://cdn.example.com"
    assert cfg["XRAY_SUBSCRIPTION_URL_PREFIX"] == "https://cdn.example.com"


def test_legacy_xray_names_still_work(tmp_path):
    cfg = _read_config(
        tmp_path,
        'XRAY_SUBSCRIPTION_URL_PREFIX = "https://legacy.example.com"\n'
        'XRAY_SUBSCRIPTION_PATH = "oldsub"\n',
    )
    assert cfg["SUBSCRIPTION_URL_PREFIX"] == "https://legacy.example.com"
    assert cfg["XRAY_SUBSCRIPTION_URL_PREFIX"] == "https://legacy.example.com"
    assert cfg["SUBSCRIPTION_PATH"] == "oldsub"
    assert cfg["XRAY_SUBSCRIPTION_PATH"] == "oldsub"


def test_canonical_wins_when_both_names_set(tmp_path):
    cfg = _read_config(
        tmp_path,
        'SUBSCRIPTION_PATH = "new"\nXRAY_SUBSCRIPTION_PATH = "old"\n',
    )
    assert cfg["SUBSCRIPTION_PATH"] == "new"
    assert cfg["XRAY_SUBSCRIPTION_PATH"] == "new"


def test_env_file_values_apply_and_real_env_wins(tmp_path):
    cfg = _read_config(
        tmp_path,
        'UVICORN_HOST = "10.20.30.40"\nUVICORN_PORT = 9000\n'
        'TLS_MODE = "off"\nTRUSTED_HOSTS = "a.example.com, b.example.com"\n',
        extra_env={"UVICORN_PORT": "1234"},  # real env beats the file
    )
    assert cfg["UVICORN_HOST"] == "10.20.30.40"
    assert cfg["UVICORN_PORT"] == 1234
    assert cfg["TLS_MODE"] == "off"
    assert cfg["TRUSTED_HOSTS"] == ["a.example.com", "b.example.com"]


def test_defaults_without_any_file_settings(tmp_path):
    cfg = _read_config(tmp_path, "")
    assert cfg["UVICORN_HOST"] == "0.0.0.0"
    assert cfg["UVICORN_PORT"] == 8000
    assert cfg["TLS_MODE"] == "auto"
    assert cfg["XRAY_JSON"] == "/var/lib/zagros/cores/xray/xray_config.json"
    assert cfg["XRAY_EXECUTABLE_PATH"] == "/var/lib/zagros/cores/xray/bin/xray"
    assert cfg["XRAY_ASSETS_PATH"] == "/var/lib/zagros/cores/xray/assets"
    assert cfg["PANEL_BASE_URL"] == ""
    assert cfg["TRUSTED_HOSTS"] == []
    assert cfg["ALLOWED_ORIGINS"] == []
