"""Run with: python -m app.node_agent (TLS is mandatory)."""
from __future__ import annotations

import os
from pathlib import Path

import uvicorn


def main() -> None:
    host = os.environ.get("ZAGROS_NODE_HOST", "0.0.0.0")
    port = int(os.environ.get("ZAGROS_NODE_PORT", "62050"))
    cert = os.environ.get("ZAGROS_NODE_TLS_CERT", "")
    key = os.environ.get("ZAGROS_NODE_TLS_KEY", "")
    if not cert or not key or not Path(cert).is_file() or not Path(key).is_file():
        raise SystemExit(
            "ZAGROS_NODE_TLS_CERT and ZAGROS_NODE_TLS_KEY are required readable files")
    uvicorn.run("app.node_agent.app:app", host=host, port=port,
                ssl_certfile=cert, ssl_keyfile=key, workers=1,
                proxy_headers=False, forwarded_allow_ips="")


if __name__ == "__main__":
    main()
