"""ACME auto-renewal: entries under 30 days to expiry
are renewed in place — same exactly-once discipline as everything else
(idempotent renew; failures logged, never crash the scheduler loop)."""
from __future__ import annotations

import logging

from app import scheduler
from app import app as webapp

logger = logging.getLogger(__name__)


def renew_acme_certificates() -> None:
    try:
        from app.platform.acme import default_data_dir, renew_due

        unseal = None
        try:
            # DNS-01 entries keep their credentials sealed with the runtime
            # cipher; the sweep needs the unseal callback to renew them.
            unseal = lambda blob: webapp.state.zagros.cipher.decrypt_json(
                blob, aad="acme-dns-env")
        except Exception:  # noqa: BLE001 — renew HTTP-01 entries regardless
            unseal = None

        results = renew_due(default_data_dir(), unseal=unseal)
        for r in results:
            if not r["ok"]:
                logger.warning("acme renewal failed for %s: %s", r["domain"], r["error"])
    except Exception as exc:  # noqa: BLE001 — jobs must never crash the scheduler
        logger.warning("acme renewal sweep failed: %s", exc)


scheduler.add_job(renew_acme_certificates, 'interval', coalesce=True,
                  hours=12, max_instances=1)
