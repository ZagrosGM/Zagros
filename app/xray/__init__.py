import os
import shutil
from pathlib import Path
from random import randint
from typing import TYPE_CHECKING, Sequence

from app.models.proxy import ProxyHostSecurity
from app.utils.store import DictStorage
from app.utils.system import check_port
from app.xray import operations
from app.xray.config import XRayConfig
from app.xray.core import XRayCore
from config import XRAY_ASSETS_PATH, XRAY_EXECUTABLE_PATH, XRAY_JSON
from xray_api import XRay as XRayAPI
from xray_api import exceptions, types
from xray_api import exceptions as exc


def _ensure_persistent_config() -> None:
    """Seed the mounted Xray config once; never overwrite operator state.

    Production containers run with a writable mounted /var/lib/zagros. A
    direct unprivileged developer checkout cannot create that path; it falls
    back to the bundled read/write fixture instead of making `import app`
    crash. The host config module is updated too so Studio uses the same file.
    """
    global XRAY_JSON
    if os.path.exists(XRAY_JSON):
        return
    target = Path(XRAY_JSON)
    bundled = Path(__file__).resolve().parents[2] / "xray_config.json"
    if not bundled.is_file():
        raise FileNotFoundError(
            f"Xray config is missing at {XRAY_JSON} and bundled seed {bundled}"
        )
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        part = target.with_name(target.name + ".part")
        shutil.copy2(bundled, part)
        os.replace(part, target)
    except OSError:
        XRAY_JSON = str(bundled)
        import config as host_config

        host_config.XRAY_JSON = XRAY_JSON


_ensure_persistent_config()
core = XRayCore(XRAY_EXECUTABLE_PATH, XRAY_ASSETS_PATH)

# Search for a free API port
try:
    for api_port in range(randint(10000, 60000), 65536):
        if not check_port(api_port):
            break
finally:
    config = XRayConfig(XRAY_JSON, api_port=api_port)
    del api_port

api = XRayAPI(config.api_host, config.api_port)


if TYPE_CHECKING:
    from app.db.models import ProxyHost


@DictStorage
def hosts(storage: dict):
    from app.db import GetDB, crud

    storage.clear()
    with GetDB() as db:
        for inbound_tag in config.inbounds_by_tag:
            inbound_hosts: Sequence[ProxyHost] = crud.get_hosts(db, inbound_tag)

            storage[inbound_tag] = [
                {
                    "remark": host.remark,
                    "address": [i.strip() for i in host.address.split(',')] if host.address else [],
                    "port": host.port,
                    "path": host.path if host.path else None,
                    "sni": [i.strip() for i in host.sni.split(',')] if host.sni else [],
                    "host": [i.strip() for i in host.host.split(',')] if host.host else [],
                    "alpn": host.alpn.value,
                    "fingerprint": host.fingerprint.value,
                    # None means the tls is not specified by host itself and
                    #  complies with its inbound's settings.
                    "tls": None
                    if host.security == ProxyHostSecurity.inbound_default
                    else host.security.value,
                    "allowinsecure": host.allowinsecure,
                    "mux_enable": host.mux_enable,
                    "fragment_setting": host.fragment_setting,
                    "noise_setting": host.noise_setting,
                    "random_user_agent": host.random_user_agent,
                    "use_sni_as_host": host.use_sni_as_host,
                } for host in inbound_hosts if not host.is_disabled
            ]


__all__ = [
    "config",
    "hosts",
    "core",
    "api",
    "operations",
    "exceptions",
    "exc",
    "types",
    "XRayConfig",
    "XRayCore",
]
