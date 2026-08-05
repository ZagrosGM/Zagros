"""sing-box driver package. Importing registers ``SingBoxDriver`` in the registry."""
from app.cores.drivers.singbox.backend import LocalSingBoxBackend, SingBoxBackend
from app.cores.drivers.singbox.driver import SingBoxDriver

__all__ = ["SingBoxDriver", "SingBoxBackend", "LocalSingBoxBackend"]
