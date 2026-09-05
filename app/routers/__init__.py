from fastapi import APIRouter
from . import (
    admin,
    core,
    system,
    user_template,
    user,
    home,
    node_compat,
)

api_router = APIRouter()

routers = [
    admin.router,
    core.router,
    system.router,
    user_template.router,
    user.router,
    home.router,
    node_compat.router,
]

for router in routers:
    api_router.include_router(router)

__all__ = ["api_router"]
