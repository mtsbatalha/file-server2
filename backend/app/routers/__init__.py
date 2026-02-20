"""
FastAPI Routers
API endpoints for the File Server Manager
"""

from .auth import router as auth_router
from .services import router as services_router
from .users import router as users_router
from .shares import router as shares_router
from .system import router as system_router
from .logs import router as logs_router

__all__ = [
    "auth_router",
    "services_router",
    "users_router",
    "shares_router",
    "system_router",
    "logs_router"
]