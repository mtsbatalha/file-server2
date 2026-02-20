"""
File Server Manager - Main Application
FastAPI application with complete file server management
"""

import os
import logging
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse
from fastapi.openapi.docs import get_swagger_ui_html
import uvicorn

from .database import init_db, seed_db
from .routers import (
    auth_router,
    services_router,
    users_router,
    shares_router,
    system_router,
    logs_router
)


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("/var/log/fileserver-manager.log")
        if os.path.exists("/var/log")
        else logging.NullHandler()
    ]
)

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator:
    """
    Application lifespan handler.
    Runs on startup and shutdown.
    """
    # Startup
    logger.info("Starting File Server Manager...")
    
    # Initialize database
    logger.info("Initializing database...")
    init_db()
    
    # Seed database with initial data
    logger.info("Seeding database...")
    seed_db()
    
    logger.info("File Server Manager started successfully!")
    
    yield
    
    # Shutdown
    logger.info("Shutting down File Server Manager...")


# Create FastAPI application
app = FastAPI(
    title="File Server Manager",
    description="""
## File Server Manager API

A comprehensive file server management solution supporting:
- **FTP** (vsftpd) - With FTPS support
- **SFTP** (OpenSSH) - Secure file transfer
- **SMB/CIFS** (Samba) - Windows-compatible file sharing
- **NFS** - Unix/Linux file sharing
- **WebDAV** (Nginx) - HTTP-based file access

### Features
- User management with RBAC (Role-Based Access Control)
- System hardening and security configuration
- Firewall management
- Real-time log streaming via WebSocket
- Backup and restore capabilities

### Authentication
Use the `/api/auth/login` endpoint to obtain a JWT token.
Include the token in the `Authorization` header as `Bearer <token>`.
    """,
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan
)


# Add middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CORS_ORIGINS", "*").split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(GZipMiddleware, minimum_size=1000)


# Exception handlers
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Global exception handler"""
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "detail": "Internal server error",
            "error": str(exc) if os.getenv("DEBUG") == "true" else None
        }
    )


# Health check endpoint
@app.get("/health", tags=["Health"])
async def health_check():
    """
    Health check endpoint.
    Used by load balancers and monitoring systems.
    """
    return {
        "status": "healthy",
        "service": "fileserver-manager",
        "version": "1.0.0"
    }


@app.get("/", tags=["Root"])
async def root():
    """
    Root endpoint with API information.
    """
    return {
        "name": "File Server Manager API",
        "version": "1.0.0",
        "docs": "/docs",
        "health": "/health"
    }


# Include routers
app.include_router(auth_router, prefix="/api")
app.include_router(services_router, prefix="/api")
app.include_router(users_router, prefix="/api")
app.include_router(shares_router, prefix="/api")
app.include_router(system_router, prefix="/api")
app.include_router(logs_router, prefix="/api")


# Run the application
if __name__ == "__main__":
    uvicorn.run(
        "app.main:app",
        host=os.getenv("HOST", "0.0.0.0"),
        port=int(os.getenv("PORT", "8000")),
        reload=os.getenv("DEBUG", "false").lower() == "true",
        log_level="info"
    )