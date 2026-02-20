"""
Services Router
Manage file server services (FTP, SFTP, SMB, NFS, WebDAV)
"""

from typing import Dict, Any, List, Optional
import logging

from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from pydantic import BaseModel

from ..database import get_db
from ..models.user import User
from ..models.log import AuditLog, AuditAction
from ..security.auth import get_current_active_user, require_permission
from ..services import get_service_manager, ServiceManager
from ..services.base import ServiceResult


logger = logging.getLogger(__name__)

router = APIRouter(prefix="/services", tags=["Services"])


class ServiceInstallRequest(BaseModel):
    """Service installation request"""
    settings: Optional[Dict[str, Any]] = None


class ServiceConfigureRequest(BaseModel):
    """Service configuration request"""
    settings: Dict[str, Any]


class BulkInstallRequest(BaseModel):
    """Bulk installation request"""
    services: List[str]
    settings: Optional[Dict[str, Dict[str, Any]]] = None


@router.get("")
async def list_services(
    current_user: User = Depends(get_current_active_user)
):
    """
    List all available services with their status.
    """
    manager = get_service_manager()
    return manager.list_services()


@router.get("/status")
async def get_services_status(
    current_user: User = Depends(get_current_active_user)
):
    """
    Get status summary of all services.
    """
    manager = get_service_manager()
    return manager.get_services_status()


@router.get("/health")
async def health_check(
    current_user: User = Depends(get_current_active_user)
):
    """
    Perform health check on all services.
    """
    manager = get_service_manager()
    return manager.health_check()


@router.get("/connections")
async def get_all_connections(
    current_user: User = Depends(require_permission("services:list"))
):
    """
    Get connections for all running services.
    """
    manager = get_service_manager()
    return manager.get_all_connections()


@router.post("/install-all")
async def install_all_services(
    request: Request,
    install_data: BulkInstallRequest = None,
    current_user: User = Depends(require_permission("services:install")),
    db: Session = Depends(get_db)
):
    """
    Install all services.
    """
    manager = get_service_manager()
    settings = install_data.settings if install_data else None
    results = manager.install_all(settings)
    
    # Create audit log
    audit_log = AuditLog(
        user_id=current_user.id,
        username=current_user.username,
        action=AuditAction.SERVICE_INSTALL,
        resource_type="service",
        description="Installed all services",
        ip_address=request.client.host if request.client else None
    )
    db.add(audit_log)
    db.commit()
    
    return {
        "message": "Installation completed",
        "results": {k: v.model_dump() for k, v in results.items()}
    }


@router.get("/{service_name}")
async def get_service_info(
    service_name: str,
    current_user: User = Depends(get_current_active_user)
):
    """
    Get detailed information about a specific service.
    """
    manager = get_service_manager()
    info = manager.get_service_info(service_name)
    
    if not info:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Service '{service_name}' not found"
        )
    
    return info


@router.post("/{service_name}/install")
async def install_service(
    service_name: str,
    request: Request,
    install_data: ServiceInstallRequest = None,
    current_user: User = Depends(require_permission("services:install")),
    db: Session = Depends(get_db)
):
    """
    Install a specific service.
    """
    manager = get_service_manager()
    settings = install_data.settings if install_data else None
    result = manager.install_service(service_name, settings)
    
    # Create audit log
    audit_log = AuditLog(
        user_id=current_user.id,
        username=current_user.username,
        action=AuditAction.SERVICE_INSTALL,
        resource_type="service",
        resource_name=service_name,
        description=f"Installed service: {service_name}",
        status="success" if result.success else "failed",
        error_message=result.error,
        ip_address=request.client.host if request.client else None
    )
    db.add(audit_log)
    db.commit()
    
    if not result.success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=result.message
        )
    
    return result.model_dump()


@router.delete("/{service_name}")
async def uninstall_service(
    service_name: str,
    request: Request,
    purge: bool = False,
    current_user: User = Depends(require_permission("services:install")),
    db: Session = Depends(get_db)
):
    """
    Uninstall a specific service.
    """
    manager = get_service_manager()
    result = manager.uninstall_service(service_name, purge)
    
    # Create audit log
    audit_log = AuditLog(
        user_id=current_user.id,
        username=current_user.username,
        action=AuditAction.SERVICE_UNINSTALL,
        resource_type="service",
        resource_name=service_name,
        description=f"Uninstalled service: {service_name}",
        status="success" if result.success else "failed",
        ip_address=request.client.host if request.client else None
    )
    db.add(audit_log)
    db.commit()
    
    if not result.success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=result.message
        )
    
    return result.model_dump()


@router.post("/{service_name}/start")
async def start_service(
    service_name: str,
    request: Request,
    current_user: User = Depends(require_permission("services:start")),
    db: Session = Depends(get_db)
):
    """
    Start a specific service.
    """
    manager = get_service_manager()
    result = manager.start_service(service_name)
    
    # Create audit log
    audit_log = AuditLog(
        user_id=current_user.id,
        username=current_user.username,
        action=AuditAction.SERVICE_START,
        resource_type="service",
        resource_name=service_name,
        description=f"Started service: {service_name}",
        status="success" if result.success else "failed",
        ip_address=request.client.host if request.client else None
    )
    db.add(audit_log)
    db.commit()
    
    if not result.success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=result.message
        )
    
    return result.model_dump()


@router.post("/{service_name}/stop")
async def stop_service(
    service_name: str,
    request: Request,
    current_user: User = Depends(require_permission("services:stop")),
    db: Session = Depends(get_db)
):
    """
    Stop a specific service.
    """
    manager = get_service_manager()
    result = manager.stop_service(service_name)
    
    # Create audit log
    audit_log = AuditLog(
        user_id=current_user.id,
        username=current_user.username,
        action=AuditAction.SERVICE_STOP,
        resource_type="service",
        resource_name=service_name,
        description=f"Stopped service: {service_name}",
        status="success" if result.success else "failed",
        ip_address=request.client.host if request.client else None
    )
    db.add(audit_log)
    db.commit()
    
    if not result.success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=result.message
        )
    
    return result.model_dump()


@router.post("/{service_name}/restart")
async def restart_service(
    service_name: str,
    request: Request,
    current_user: User = Depends(require_permission("services:start")),
    db: Session = Depends(get_db)
):
    """
    Restart a specific service.
    """
    manager = get_service_manager()
    result = manager.restart_service(service_name)
    
    # Create audit log
    audit_log = AuditLog(
        user_id=current_user.id,
        username=current_user.username,
        action=AuditAction.SERVICE_RESTART,
        resource_type="service",
        resource_name=service_name,
        description=f"Restarted service: {service_name}",
        status="success" if result.success else "failed",
        ip_address=request.client.host if request.client else None
    )
    db.add(audit_log)
    db.commit()
    
    if not result.success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=result.message
        )
    
    return result.model_dump()


@router.get("/{service_name}/config")
async def get_service_config(
    service_name: str,
    current_user: User = Depends(require_permission("services:config"))
):
    """
    Get configuration for a specific service.
    """
    manager = get_service_manager()
    config = manager.get_service_config(service_name)
    
    if config is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Service '{service_name}' not found"
        )
    
    return config


@router.put("/{service_name}/config")
async def configure_service(
    service_name: str,
    request: Request,
    config_data: ServiceConfigureRequest,
    current_user: User = Depends(require_permission("services:config")),
    db: Session = Depends(get_db)
):
    """
    Update configuration for a specific service.
    """
    manager = get_service_manager()
    result = manager.configure_service(service_name, config_data.settings)
    
    # Create audit log
    audit_log = AuditLog(
        user_id=current_user.id,
        username=current_user.username,
        action=AuditAction.SERVICE_CONFIG_CHANGE,
        resource_type="service",
        resource_name=service_name,
        description=f"Updated configuration for service: {service_name}",
        status="success" if result.success else "failed",
        ip_address=request.client.host if request.client else None
    )
    db.add(audit_log)
    db.commit()
    
    if not result.success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=result.message
        )
    
    return result.model_dump()


@router.get("/{service_name}/logs")
async def get_service_logs(
    service_name: str,
    lines: int = 100,
    current_user: User = Depends(require_permission("logs:read"))
):
    """
    Get logs for a specific service.
    """
    manager = get_service_manager()
    logs = manager.get_service_logs(service_name, lines)
    
    if logs is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Service '{service_name}' not found"
        )
    
    return {"service": service_name, "logs": logs}


@router.get("/{service_name}/validate")
async def validate_service_config(
    service_name: str,
    current_user: User = Depends(require_permission("services:config"))
):
    """
    Validate configuration for a specific service.
    """
    manager = get_service_manager()
    result = manager.validate_service_config(service_name)
    
    if result is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Service '{service_name}' not found"
        )
    
    return result