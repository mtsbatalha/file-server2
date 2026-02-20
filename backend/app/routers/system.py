"""
System Router
System configuration, hardening, and monitoring
"""

from typing import Dict, Any, Optional
import logging

from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from pydantic import BaseModel

from ..database import get_db
from ..models.user import User
from ..models.config import SystemConfig, BackupConfig, BackupRecord, ConfigType
from ..models.log import AuditLog, AuditAction
from ..security.auth import get_current_active_user, require_permission
from ..security.hardening import HardeningService, HardeningConfig, HardeningReport
from ..security.firewall import FirewallManager, get_firewall_manager
from ..services import get_service_manager


logger = logging.getLogger(__name__)

router = APIRouter(prefix="/system", tags=["System"])


class ConfigUpdateRequest(BaseModel):
    """System config update request"""
    key: str
    value: Any


class HardeningRequest(BaseModel):
    """Hardening configuration request"""
    ssh_disable_root_login: bool = True
    ssh_disable_password_auth: bool = False
    ssh_max_auth_tries: int = 3
    firewall_enabled: bool = True
    firewall_allowed_ports: list[int] = [22, 80, 443, 445, 21]
    fail2ban_enabled: bool = True
    enable_auto_updates: bool = True
    tls_enabled: bool = False


class FirewallRuleRequest(BaseModel):
    """Firewall rule request"""
    port: int
    protocol: str = "tcp"
    action: str = "allow"
    source: Optional[str] = None
    comment: Optional[str] = None


# System Info
@router.get("/info")
async def get_system_info(
    current_user: User = Depends(get_current_active_user)
):
    """
    Get system information.
    """
    import platform
    import psutil
    
    return {
        "system": {
            "hostname": platform.node(),
            "os": platform.system(),
            "os_version": platform.version(),
            "os_release": platform.release(),
            "architecture": platform.machine(),
            "python_version": platform.python_version()
        },
        "cpu": {
            "count": psutil.cpu_count(),
            "percent": psutil.cpu_percent(interval=1)
        },
        "memory": {
            "total": psutil.virtual_memory().total,
            "available": psutil.virtual_memory().available,
            "percent": psutil.virtual_memory().percent
        },
        "boot_time": psutil.boot_time()
    }


@router.get("/resources")
async def get_resource_usage(
    current_user: User = Depends(get_current_active_user)
):
    """
    Get system resource usage.
    """
    manager = get_service_manager()
    return manager.get_resource_usage()


# Configuration
@router.get("/config")
async def list_config(
    category: str = None,
    current_user: User = Depends(require_permission("config:read")),
    db: Session = Depends(get_db)
):
    """
    List system configuration.
    """
    query = db.query(SystemConfig)
    
    if category:
        try:
            cat = ConfigType(category)
            query = query.filter(SystemConfig.category == cat)
        except ValueError:
            pass
    
    configs = query.all()
    
    return {
        "configs": [c.to_dict() for c in configs]
    }


@router.put("/config")
async def update_config(
    request: Request,
    config_data: ConfigUpdateRequest,
    current_user: User = Depends(require_permission("config:update")),
    db: Session = Depends(get_db)
):
    """
    Update system configuration.
    """
    config = db.query(SystemConfig).filter(SystemConfig.key == config_data.key).first()
    
    if not config:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Configuration key '{config_data.key}' not found"
        )
    
    old_value = config.value
    config.set_typed_value(config_data.value)
    
    # Create audit log
    audit_log = AuditLog(
        user_id=current_user.id,
        username=current_user.username,
        action=AuditAction.SYSTEM_CONFIG_CHANGE,
        resource_type="config",
        resource_name=config_data.key,
        description=f"Updated config: {config_data.key}",
        changes={"old_value": old_value, "new_value": config_data.value},
        ip_address=request.client.host if request.client else None
    )
    db.add(audit_log)
    db.commit()
    
    return {"message": "Configuration updated", "config": config.to_dict()}


# Hardening
@router.get("/security/status")
async def get_security_status(
    current_user: User = Depends(require_permission("security:manage"))
):
    """
    Get security hardening status.
    """
    hardening = HardeningService()
    return hardening.check_security_status()


@router.post("/security/harden")
async def apply_hardening(
    request: Request,
    hardening_data: HardeningRequest = None,
    current_user: User = Depends(require_permission("security:manage")),
    db: Session = Depends(get_db)
):
    """
    Apply security hardening.
    """
    config = HardeningConfig()
    
    if hardening_data:
        config = HardeningConfig(
            ssh_disable_root_login=hardening_data.ssh_disable_root_login,
            ssh_disable_password_auth=hardening_data.ssh_disable_password_auth,
            ssh_max_auth_tries=hardening_data.ssh_max_auth_tries,
            firewall_enabled=hardening_data.firewall_enabled,
            firewall_allowed_ports=hardening_data.firewall_allowed_ports,
            fail2ban_enabled=hardening_data.fail2ban_enabled,
            enable_auto_updates=hardening_data.enable_auto_updates,
            tls_enabled=hardening_data.tls_enabled
        )
    
    hardening = HardeningService(config)
    reports = hardening.apply_all()
    
    # Create audit log
    audit_log = AuditLog(
        user_id=current_user.id,
        username=current_user.username,
        action=AuditAction.SYSTEM_HARDENING,
        resource_type="system",
        description="Applied security hardening",
        details={"reports": [r.model_dump() for r in reports]},
        ip_address=request.client.host if request.client else None
    )
    db.add(audit_log)
    db.commit()
    
    return hardening.get_report_summary()


@router.get("/security/report")
async def get_hardening_report(
    current_user: User = Depends(require_permission("security:manage"))
):
    """
    Get last hardening report.
    """
    hardening = HardeningService()
    return {
        "status": hardening.check_security_status(),
        "summary": hardening.get_report_summary()
    }


# Firewall
@router.get("/firewall/status")
async def get_firewall_status(
    current_user: User = Depends(require_permission("firewall:manage"))
):
    """
    Get firewall status.
    """
    firewall = get_firewall_manager()
    
    if not firewall.is_available():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="No supported firewall found"
        )
    
    return firewall.get_status().model_dump()


@router.post("/firewall/enable")
async def enable_firewall(
    request: Request,
    current_user: User = Depends(require_permission("firewall:manage")),
    db: Session = Depends(get_db)
):
    """
    Enable firewall.
    """
    firewall = get_firewall_manager()
    
    if not firewall.is_available():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="No supported firewall found"
        )
    
    result = firewall.enable()
    
    # Create audit log
    audit_log = AuditLog(
        user_id=current_user.id,
        username=current_user.username,
        action=AuditAction.SYSTEM_CONFIG_CHANGE,
        resource_type="firewall",
        description="Enabled firewall",
        ip_address=request.client.host if request.client else None
    )
    db.add(audit_log)
    db.commit()
    
    return {"message": "Firewall enabled", "success": result}


@router.post("/firewall/disable")
async def disable_firewall(
    request: Request,
    current_user: User = Depends(require_permission("firewall:manage")),
    db: Session = Depends(get_db)
):
    """
    Disable firewall.
    """
    firewall = get_firewall_manager()
    
    if not firewall.is_available():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="No supported firewall found"
        )
    
    result = firewall.disable()
    
    # Create audit log
    audit_log = AuditLog(
        user_id=current_user.id,
        username=current_user.username,
        action=AuditAction.SYSTEM_CONFIG_CHANGE,
        resource_type="firewall",
        description="Disabled firewall",
        ip_address=request.client.host if request.client else None
    )
    db.add(audit_log)
    db.commit()
    
    return {"message": "Firewall disabled", "success": result}


@router.post("/firewall/rules")
async def add_firewall_rule(
    request: Request,
    rule_data: FirewallRuleRequest,
    current_user: User = Depends(require_permission("firewall:manage")),
    db: Session = Depends(get_db)
):
    """
    Add firewall rule.
    """
    firewall = get_firewall_manager()
    
    if not firewall.is_available():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="No supported firewall found"
        )
    
    result = firewall.allow_port(
        port=rule_data.port,
        source=rule_data.source,
        comment=rule_data.comment
    )
    
    # Create audit log
    audit_log = AuditLog(
        user_id=current_user.id,
        username=current_user.username,
        action=AuditAction.SYSTEM_CONFIG_CHANGE,
        resource_type="firewall",
        description=f"Added firewall rule for port {rule_data.port}",
        ip_address=request.client.host if request.client else None
    )
    db.add(audit_log)
    db.commit()
    
    return {"message": f"Rule added for port {rule_data.port}", "success": result}


@router.delete("/firewall/rules/{port}")
async def remove_firewall_rule(
    port: int,
    request: Request,
    current_user: User = Depends(require_permission("firewall:manage")),
    db: Session = Depends(get_db)
):
    """
    Remove firewall rule.
    """
    firewall = get_firewall_manager()
    
    if not firewall.is_available():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="No supported firewall found"
        )
    
    from ..security.firewall import FirewallRule, FirewallAction
    rule = FirewallRule(port=port, action=FirewallAction.ALLOW)
    result = firewall.remove_rule(rule)
    
    # Create audit log
    audit_log = AuditLog(
        user_id=current_user.id,
        username=current_user.username,
        action=AuditAction.SYSTEM_CONFIG_CHANGE,
        resource_type="firewall",
        description=f"Removed firewall rule for port {port}",
        ip_address=request.client.host if request.client else None
    )
    db.add(audit_log)
    db.commit()
    
    return {"message": f"Rule removed for port {port}", "success": result}


# Backup
@router.get("/backup/configs")
async def list_backup_configs(
    current_user: User = Depends(require_permission("backup:list")),
    db: Session = Depends(get_db)
):
    """
    List backup configurations.
    """
    configs = db.query(BackupConfig).all()
    return {"configs": [c.to_dict() for c in configs]}


@router.post("/backup/run")
async def run_backup(
    request: Request,
    config_id: int = None,
    current_user: User = Depends(require_permission("backup:create")),
    db: Session = Depends(get_db)
):
    """
    Run a backup.
    """
    # Create audit log
    audit_log = AuditLog(
        user_id=current_user.id,
        username=current_user.username,
        action=AuditAction.SYSTEM_BACKUP,
        resource_type="backup",
        description=f"Ran backup (config_id: {config_id})",
        ip_address=request.client.host if request.client else None
    )
    db.add(audit_log)
    db.commit()
    
    # TODO: Implement actual backup logic
    
    return {"message": "Backup started"}