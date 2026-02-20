"""
Logs Router
View and manage system logs
"""

from datetime import datetime, timedelta
from typing import Optional, List
import logging

from fastapi import APIRouter, Depends, HTTPException, status, Query, WebSocket, WebSocketDisconnect
from sqlalchemy.orm import Session
from pydantic import BaseModel

from ..database import get_db
from ..models.user import User
from ..models.log import AuditLog, LoginLog, ServiceLog, BlockedIP, AuditAction, LogLevel
from ..security.auth import get_current_active_user, require_permission


logger = logging.getLogger(__name__)

router = APIRouter(prefix="/logs", tags=["Logs"])


# Audit Logs
@router.get("/audit")
async def list_audit_logs(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    user_id: Optional[int] = None,
    action: Optional[str] = None,
    resource_type: Optional[str] = None,
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    current_user: User = Depends(require_permission("audit:read")),
    db: Session = Depends(get_db)
):
    """
    List audit logs with filtering.
    """
    query = db.query(AuditLog)
    
    if user_id:
        query = query.filter(AuditLog.user_id == user_id)
    
    if action:
        try:
            action_enum = AuditAction(action)
            query = query.filter(AuditLog.action == action_enum)
        except ValueError:
            pass
    
    if resource_type:
        query = query.filter(AuditLog.resource_type == resource_type)
    
    if start_date:
        query = query.filter(AuditLog.timestamp >= start_date)
    
    if end_date:
        query = query.filter(AuditLog.timestamp <= end_date)
    
    total = query.count()
    logs = query.order_by(AuditLog.timestamp.desc()).offset(skip).limit(limit).all()
    
    return {
        "total": total,
        "skip": skip,
        "limit": limit,
        "logs": [l.to_dict() for l in logs]
    }


@router.get("/audit/{log_id}")
async def get_audit_log(
    log_id: int,
    current_user: User = Depends(require_permission("audit:read")),
    db: Session = Depends(get_db)
):
    """
    Get a specific audit log entry.
    """
    log = db.query(AuditLog).filter(AuditLog.id == log_id).first()
    
    if not log:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Audit log {log_id} not found"
        )
    
    return log.to_dict()


# Login Logs
@router.get("/login")
async def list_login_logs(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    username: Optional[str] = None,
    success: Optional[bool] = None,
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    current_user: User = Depends(require_permission("audit:read")),
    db: Session = Depends(get_db)
):
    """
    List login logs with filtering.
    """
    query = db.query(LoginLog)
    
    if username:
        query = query.filter(LoginLog.username.ilike(f"%{username}%"))
    
    if success is not None:
        query = query.filter(LoginLog.success == success)
    
    if start_date:
        query = query.filter(LoginLog.timestamp >= start_date)
    
    if end_date:
        query = query.filter(LoginLog.timestamp <= end_date)
    
    total = query.count()
    logs = query.order_by(LoginLog.timestamp.desc()).offset(skip).limit(limit).all()
    
    return {
        "total": total,
        "skip": skip,
        "limit": limit,
        "logs": [l.to_dict() for l in logs]
    }


@router.get("/login/last")
async def get_last_logins(
    limit: int = Query(10, ge=1, le=100),
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """
    Get last login attempts.
    """
    logs = db.query(LoginLog).order_by(LoginLog.timestamp.desc()).limit(limit).all()
    return {"logins": [l.to_dict() for l in logs]}


# Service Logs
@router.get("/service")
async def list_service_logs(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    service_name: Optional[str] = None,
    level: Optional[str] = None,
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    current_user: User = Depends(require_permission("logs:read")),
    db: Session = Depends(get_db)
):
    """
    List service logs with filtering.
    """
    query = db.query(ServiceLog)
    
    if service_name:
        query = query.filter(ServiceLog.service_name == service_name)
    
    if level:
        try:
            level_enum = LogLevel(level)
            query = query.filter(ServiceLog.level == level_enum)
        except ValueError:
            pass
    
    if start_date:
        query = query.filter(ServiceLog.timestamp >= start_date)
    
    if end_date:
        query = query.filter(ServiceLog.timestamp <= end_date)
    
    total = query.count()
    logs = query.order_by(ServiceLog.timestamp.desc()).offset(skip).limit(limit).all()
    
    return {
        "total": total,
        "skip": skip,
        "limit": limit,
        "logs": [l.to_dict() for l in logs]
    }


# Blocked IPs
@router.get("/blocked")
async def list_blocked_ips(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    is_active: Optional[bool] = None,
    service: Optional[str] = None,
    current_user: User = Depends(require_permission("security:manage")),
    db: Session = Depends(get_db)
):
    """
    List blocked IP addresses.
    """
    query = db.query(BlockedIP)
    
    if is_active is not None:
        query = query.filter(BlockedIP.is_active == is_active)
    
    if service:
        query = query.filter(BlockedIP.service == service)
    
    total = query.count()
    blocked = query.order_by(BlockedIP.blocked_at.desc()).offset(skip).limit(limit).all()
    
    return {
        "total": total,
        "skip": skip,
        "limit": limit,
        "blocked_ips": [b.to_dict() for b in blocked]
    }


@router.delete("/blocked/{ip_id}")
async def unblock_ip(
    ip_id: int,
    current_user: User = Depends(require_permission("security:manage")),
    db: Session = Depends(get_db)
):
    """
    Unblock an IP address.
    """
    blocked = db.query(BlockedIP).filter(BlockedIP.id == ip_id).first()
    
    if not blocked:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Blocked IP {ip_id} not found"
        )
    
    blocked.is_active = False
    blocked.unblocked_at = datetime.utcnow()
    blocked.unblocked_by = current_user.username
    
    db.commit()
    
    return {"message": f"IP {blocked.ip_address} unblocked"}


# Statistics
@router.get("/stats")
async def get_log_stats(
    days: int = Query(7, ge=1, le=30),
    current_user: User = Depends(require_permission("audit:read")),
    db: Session = Depends(get_db)
):
    """
    Get log statistics.
    """
    start_date = datetime.utcnow() - timedelta(days=days)
    
    # Audit log stats
    audit_total = db.query(AuditLog).filter(AuditLog.timestamp >= start_date).count()
    
    # Login stats
    login_total = db.query(LoginLog).filter(LoginLog.timestamp >= start_date).count()
    login_success = db.query(LoginLog).filter(
        LoginLog.timestamp >= start_date,
        LoginLog.success == True
    ).count()
    login_failed = db.query(LoginLog).filter(
        LoginLog.timestamp >= start_date,
        LoginLog.success == False
    ).count()
    
    # Failed logins by IP
    failed_by_ip = db.query(
        LoginLog.ip_address,
        db.func.count(LoginLog.id).label('count')
    ).filter(
        LoginLog.timestamp >= start_date,
        LoginLog.success == False,
        LoginLog.ip_address.isnot(None)
    ).group_by(LoginLog.ip_address).order_by(db.desc('count')).limit(10).all()
    
    # Actions by type
    actions_by_type = db.query(
        AuditLog.action,
        db.func.count(AuditLog.id).label('count')
    ).filter(
        AuditLog.timestamp >= start_date
    ).group_by(AuditLog.action).all()
    
    return {
        "period_days": days,
        "audit_logs": audit_total,
        "login_stats": {
            "total": login_total,
            "successful": login_success,
            "failed": login_failed
        },
        "top_failed_ips": [{"ip": ip, "count": count} for ip, count in failed_by_ip],
        "actions_breakdown": {str(action): count for action, count in actions_by_type}
    }


# WebSocket for real-time logs
class ConnectionManager:
    """WebSocket connection manager for real-time logs"""
    
    def __init__(self):
        self.active_connections: List[WebSocket] = []
    
    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
    
    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)
    
    async def broadcast(self, message: dict):
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception:
                pass


manager = ConnectionManager()


@router.websocket("/ws")
async def websocket_logs(
    websocket: WebSocket,
    token: str = Query(...),
    db: Session = Depends(get_db)
):
    """
    WebSocket endpoint for real-time log streaming.
    Requires authentication via token query parameter.
    """
    from ..security.auth import verify_token
    
    # Verify token
    token_data = verify_token(token)
    if not token_data:
        await websocket.close(code=4001, reason="Invalid token")
        return
    
    # Check permission
    user = db.query(User).filter(User.id == int(token_data.sub)).first()
    if not user or not user.is_active:
        await websocket.close(code=4002, reason="User not found or inactive")
        return
    
    if not user.has_permission("logs:read"):
        await websocket.close(code=4003, reason="Permission denied")
        return
    
    await manager.connect(websocket)
    
    try:
        while True:
            # Keep connection alive and wait for messages
            data = await websocket.receive_text()
            
            # Handle ping/pong
            if data == "ping":
                await websocket.send_json({"type": "pong"})
    
    except WebSocketDisconnect:
        manager.disconnect(websocket)


async def broadcast_log(log_type: str, log_data: dict):
    """Broadcast a log message to all connected clients"""
    await manager.broadcast({
        "type": log_type,
        "data": log_data,
        "timestamp": datetime.utcnow().isoformat()
    })