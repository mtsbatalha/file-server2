"""
Shares Router
Manage file shares (SMB, NFS, WebDAV)
"""

from typing import Dict, Any, List, Optional
import logging

from fastapi import APIRouter, Depends, HTTPException, status, Request, Query
from sqlalchemy.orm import Session
from pydantic import BaseModel

from ..database import get_db
from ..models.user import User
from ..models.share import Share, ShareType, SharePermission, ShareAccessType, ShareStatus
from ..models.log import AuditLog, AuditAction
from ..security.auth import get_current_active_user, require_permission


logger = logging.getLogger(__name__)

router = APIRouter(prefix="/shares", tags=["Shares"])


class ShareCreateRequest(BaseModel):
    """Share creation request"""
    name: str
    description: Optional[str] = None
    share_type: str  # smb, nfs, webdav, ftp
    path: str
    permission: str = "rw"  # ro, rw, rwnd, full
    access_type: str = "private"  # public, private, guest
    allowed_users: Optional[List[str]] = None
    allowed_groups: Optional[List[str]] = None
    allowed_hosts: Optional[List[str]] = None
    quota_enabled: bool = False
    quota_bytes: int = 0


class ShareUpdateRequest(BaseModel):
    """Share update request"""
    description: Optional[str] = None
    permission: Optional[str] = None
    access_type: Optional[str] = None
    allowed_users: Optional[List[str]] = None
    allowed_groups: Optional[List[str]] = None
    allowed_hosts: Optional[List[str]] = None
    quota_enabled: Optional[bool] = None
    quota_bytes: Optional[int] = None


@router.get("")
async def list_shares(
    share_type: Optional[str] = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    current_user: User = Depends(require_permission("shares:list")),
    db: Session = Depends(get_db)
):
    """
    List all shares with optional filtering.
    """
    query = db.query(Share)
    
    if share_type:
        try:
            st = ShareType(share_type)
            query = query.filter(Share.share_type == st)
        except ValueError:
            pass
    
    total = query.count()
    shares = query.offset(skip).limit(limit).all()
    
    return {
        "total": total,
        "skip": skip,
        "limit": limit,
        "shares": [s.to_dict() for s in shares]
    }


@router.post("")
async def create_share(
    request: Request,
    share_data: ShareCreateRequest,
    current_user: User = Depends(require_permission("shares:create")),
    db: Session = Depends(get_db)
):
    """
    Create a new share.
    """
    # Check if share name exists
    existing = db.query(Share).filter(Share.name == share_data.name).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Share '{share_data.name}' already exists"
        )
    
    # Validate share type
    try:
        share_type = ShareType(share_data.share_type)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid share type: {share_data.share_type}"
        )
    
    # Validate permission
    try:
        permission = SharePermission(share_data.permission)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid permission: {share_data.permission}"
        )
    
    # Validate access type
    try:
        access_type = ShareAccessType(share_data.access_type)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid access type: {share_data.access_type}"
        )
    
    # Create share
    share = Share(
        name=share_data.name,
        description=share_data.description,
        share_type=share_type,
        path=share_data.path,
        permission=permission,
        access_type=access_type,
        allowed_users=share_data.allowed_users or [],
        allowed_groups=share_data.allowed_groups or [],
        allowed_hosts=share_data.allowed_hosts or [],
        quota_enabled=share_data.quota_enabled,
        quota_bytes=share_data.quota_bytes,
        owner_id=current_user.id,
        status=ShareStatus.ACTIVE
    )
    
    db.add(share)
    
    # Create audit log
    audit_log = AuditLog(
        user_id=current_user.id,
        username=current_user.username,
        action=AuditAction.SHARE_CREATE,
        resource_type="share",
        resource_name=share_data.name,
        description=f"Created share: {share_data.name}",
        ip_address=request.client.host if request.client else None
    )
    db.add(audit_log)
    db.commit()
    
    return {"message": "Share created successfully", "share": share.to_dict()}


@router.get("/{share_id}")
async def get_share(
    share_id: int,
    current_user: User = Depends(require_permission("shares:read")),
    db: Session = Depends(get_db)
):
    """
    Get share details by ID.
    """
    share = db.query(Share).filter(Share.id == share_id).first()
    
    if not share:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Share with ID {share_id} not found"
        )
    
    return share.to_dict()


@router.put("/{share_id}")
async def update_share(
    share_id: int,
    request: Request,
    share_data: ShareUpdateRequest,
    current_user: User = Depends(require_permission("shares:update")),
    db: Session = Depends(get_db)
):
    """
    Update share details.
    """
    share = db.query(Share).filter(Share.id == share_id).first()
    
    if not share:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Share with ID {share_id} not found"
        )
    
    changes = {}
    
    if share_data.description is not None:
        share.description = share_data.description
        changes["description"] = share_data.description
    
    if share_data.permission is not None:
        try:
            share.permission = SharePermission(share_data.permission)
            changes["permission"] = share_data.permission
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid permission: {share_data.permission}"
            )
    
    if share_data.access_type is not None:
        try:
            share.access_type = ShareAccessType(share_data.access_type)
            changes["access_type"] = share_data.access_type
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid access type: {share_data.access_type}"
            )
    
    if share_data.allowed_users is not None:
        share.allowed_users = share_data.allowed_users
        changes["allowed_users"] = share_data.allowed_users
    
    if share_data.allowed_groups is not None:
        share.allowed_groups = share_data.allowed_groups
        changes["allowed_groups"] = share_data.allowed_groups
    
    if share_data.allowed_hosts is not None:
        share.allowed_hosts = share_data.allowed_hosts
        changes["allowed_hosts"] = share_data.allowed_hosts
    
    if share_data.quota_enabled is not None:
        share.quota_enabled = share_data.quota_enabled
        changes["quota_enabled"] = share_data.quota_enabled
    
    if share_data.quota_bytes is not None:
        share.quota_bytes = share_data.quota_bytes
        changes["quota_bytes"] = share_data.quota_bytes
    
    # Create audit log
    audit_log = AuditLog(
        user_id=current_user.id,
        username=current_user.username,
        action=AuditAction.SHARE_UPDATE,
        resource_type="share",
        resource_id=share.id,
        resource_name=share.name,
        description=f"Updated share: {share.name}",
        changes=changes,
        ip_address=request.client.host if request.client else None
    )
    db.add(audit_log)
    db.commit()
    
    return {"message": "Share updated successfully", "share": share.to_dict()}


@router.delete("/{share_id}")
async def delete_share(
    share_id: int,
    request: Request,
    current_user: User = Depends(require_permission("shares:delete")),
    db: Session = Depends(get_db)
):
    """
    Delete a share.
    """
    share = db.query(Share).filter(Share.id == share_id).first()
    
    if not share:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Share with ID {share_id} not found"
        )
    
    share_name = share.name
    
    # Create audit log
    audit_log = AuditLog(
        user_id=current_user.id,
        username=current_user.username,
        action=AuditAction.SHARE_DELETE,
        resource_type="share",
        resource_id=share.id,
        resource_name=share_name,
        description=f"Deleted share: {share_name}",
        ip_address=request.client.host if request.client else None
    )
    db.add(audit_log)
    
    db.delete(share)
    db.commit()
    
    return {"message": f"Share '{share_name}' deleted successfully"}


@router.get("/{share_id}/config")
async def get_share_config(
    share_id: int,
    current_user: User = Depends(require_permission("shares:read")),
    db: Session = Depends(get_db)
):
    """
    Get generated configuration for a share.
    """
    share = db.query(Share).filter(Share.id == share_id).first()
    
    if not share:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Share with ID {share_id} not found"
        )
    
    config = {}
    
    if share.share_type == ShareType.SMB:
        config["smb_config"] = share.get_smb_config()
    elif share.share_type == ShareType.NFS:
        config["nfs_export"] = share.get_nfs_export()
    elif share.share_type == ShareType.WEBDAV:
        config["webdav_config"] = share.get_webdav_config()
    
    return config


@router.post("/{share_id}/apply")
async def apply_share_config(
    share_id: int,
    request: Request,
    current_user: User = Depends(require_permission("shares:update")),
    db: Session = Depends(get_db)
):
    """
    Apply share configuration to services.
    """
    share = db.query(Share).filter(Share.id == share_id).first()
    
    if not share:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Share with ID {share_id} not found"
        )
    
    # Create audit log
    audit_log = AuditLog(
        user_id=current_user.id,
        username=current_user.username,
        action=AuditAction.SHARE_UPDATE,
        resource_type="share",
        resource_id=share.id,
        resource_name=share.name,
        description=f"Applied configuration for share: {share.name}",
        ip_address=request.client.host if request.client else None
    )
    db.add(audit_log)
    db.commit()
    
    # In a real implementation, this would apply the config to the respective service
    # For now, we just return success
    
    return {"message": f"Configuration applied for share '{share.name}'"}