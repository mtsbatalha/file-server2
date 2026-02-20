"""
Users Router
Manage system and virtual users
"""

from typing import Dict, Any, List, Optional
import logging

from fastapi import APIRouter, Depends, HTTPException, status, Request, Query
from sqlalchemy.orm import Session
from pydantic import BaseModel, EmailStr

from ..database import get_db
from ..models.user import User, Role, Permission, UserRole
from ..models.log import AuditLog, AuditAction
from ..security.auth import (
    get_current_active_user,
    get_current_superuser,
    require_permission
)


logger = logging.getLogger(__name__)

router = APIRouter(prefix="/users", tags=["Users"])


class UserCreateRequest(BaseModel):
    """User creation request"""
    username: str
    password: str
    email: Optional[EmailStr] = None
    full_name: Optional[str] = None
    is_system_user: bool = False
    is_virtual_user: bool = True
    roles: List[str] = []
    home_directory: Optional[str] = None
    quota_bytes: int = 0


class UserUpdateRequest(BaseModel):
    """User update request"""
    email: Optional[EmailStr] = None
    full_name: Optional[str] = None
    is_active: Optional[bool] = None
    roles: Optional[List[str]] = None
    home_directory: Optional[str] = None
    quota_bytes: Optional[int] = None


class PasswordResetRequest(BaseModel):
    """Password reset request"""
    new_password: str


class RoleCreateRequest(BaseModel):
    """Role creation request"""
    name: str
    description: Optional[str] = None
    permissions: List[str] = []


@router.get("")
async def list_users(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    is_active: Optional[bool] = None,
    search: Optional[str] = None,
    current_user: User = Depends(require_permission("users:list")),
    db: Session = Depends(get_db)
):
    """
    List all users with optional filtering.
    """
    query = db.query(User)
    
    if is_active is not None:
        query = query.filter(User.is_active == is_active)
    
    if search:
        query = query.filter(
            (User.username.ilike(f"%{search}%")) |
            (User.email.ilike(f"%{search}%")) |
            (User.full_name.ilike(f"%{search}%"))
        )
    
    total = query.count()
    users = query.offset(skip).limit(limit).all()
    
    return {
        "total": total,
        "skip": skip,
        "limit": limit,
        "users": [u.to_dict() for u in users]
    }


@router.post("")
async def create_user(
    request: Request,
    user_data: UserCreateRequest,
    current_user: User = Depends(require_permission("users:create")),
    db: Session = Depends(get_db)
):
    """
    Create a new user.
    """
    # Check if username exists
    existing = db.query(User).filter(User.username == user_data.username).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Username '{user_data.username}' already exists"
        )
    
    # Check if email exists
    if user_data.email:
        existing = db.query(User).filter(User.email == user_data.email).first()
        if existing:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Email '{user_data.email}' already registered"
            )
    
    # Create user
    user = User(
        username=user_data.username,
        email=user_data.email,
        full_name=user_data.full_name,
        is_system_user=user_data.is_system_user,
        is_virtual_user=user_data.is_virtual_user,
        home_directory=user_data.home_directory,
        quota_bytes=user_data.quota_bytes
    )
    user.password = user_data.password
    
    # Assign roles
    for role_name in user_data.roles:
        role = db.query(Role).filter(Role.name == role_name).first()
        if role:
            user.roles.append(role)
    
    db.add(user)
    
    # Create audit log
    audit_log = AuditLog(
        user_id=current_user.id,
        username=current_user.username,
        action=AuditAction.USER_CREATE,
        resource_type="user",
        resource_name=user_data.username,
        description=f"Created user: {user_data.username}",
        ip_address=request.client.host if request.client else None
    )
    db.add(audit_log)
    db.commit()
    
    return {"message": "User created successfully", "user": user.to_dict()}


@router.get("/{user_id}")
async def get_user(
    user_id: int,
    current_user: User = Depends(require_permission("users:read")),
    db: Session = Depends(get_db)
):
    """
    Get user details by ID.
    """
    user = db.query(User).filter(User.id == user_id).first()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User with ID {user_id} not found"
        )
    
    return user.to_dict(include_permissions=True)


@router.put("/{user_id}")
async def update_user(
    user_id: int,
    request: Request,
    user_data: UserUpdateRequest,
    current_user: User = Depends(require_permission("users:update")),
    db: Session = Depends(get_db)
):
    """
    Update user details.
    """
    user = db.query(User).filter(User.id == user_id).first()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User with ID {user_id} not found"
        )
    
    changes = {}
    
    if user_data.email is not None:
        # Check email uniqueness
        existing = db.query(User).filter(
            User.email == user_data.email,
            User.id != user_id
        ).first()
        if existing:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Email '{user_data.email}' already registered"
            )
        user.email = user_data.email
        changes["email"] = user_data.email
    
    if user_data.full_name is not None:
        user.full_name = user_data.full_name
        changes["full_name"] = user_data.full_name
    
    if user_data.is_active is not None:
        user.is_active = user_data.is_active
        changes["is_active"] = user_data.is_active
    
    if user_data.home_directory is not None:
        user.home_directory = user_data.home_directory
        changes["home_directory"] = user_data.home_directory
    
    if user_data.quota_bytes is not None:
        user.quota_bytes = user_data.quota_bytes
        changes["quota_bytes"] = user_data.quota_bytes
    
    if user_data.roles is not None:
        user.roles = []
        for role_name in user_data.roles:
            role = db.query(Role).filter(Role.name == role_name).first()
            if role:
                user.roles.append(role)
        changes["roles"] = user_data.roles
    
    # Create audit log
    audit_log = AuditLog(
        user_id=current_user.id,
        username=current_user.username,
        action=AuditAction.USER_UPDATE,
        resource_type="user",
        resource_id=user.id,
        resource_name=user.username,
        description=f"Updated user: {user.username}",
        changes=changes,
        ip_address=request.client.host if request.client else None
    )
    db.add(audit_log)
    db.commit()
    
    return {"message": "User updated successfully", "user": user.to_dict()}


@router.delete("/{user_id}")
async def delete_user(
    user_id: int,
    request: Request,
    current_user: User = Depends(require_permission("users:delete")),
    db: Session = Depends(get_db)
):
    """
    Delete a user.
    """
    user = db.query(User).filter(User.id == user_id).first()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User with ID {user_id} not found"
        )
    
    # Prevent self-deletion
    if user.id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete your own account"
        )
    
    username = user.username
    
    # Create audit log
    audit_log = AuditLog(
        user_id=current_user.id,
        username=current_user.username,
        action=AuditAction.USER_DELETE,
        resource_type="user",
        resource_id=user.id,
        resource_name=username,
        description=f"Deleted user: {username}",
        ip_address=request.client.host if request.client else None
    )
    db.add(audit_log)
    
    db.delete(user)
    db.commit()
    
    return {"message": f"User '{username}' deleted successfully"}


@router.post("/{user_id}/reset-password")
async def reset_user_password(
    user_id: int,
    request: Request,
    password_data: PasswordResetRequest,
    current_user: User = Depends(require_permission("users:update")),
    db: Session = Depends(get_db)
):
    """
    Reset a user's password.
    """
    user = db.query(User).filter(User.id == user_id).first()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User with ID {user_id} not found"
        )
    
    if len(password_data.new_password) < 8:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must be at least 8 characters"
        )
    
    user.password = password_data.new_password
    
    # Create audit log
    audit_log = AuditLog(
        user_id=current_user.id,
        username=current_user.username,
        action=AuditAction.USER_PASSWORD_CHANGE,
        resource_type="user",
        resource_id=user.id,
        resource_name=user.username,
        description=f"Reset password for user: {user.username}",
        ip_address=request.client.host if request.client else None
    )
    db.add(audit_log)
    db.commit()
    
    return {"message": "Password reset successfully"}


# Role endpoints
@router.get("/roles/")
async def list_roles(
    current_user: User = Depends(require_permission("users:list")),
    db: Session = Depends(get_db)
):
    """
    List all roles.
    """
    roles = db.query(Role).all()
    return {
        "roles": [
            {
                "id": r.id,
                "name": r.name,
                "description": r.description,
                "is_system": r.is_system,
                "permissions": [p.name for p in r.permissions]
            }
            for r in roles
        ]
    }


@router.post("/roles/")
async def create_role(
    request: Request,
    role_data: RoleCreateRequest,
    current_user: User = Depends(require_permission("users:create")),
    db: Session = Depends(get_db)
):
    """
    Create a new role.
    """
    # Check if role exists
    existing = db.query(Role).filter(Role.name == role_data.name).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Role '{role_data.name}' already exists"
        )
    
    role = Role(
        name=role_data.name,
        description=role_data.description
    )
    
    # Assign permissions
    for perm_name in role_data.permissions:
        perm = db.query(Permission).filter(Permission.name == perm_name).first()
        if perm:
            role.permissions.append(perm)
    
    db.add(role)
    db.commit()
    
    return {"message": "Role created successfully", "role_id": role.id}


# Permission endpoints
@router.get("/permissions/")
async def list_permissions(
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """
    List all available permissions.
    """
    permissions = db.query(Permission).all()
    return {
        "permissions": [
            {
                "id": p.id,
                "name": p.name,
                "resource": p.resource,
                "action": p.action,
                "description": p.description
            }
            for p in permissions
        ]
    }