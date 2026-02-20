"""
Authentication Router
Handles login, logout, token refresh, and password management
"""

from datetime import datetime
from typing import Optional
import logging

from fastapi import APIRouter, Depends, HTTPException, status, Request, BackgroundTasks
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from pydantic import BaseModel, EmailStr

from ..database import get_db
from ..models.user import User, Role, Permission
from ..models.log import LoginLog, AuditLog, AuditAction
from ..security.auth import (
    AuthHandler,
    create_access_token,
    create_refresh_token,
    verify_token,
    get_current_user,
    get_current_active_user,
    TokenResponse,
    LoginRequest,
    PasswordChangeRequest
)


logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["Authentication"])


class UserCreate(BaseModel):
    """User creation request"""
    username: str
    password: str
    email: Optional[EmailStr] = None
    full_name: Optional[str] = None
    roles: list[str] = []


class UserResponse(BaseModel):
    """User response model"""
    id: int
    username: str
    email: Optional[str]
    full_name: Optional[str]
    is_active: bool
    roles: list[str]
    created_at: datetime


class RefreshRequest(BaseModel):
    """Token refresh request"""
    refresh_token: str


@router.post("/login", response_model=TokenResponse)
async def login(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    """
    Authenticate user and return tokens.
    
    Uses OAuth2 password flow for compatibility with Swagger UI.
    """
    # Authenticate user
    user = AuthHandler.authenticate_user(db, form_data.username, form_data.password)
    
    # Get client info
    ip_address = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent", "")
    
    if not user:
        # Log failed attempt
        login_log = LoginLog(
            username=form_data.username,
            success=False,
            failure_reason="invalid_credentials",
            ip_address=ip_address,
            user_agent=user_agent
        )
        db.add(login_log)
        db.commit()
        
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Create tokens
    access_token = create_access_token(user)
    refresh_token = create_refresh_token(user)
    
    # Log successful login
    login_log = LoginLog(
        user_id=user.id,
        username=user.username,
        success=True,
        ip_address=ip_address,
        user_agent=user_agent
    )
    db.add(login_log)
    
    # Create audit log
    audit_log = AuditLog(
        user_id=user.id,
        username=user.username,
        action=AuditAction.USER_LOGIN,
        resource_type="user",
        resource_id=user.id,
        resource_name=user.username,
        description=f"User {user.username} logged in",
        ip_address=ip_address,
        user_agent=user_agent
    )
    db.add(audit_log)
    db.commit()
    
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        expires_in=30 * 60,  # 30 minutes
        user=user.to_dict()
    )


@router.post("/login/json", response_model=TokenResponse)
async def login_json(
    request: Request,
    login_data: LoginRequest,
    db: Session = Depends(get_db)
):
    """
    Authenticate user using JSON body and return tokens.
    """
    # Authenticate user
    user = AuthHandler.authenticate_user(db, login_data.username, login_data.password)
    
    # Get client info
    ip_address = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent", "")
    
    if not user:
        # Log failed attempt
        login_log = LoginLog(
            username=login_data.username,
            success=False,
            failure_reason="invalid_credentials",
            ip_address=ip_address,
            user_agent=user_agent
        )
        db.add(login_log)
        db.commit()
        
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Create tokens
    access_token = create_access_token(user)
    refresh_token = create_refresh_token(user)
    
    # Log successful login
    login_log = LoginLog(
        user_id=user.id,
        username=user.username,
        success=True,
        ip_address=ip_address,
        user_agent=user_agent
    )
    db.add(login_log)
    db.commit()
    
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        expires_in=30 * 60,
        user=user.to_dict()
    )


@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(
    refresh_data: RefreshRequest,
    db: Session = Depends(get_db)
):
    """
    Refresh access token using refresh token.
    """
    token_data = verify_token(refresh_data.refresh_token)
    
    if not token_data or token_data.type != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Get user
    user = db.query(User).filter(User.id == int(token_data.sub)).first()
    
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Create new tokens
    access_token = create_access_token(user)
    new_refresh_token = create_refresh_token(user)
    
    return TokenResponse(
        access_token=access_token,
        refresh_token=new_refresh_token,
        token_type="bearer",
        expires_in=30 * 60,
        user=user.to_dict()
    )


@router.post("/logout")
async def logout(
    request: Request,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """
    Logout current user.
    
    In a production system, you would invalidate the token here
    by adding it to a blacklist/revocation list.
    """
    ip_address = request.client.host if request.client else None
    
    # Create audit log
    audit_log = AuditLog(
        user_id=current_user.id,
        username=current_user.username,
        action=AuditAction.USER_LOGOUT,
        resource_type="user",
        resource_id=current_user.id,
        resource_name=current_user.username,
        description=f"User {current_user.username} logged out",
        ip_address=ip_address
    )
    db.add(audit_log)
    db.commit()
    
    return {"message": "Successfully logged out"}


@router.get("/me", response_model=dict)
async def get_current_user_info(
    current_user: User = Depends(get_current_active_user)
):
    """
    Get current authenticated user information.
    """
    return current_user.to_dict(include_permissions=True)


@router.post("/change-password")
async def change_password(
    request: Request,
    password_data: PasswordChangeRequest,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """
    Change current user's password.
    """
    # Verify current password
    if not current_user.verify_password(password_data.current_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect"
        )
    
    # Validate new password
    if password_data.new_password != password_data.confirm_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="New passwords do not match"
        )
    
    if len(password_data.new_password) < 8:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must be at least 8 characters"
        )
    
    # Update password
    current_user.password = password_data.new_password
    
    # Create audit log
    ip_address = request.client.host if request.client else None
    audit_log = AuditLog(
        user_id=current_user.id,
        username=current_user.username,
        action=AuditAction.USER_PASSWORD_CHANGE,
        resource_type="user",
        resource_id=current_user.id,
        resource_name=current_user.username,
        description=f"User {current_user.username} changed password",
        ip_address=ip_address
    )
    db.add(audit_log)
    db.commit()
    
    return {"message": "Password changed successfully"}


@router.get("/verify")
async def verify_token_endpoint(
    current_user: User = Depends(get_current_active_user)
):
    """
    Verify if the current token is valid.
    """
    return {
        "valid": True,
        "user_id": current_user.id,
        "username": current_user.username
    }