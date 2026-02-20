"""
Authentication and Authorization Module
JWT-based authentication with RBAC support
"""

from datetime import datetime, timedelta
from typing import Optional, List, Callable, Any
from functools import wraps

from fastapi import Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials, OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session

import os
import secrets

from ..database import get_db
from ..models.user import User, Role, Permission


# Configuration
SECRET_KEY = os.getenv("JWT_SECRET_KEY", secrets.token_urlsafe(64))
ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))
REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7"))
ISSUER = os.getenv("JWT_ISSUER", "fileserver-manager")
AUDIENCE = os.getenv("JWT_AUDIENCE", "fileserver-manager-api")


# Password context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2 scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login", auto_error=False)
bearer_scheme = HTTPBearer(auto_error=False)


class TokenData(BaseModel):
    """Token payload data"""
    sub: str  # User ID
    username: str
    email: Optional[str] = None
    roles: List[str] = []
    permissions: List[str] = []
    exp: Optional[datetime] = None
    iat: Optional[datetime] = None
    type: str = "access"  # access or refresh


class TokenResponse(BaseModel):
    """Token response model"""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    user: dict


class LoginRequest(BaseModel):
    """Login request model"""
    username: str
    password: str
    remember_me: bool = False


class PasswordChangeRequest(BaseModel):
    """Password change request"""
    current_password: str
    new_password: str
    confirm_password: str


class AuthHandler:
    """Authentication handler class"""
    
    @staticmethod
    def verify_password(plain_password: str, hashed_password: str) -> bool:
        """Verify a password against its hash"""
        return pwd_context.verify(plain_password, hashed_password)
    
    @staticmethod
    def hash_password(password: str) -> str:
        """Hash a password"""
        return pwd_context.hash(password)
    
    @staticmethod
    def create_token(
        user: User,
        token_type: str = "access",
        expires_delta: Optional[timedelta] = None
    ) -> str:
        """Create a JWT token for a user"""
        now = datetime.utcnow()
        
        if expires_delta:
            expire = now + expires_delta
        elif token_type == "refresh":
            expire = now + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
        else:
            expire = now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        
        # Build payload
        payload = {
            "sub": str(user.id),
            "username": user.username,
            "email": user.email,
            "roles": [r.name for r in user.roles],
            "permissions": user.get_all_permissions(),
            "exp": expire,
            "iat": now,
            "iss": ISSUER,
            "aud": AUDIENCE,
            "type": token_type
        }
        
        return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    
    @staticmethod
    def decode_token(token: str) -> Optional[TokenData]:
        """Decode and validate a JWT token"""
        try:
            payload = jwt.decode(
                token,
                SECRET_KEY,
                algorithms=[ALGORITHM],
                issuer=ISSUER,
                audience=AUDIENCE
            )
            return TokenData(
                sub=payload.get("sub"),
                username=payload.get("username"),
                email=payload.get("email"),
                roles=payload.get("roles", []),
                permissions=payload.get("permissions", []),
                exp=datetime.fromtimestamp(payload.get("exp", 0)),
                iat=datetime.fromtimestamp(payload.get("iat", 0)),
                type=payload.get("type", "access")
            )
        except JWTError:
            return None
    
    @staticmethod
    def authenticate_user(db: Session, username: str, password: str) -> Optional[User]:
        """Authenticate a user by username and password"""
        # Find user by username or email
        user = db.query(User).filter(
            (User.username == username) | (User.email == username)
        ).first()
        
        if not user:
            return None
        
        if not user.is_active:
            return None
        
        if not user.verify_password(password):
            return None
        
        # Update last login
        user.last_login = datetime.utcnow()
        db.commit()
        
        return user


def create_access_token(user: User, expires_delta: Optional[timedelta] = None) -> str:
    """Create an access token for a user"""
    return AuthHandler.create_token(user, "access", expires_delta)


def create_refresh_token(user: User) -> str:
    """Create a refresh token for a user"""
    return AuthHandler.create_token(user, "refresh")


def verify_token(token: str) -> Optional[TokenData]:
    """Verify and decode a token"""
    return AuthHandler.decode_token(token)


async def get_token_from_request(
    request: Request,
    token: Optional[str] = Depends(oauth2_scheme),
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme)
) -> Optional[str]:
    """Extract token from request (header or query param)"""
    # Try OAuth2 scheme (Authorization: Bearer <token>)
    if token:
        return token
    
    # Try HTTPBearer
    if credentials:
        return credentials.credentials
    
    # Try query parameter
    token = request.query_params.get("token")
    if token:
        return token
    
    return None


async def get_current_user(
    request: Request,
    token: Optional[str] = Depends(get_token_from_request),
    db: Session = Depends(get_db)
) -> Optional[User]:
    """Get the current authenticated user from the token"""
    if not token:
        return None
    
    token_data = verify_token(token)
    if not token_data:
        return None
    
    if token_data.type != "access":
        return None
    
    # Check if token is expired
    if token_data.exp and token_data.exp < datetime.utcnow():
        return None
    
    # Get user from database
    user = db.query(User).filter(User.id == int(token_data.sub)).first()
    
    if not user or not user.is_active:
        return None
    
    # Store token data in request state
    request.state.user = user
    request.state.token_data = token_data
    
    return user


async def get_current_active_user(
    current_user: Optional[User] = Depends(get_current_user)
) -> User:
    """Get the current active user (raises exception if not authenticated)"""
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is disabled"
        )
    
    return current_user


async def get_current_superuser(
    current_user: User = Depends(get_current_active_user)
) -> User:
    """Get the current superuser (raises exception if not superuser)"""
    if not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Superuser access required"
        )
    return current_user


def require_permission(permission: str) -> Callable:
    """
    Decorator to require a specific permission.
    Usage: @require_permission("users:create")
    """
    async def permission_checker(
        current_user: User = Depends(get_current_active_user)
    ) -> User:
        # Superusers have all permissions
        if current_user.is_superuser:
            return current_user
        
        if not current_user.has_permission(permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission '{permission}' required"
            )
        return current_user
    
    return permission_checker


def require_role(role_name: str) -> Callable:
    """
    Decorator to require a specific role.
    Usage: @require_role("admin")
    """
    async def role_checker(
        current_user: User = Depends(get_current_active_user)
    ) -> User:
        # Superusers have all roles
        if current_user.is_superuser:
            return current_user
        
        if not current_user.has_role(role_name):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{role_name}' required"
            )
        return current_user
    
    return role_checker


def require_permissions(*permissions: str) -> Callable:
    """
    Decorator to require multiple permissions (AND logic).
    Usage: @require_permissions("users:read", "users:create")
    """
    async def permissions_checker(
        current_user: User = Depends(get_current_active_user)
    ) -> User:
        # Superusers have all permissions
        if current_user.is_superuser:
            return current_user
        
        user_permissions = current_user.get_all_permissions()
        missing = [p for p in permissions if p not in user_permissions]
        
        if missing:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Missing required permissions: {', '.join(missing)}"
            )
        return current_user
    
    return permissions_checker


def require_any_permission(*permissions: str) -> Callable:
    """
    Decorator to require at least one permission (OR logic).
    Usage: @require_any_permission("users:read", "users:list")
    """
    async def permission_checker(
        current_user: User = Depends(get_current_active_user)
    ) -> User:
        # Superusers have all permissions
        if current_user.is_superuser:
            return current_user
        
        user_permissions = current_user.get_all_permissions()
        if not any(p in user_permissions for p in permissions):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"One of these permissions required: {', '.join(permissions)}"
            )
        return current_user
    
    return permission_checker


class PermissionChecker:
    """
    Class-based permission checker for more complex scenarios.
    
    Usage:
        checker = PermissionChecker()
        
        @app.get("/users", dependencies=[Depends(checker.require("users:list"))])
        async def list_users(): ...
    """
    
    def __init__(self, require_superuser: bool = False):
        self.require_superuser = require_superuser
    
    def require(self, permission: str) -> Callable:
        """Require a specific permission"""
        return require_permission(permission)
    
    def require_all(self, *permissions: str) -> Callable:
        """Require all specified permissions"""
        return require_permissions(*permissions)
    
    def require_any(self, *permissions: str) -> Callable:
        """Require at least one permission"""
        return require_any_permission(*permissions)
    
    def __call__(
        self,
        current_user: User = Depends(get_current_active_user)
    ) -> User:
        """Default check - just require authentication"""
        if self.require_superuser and not current_user.is_superuser:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Superuser access required"
            )
        return current_user


# Permission constants for common actions
class Permissions:
    """Predefined permission constants"""
    
    # User management
    USER_CREATE = "users:create"
    USER_READ = "users:read"
    USER_UPDATE = "users:update"
    USER_DELETE = "users:delete"
    USER_LIST = "users:list"
    
    # Service management
    SERVICE_INSTALL = "services:install"
    SERVICE_UNINSTALL = "services:uninstall"
    SERVICE_START = "services:start"
    SERVICE_STOP = "services:stop"
    SERVICE_CONFIG = "services:config"
    SERVICE_LIST = "services:list"
    
    # Share management
    SHARE_CREATE = "shares:create"
    SHARE_READ = "shares:read"
    SHARE_UPDATE = "shares:update"
    SHARE_DELETE = "shares:delete"
    SHARE_LIST = "shares:list"
    
    # System configuration
    CONFIG_READ = "config:read"
    CONFIG_UPDATE = "config:update"
    
    # Backup management
    BACKUP_CREATE = "backup:create"
    BACKUP_RESTORE = "backup:restore"
    BACKUP_LIST = "backup:list"
    
    # Audit & logs
    AUDIT_READ = "audit:read"
    LOGS_READ = "logs:read"
    
    # Security
    SECURITY_MANAGE = "security:manage"
    FIREWALL_MANAGE = "firewall:manage"