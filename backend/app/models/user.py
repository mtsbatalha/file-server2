"""
User, Role and Permission Models for RBAC
"""

from datetime import datetime
from typing import List, Optional
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, ForeignKey, Table, Enum as SQLEnum
from sqlalchemy.orm import relationship
import enum
import bcrypt

from .base import Base, BaseModel


# Association tables for many-to-many relationships
user_roles = Table(
    'user_roles',
    Base.metadata,
    Column('user_id', Integer, ForeignKey('users.id', ondelete='CASCADE'), primary_key=True),
    Column('role_id', Integer, ForeignKey('roles.id', ondelete='CASCADE'), primary_key=True)
)

role_permissions = Table(
    'role_permissions',
    Base.metadata,
    Column('role_id', Integer, ForeignKey('roles.id', ondelete='CASCADE'), primary_key=True),
    Column('permission_id', Integer, ForeignKey('permissions.id', ondelete='CASCADE'), primary_key=True)
)


class UserRole(str, enum.Enum):
    """Predefined system roles"""
    ADMIN = "admin"
    OPERATOR = "operator"
    AUDITOR = "auditor"


class Permission(Base):
    """Permission model for fine-grained access control"""
    __tablename__ = 'permissions'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(100), unique=True, nullable=False, index=True)
    description = Column(String(255), nullable=True)
    resource = Column(String(50), nullable=False)  # e.g., 'users', 'services', 'shares'
    action = Column(String(50), nullable=False)    # e.g., 'create', 'read', 'update', 'delete'
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    
    # Relationships
    roles = relationship("Role", secondary=role_permissions, back_populates="permissions")
    
    def __repr__(self):
        return f"<Permission(name='{self.name}', resource='{self.resource}', action='{self.action}')>"
    
    @property
    def code(self) -> str:
        """Return permission code as resource:action"""
        return f"{self.resource}:{self.action}"


class Role(Base):
    """Role model for grouping permissions"""
    __tablename__ = 'roles'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(50), unique=True, nullable=False, index=True)
    description = Column(String(255), nullable=True)
    is_system = Column(Boolean, default=False, nullable=False)  # System roles cannot be deleted
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    
    # Relationships
    users = relationship("User", secondary=user_roles, back_populates="roles")
    permissions = relationship("Permission", secondary=role_permissions, back_populates="roles")
    
    def __repr__(self):
        return f"<Role(name='{self.name}')>"
    
    def has_permission(self, permission_name: str) -> bool:
        """Check if role has a specific permission"""
        return any(p.name == permission_name for p in self.permissions)
    
    def add_permission(self, permission: Permission) -> None:
        """Add a permission to this role"""
        if permission not in self.permissions:
            self.permissions.append(permission)
    
    def remove_permission(self, permission: Permission) -> None:
        """Remove a permission from this role"""
        if permission in self.permissions:
            self.permissions.remove(permission)


class User(Base):
    """User model with authentication and authorization"""
    __tablename__ = 'users'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(50), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=True, index=True)
    password_hash = Column(String(255), nullable=False)
    
    # User type flags
    is_active = Column(Boolean, default=True, nullable=False)
    is_system_user = Column(Boolean, default=False, nullable=False)  # Has system account
    is_virtual_user = Column(Boolean, default=False, nullable=False)  # Virtual user for FTP/Samba
    is_superuser = Column(Boolean, default=False, nullable=False)
    
    # Profile information
    full_name = Column(String(100), nullable=True)
    home_directory = Column(String(255), nullable=True)
    shell = Column(String(100), default='/bin/false', nullable=False)
    
    # Quota settings
    quota_bytes = Column(Integer, default=0, nullable=False)  # 0 = unlimited
    quota_used = Column(Integer, default=0, nullable=False)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    last_login = Column(DateTime, nullable=True)
    password_changed_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    
    # Relationships
    roles = relationship("Role", secondary=user_roles, back_populates="users")
    shares = relationship("Share", back_populates="owner", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<User(username='{self.username}', is_active={self.is_active})>"
    
    @property
    def password(self) -> str:
        """Password property - write only"""
        raise AttributeError("Password is not readable")
    
    @password.setter
    def password(self, password: str) -> None:
        """Set password with bcrypt hashing"""
        if len(password) < 8:
            raise ValueError("Password must be at least 8 characters")
        salt = bcrypt.gensalt(rounds=12)
        self.password_hash = bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
        self.password_changed_at = datetime.utcnow()
    
    def verify_password(self, password: str) -> bool:
        """Verify password against stored hash"""
        return bcrypt.checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8'))
    
    def has_role(self, role_name: str) -> bool:
        """Check if user has a specific role"""
        return any(r.name == role_name for r in self.roles)
    
    def has_permission(self, permission_name: str) -> bool:
        """Check if user has a specific permission through any of their roles"""
        for role in self.roles:
            if role.has_permission(permission_name):
                return True
        return False
    
    def get_all_permissions(self) -> List[str]:
        """Get all unique permissions from all roles"""
        permissions = set()
        for role in self.roles:
            for perm in role.permissions:
                permissions.add(perm.name)
        return list(permissions)
    
    def add_role(self, role: Role) -> None:
        """Add a role to this user"""
        if role not in self.roles:
            self.roles.append(role)
    
    def remove_role(self, role: Role) -> None:
        """Remove a role from this user"""
        if role in self.roles:
            self.roles.remove(role)
    
    @property
    def quota_usage_percent(self) -> float:
        """Calculate quota usage percentage"""
        if self.quota_bytes == 0:
            return 0.0
        return (self.quota_used / self.quota_bytes) * 100
    
    @property
    def quota_unlimited(self) -> bool:
        """Check if quota is unlimited"""
        return self.quota_bytes == 0
    
    def to_dict(self, include_permissions: bool = False) -> dict:
        """Convert user to dictionary"""
        data = {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "full_name": self.full_name,
            "is_active": self.is_active,
            "is_system_user": self.is_system_user,
            "is_virtual_user": self.is_virtual_user,
            "is_superuser": self.is_superuser,
            "home_directory": self.home_directory,
            "quota_bytes": self.quota_bytes,
            "quota_used": self.quota_used,
            "quota_usage_percent": self.quota_usage_percent,
            "roles": [r.name for r in self.roles],
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_login": self.last_login.isoformat() if self.last_login else None,
        }
        if include_permissions:
            data["permissions"] = self.get_all_permissions()
        return data