"""
Audit and Login Log Models
"""

from datetime import datetime
from typing import Optional
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, ForeignKey, JSON, Enum as SQLEnum
from sqlalchemy.orm import relationship
import enum

from .base import Base


class LogLevel(str, enum.Enum):
    """Log levels"""
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class AuditAction(str, enum.Enum):
    """Audit action types"""
    # User actions
    USER_CREATE = "user.create"
    USER_UPDATE = "user.update"
    USER_DELETE = "user.delete"
    USER_LOGIN = "user.login"
    USER_LOGOUT = "user.logout"
    USER_PASSWORD_CHANGE = "user.password_change"
    
    # Service actions
    SERVICE_INSTALL = "service.install"
    SERVICE_UNINSTALL = "service.uninstall"
    SERVICE_START = "service.start"
    SERVICE_STOP = "service.stop"
    SERVICE_RESTART = "service.restart"
    SERVICE_CONFIG_CHANGE = "service.config_change"
    
    # Share actions
    SHARE_CREATE = "share.create"
    SHARE_UPDATE = "share.update"
    SHARE_DELETE = "share.delete"
    SHARE_ACCESS = "share.access"
    
    # System actions
    SYSTEM_CONFIG_CHANGE = "system.config_change"
    SYSTEM_BACKUP = "system.backup"
    SYSTEM_RESTORE = "system.restore"
    SYSTEM_HARDENING = "system.hardening"
    
    # Security actions
    SECURITY_BLOCK = "security.block"
    SECURITY_UNBLOCK = "security.unblock"
    SECURITY_ALERT = "security.alert"


class AuditLog(Base):
    """Audit log for tracking all system actions"""
    __tablename__ = 'audit_logs'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    
    # Who performed the action
    user_id = Column(Integer, ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    username = Column(String(50), nullable=True)
    
    # What action was performed
    action = Column(SQLEnum(AuditAction), nullable=False)
    resource_type = Column(String(50), nullable=True)  # user, service, share, config
    resource_id = Column(Integer, nullable=True)
    resource_name = Column(String(100), nullable=True)
    
    # Details
    description = Column(Text, nullable=True)
    details = Column(JSON, default=dict, nullable=True)  # Additional structured data
    changes = Column(JSON, default=dict, nullable=True)  # Before/after values
    
    # Status
    status = Column(String(20), default="success", nullable=False)  # success, failed
    error_message = Column(Text, nullable=True)
    
    # Where (context)
    ip_address = Column(String(45), nullable=True)  # IPv6 compatible
    user_agent = Column(String(255), nullable=True)
    session_id = Column(String(100), nullable=True)
    
    # When
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    
    def __repr__(self):
        return f"<AuditLog(action={self.action}, user='{self.username}', timestamp={self.timestamp})>"
    
    def to_dict(self) -> dict:
        """Convert to dictionary"""
        return {
            "id": self.id,
            "user_id": self.user_id,
            "username": self.username,
            "action": self.action.value if self.action else None,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "resource_name": self.resource_name,
            "description": self.description,
            "details": self.details,
            "changes": self.changes,
            "status": self.status,
            "error_message": self.error_message,
            "ip_address": self.ip_address,
            "user_agent": self.user_agent,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None
        }


class LoginLog(Base):
    """Login attempt log"""
    __tablename__ = 'login_logs'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    
    # Who
    user_id = Column(Integer, ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    username = Column(String(50), nullable=False, index=True)
    
    # Result
    success = Column(Boolean, default=False, nullable=False)
    failure_reason = Column(String(100), nullable=True)  # invalid_password, user_not_found, locked, etc.
    
    # Context
    ip_address = Column(String(45), nullable=True, index=True)
    user_agent = Column(String(255), nullable=True)
    location = Column(String(100), nullable=True)  # Country/City if geolocation available
    
    # Session
    session_id = Column(String(100), nullable=True)
    session_duration = Column(Integer, nullable=True)  # seconds
    
    # When
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    logout_timestamp = Column(DateTime, nullable=True)
    
    def __repr__(self):
        return f"<LoginLog(username='{self.username}', success={self.success}, ip='{self.ip_address}')>"
    
    def to_dict(self) -> dict:
        """Convert to dictionary"""
        return {
            "id": self.id,
            "user_id": self.user_id,
            "username": self.username,
            "success": self.success,
            "failure_reason": self.failure_reason,
            "ip_address": self.ip_address,
            "user_agent": self.user_agent,
            "location": self.location,
            "session_id": self.session_id,
            "session_duration": self.session_duration,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "logout_timestamp": self.logout_timestamp.isoformat() if self.logout_timestamp else None
        }


class ServiceLog(Base):
    """Service-specific log entries"""
    __tablename__ = 'service_logs'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    
    # Which service
    service_id = Column(Integer, ForeignKey('services.id', ondelete='CASCADE'), nullable=False)
    service_name = Column(String(50), nullable=False, index=True)
    
    # Log entry
    level = Column(SQLEnum(LogLevel), default=LogLevel.INFO, nullable=False)
    message = Column(Text, nullable=False)
    source = Column(String(100), nullable=True)  # Source module/component
    
    # Additional data
    raw_line = Column(Text, nullable=True)  # Original log line
    parsed_data = Column(JSON, default=dict, nullable=True)
    
    # When
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    
    def __repr__(self):
        return f"<ServiceLog(service='{self.service_name}', level={self.level})>"
    
    def to_dict(self) -> dict:
        """Convert to dictionary"""
        return {
            "id": self.id,
            "service_id": self.service_id,
            "service_name": self.service_name,
            "level": self.level.value if self.level else None,
            "message": self.message,
            "source": self.source,
            "raw_line": self.raw_line,
            "parsed_data": self.parsed_data,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None
        }


class BlockedIP(Base):
    """Blocked IP addresses (from Fail2ban or manual)"""
    __tablename__ = 'blocked_ips'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    
    # IP info
    ip_address = Column(String(45), unique=True, nullable=False, index=True)
    
    # Block details
    reason = Column(String(255), nullable=True)
    service = Column(String(50), nullable=True)  # ssh, ftp, smb, etc.
    attempts = Column(Integer, default=0, nullable=False)
    
    # Block info
    blocked_by = Column(String(50), default="fail2ban", nullable=False)  # fail2ban, manual
    is_permanent = Column(Boolean, default=False, nullable=False)
    
    # Timestamps
    blocked_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    expires_at = Column(DateTime, nullable=True)
    unblocked_at = Column(DateTime, nullable=True)
    unblocked_by = Column(String(50), nullable=True)
    
    # Status
    is_active = Column(Boolean, default=True, nullable=False)
    
    def __repr__(self):
        return f"<BlockedIP(ip='{self.ip_address}', service='{self.service}')>"
    
    @property
    def is_expired(self) -> bool:
        """Check if block has expired"""
        if self.is_permanent:
            return False
        if self.expires_at is None:
            return False
        return datetime.utcnow() > self.expires_at
    
    def to_dict(self) -> dict:
        """Convert to dictionary"""
        return {
            "id": self.id,
            "ip_address": self.ip_address,
            "reason": self.reason,
            "service": self.service,
            "attempts": self.attempts,
            "blocked_by": self.blocked_by,
            "is_permanent": self.is_permanent,
            "blocked_at": self.blocked_at.isoformat() if self.blocked_at else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "unblocked_at": self.unblocked_at.isoformat() if self.unblocked_at else None,
            "unblocked_by": self.unblocked_by,
            "is_active": self.is_active,
            "is_expired": self.is_expired
        }