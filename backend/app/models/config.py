"""
System Configuration and Backup Models
"""

from datetime import datetime
from typing import Optional, Dict, Any
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, JSON, Enum as SQLEnum
from sqlalchemy.orm import relationship
import enum

from .base import Base


class ConfigType(str, enum.Enum):
    """Configuration types"""
    SYSTEM = "system"
    NETWORK = "network"
    SECURITY = "security"
    SERVICE = "service"
    BACKUP = "backup"


class SystemConfig(Base):
    """System-wide configuration settings"""
    __tablename__ = 'system_config'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    key = Column(String(100), unique=True, nullable=False, index=True)
    value = Column(Text, nullable=True)
    value_type = Column(String(20), default="string", nullable=False)  # string, int, bool, json
    category = Column(SQLEnum(ConfigType), default=ConfigType.SYSTEM, nullable=False)
    description = Column(String(255), nullable=True)
    is_secret = Column(Boolean, default=False, nullable=False)  # Encrypted value
    is_readonly = Column(Boolean, default=False, nullable=False)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    
    def __repr__(self):
        return f"<SystemConfig(key='{self.key}', value='{self.value}')>"
    
    def get_typed_value(self) -> Any:
        """Get value converted to proper type"""
        if self.value is None:
            return None
        
        if self.value_type == "int":
            return int(self.value)
        elif self.value_type == "bool":
            return self.value.lower() in ("true", "1", "yes")
        elif self.value_type == "json":
            import json
            return json.loads(self.value)
        else:
            return self.value
    
    def set_typed_value(self, value: Any) -> None:
        """Set value from typed input"""
        if value is None:
            self.value = None
        elif isinstance(value, bool):
            self.value_type = "bool"
            self.value = "true" if value else "false"
        elif isinstance(value, int):
            self.value_type = "int"
            self.value = str(value)
        elif isinstance(value, (dict, list)):
            import json
            self.value_type = "json"
            self.value = json.dumps(value)
        else:
            self.value_type = "string"
            self.value = str(value)
    
    def to_dict(self) -> dict:
        """Convert to dictionary"""
        return {
            "id": self.id,
            "key": self.key,
            "value": self.get_typed_value(),
            "value_type": self.value_type,
            "category": self.category.value if self.category else None,
            "description": self.description,
            "is_secret": self.is_secret,
            "is_readonly": self.is_readonly,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None
        }


class BackupConfig(Base):
    """Backup configuration"""
    __tablename__ = 'backup_config'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(100), nullable=False)
    description = Column(String(255), nullable=True)
    
    # What to backup
    backup_type = Column(String(50), default="config", nullable=False)  # config, data, full
    include_paths = Column(JSON, default=list, nullable=True)
    exclude_paths = Column(JSON, default=list, nullable=True)
    include_services = Column(JSON, default=list, nullable=True)
    
    # Schedule
    schedule_enabled = Column(Boolean, default=False, nullable=False)
    schedule_cron = Column(String(100), nullable=True)  # Cron expression
    retention_days = Column(Integer, default=30, nullable=False)
    max_backups = Column(Integer, default=10, nullable=False)
    
    # Storage
    storage_type = Column(String(20), default="local", nullable=False)  # local, s3, sftp
    storage_path = Column(String(500), nullable=True)
    storage_config = Column(JSON, default=dict, nullable=True)  # S3 credentials, SFTP server, etc.
    
    # Compression and encryption
    compress = Column(Boolean, default=True, nullable=False)
    compression_type = Column(String(10), default="gzip", nullable=False)
    encrypt = Column(Boolean, default=False, nullable=False)
    encryption_key_id = Column(String(100), nullable=True)
    
    # Status
    is_active = Column(Boolean, default=True, nullable=False)
    last_run = Column(DateTime, nullable=True)
    last_status = Column(String(20), nullable=True)  # success, failed, running
    last_error = Column(Text, nullable=True)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    
    def __repr__(self):
        return f"<BackupConfig(name='{self.name}', type='{self.backup_type}')>"
    
    def to_dict(self) -> dict:
        """Convert to dictionary"""
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "backup_type": self.backup_type,
            "include_paths": self.include_paths,
            "exclude_paths": self.exclude_paths,
            "include_services": self.include_services,
            "schedule_enabled": self.schedule_enabled,
            "schedule_cron": self.schedule_cron,
            "retention_days": self.retention_days,
            "max_backups": self.max_backups,
            "storage_type": self.storage_type,
            "storage_path": self.storage_path,
            "compress": self.compress,
            "compression_type": self.compression_type,
            "encrypt": self.encrypt,
            "is_active": self.is_active,
            "last_run": self.last_run.isoformat() if self.last_run else None,
            "last_status": self.last_status,
            "last_error": self.last_error,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None
        }


class BackupRecord(Base):
    """Backup execution record"""
    __tablename__ = 'backup_records'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    config_id = Column(Integer, nullable=False)
    
    # Backup details
    backup_name = Column(String(255), nullable=False)
    backup_path = Column(String(500), nullable=True)
    backup_size = Column(Integer, default=0, nullable=False)
    
    # Status
    status = Column(String(20), default="running", nullable=False)  # running, success, failed
    started_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    completed_at = Column(DateTime, nullable=True)
    duration_seconds = Column(Integer, nullable=True)
    
    # Details
    files_count = Column(Integer, default=0, nullable=False)
    error_message = Column(Text, nullable=True)
    
    # Verification
    verified = Column(Boolean, default=False, nullable=False)
    verified_at = Column(DateTime, nullable=True)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    
    def __repr__(self):
        return f"<BackupRecord(name='{self.backup_name}', status='{self.status}')>"
    
    def to_dict(self) -> dict:
        """Convert to dictionary"""
        return {
            "id": self.id,
            "config_id": self.config_id,
            "backup_name": self.backup_name,
            "backup_path": self.backup_path,
            "backup_size": self.backup_size,
            "status": self.status,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "duration_seconds": self.duration_seconds,
            "files_count": self.files_count,
            "error_message": self.error_message,
            "verified": self.verified,
            "verified_at": self.verified_at.isoformat() if self.verified_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None
        }


# Default system configurations
DEFAULT_CONFIGS = [
    {"key": "system.base_path", "value": "/data", "category": ConfigType.SYSTEM, 
     "description": "Base path for file storage"},
    {"key": "system.log_path", "value": "/var/log/fileserver-manager.log", "category": ConfigType.SYSTEM,
     "description": "Path to main log file"},
    {"key": "system.hostname", "value": "fileserver", "category": ConfigType.SYSTEM,
     "description": "Server hostname"},
    
    {"key": "network.domain", "value": "local", "category": ConfigType.NETWORK,
     "description": "Network domain"},
    {"key": "network.dns_servers", "value": "8.8.8.8,8.8.4.4", "category": ConfigType.NETWORK,
     "description": "DNS servers (comma separated)"},
    
    {"key": "security.firewall_enabled", "value": "true", "category": ConfigType.SECURITY,
     "description": "Enable firewall"},
    {"key": "security.fail2ban_enabled", "value": "true", "category": ConfigType.SECURITY,
     "description": "Enable Fail2ban"},
    {"key": "security.ssh_root_login", "value": "false", "category": ConfigType.SECURITY,
     "description": "Allow SSH root login"},
    {"key": "security.ssh_password_auth", "value": "true", "category": ConfigType.SECURITY,
     "description": "Allow SSH password authentication"},
    {"key": "security.min_password_length", "value": "8", "category": ConfigType.SECURITY,
     "description": "Minimum password length"},
    {"key": "security.tls_enabled", "value": "false", "category": ConfigType.SECURITY,
     "description": "Enable TLS for services"},
    {"key": "security.tls_cert_path", "value": "/etc/ssl/certs/server.crt", "category": ConfigType.SECURITY,
     "description": "Path to TLS certificate"},
    {"key": "security.tls_key_path", "value": "/etc/ssl/private/server.key", "category": ConfigType.SECURITY,
     "description": "Path to TLS private key"},
    
    {"key": "backup.auto_before_change", "value": "true", "category": ConfigType.BACKUP,
     "description": "Automatically backup before configuration changes"},
    {"key": "backup.retention_days", "value": "30", "category": ConfigType.BACKUP,
     "description": "Backup retention in days"},
]