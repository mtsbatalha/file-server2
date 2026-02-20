"""
Service Model for managing file server services
"""

from datetime import datetime
from typing import Optional, Dict, Any
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, JSON, Enum as SQLEnum
from sqlalchemy.orm import relationship
import enum

from .base import Base


class ServiceType(str, enum.Enum):
    """Supported service types"""
    FTP = "ftp"          # vsftpd
    SFTP = "sftp"        # OpenSSH
    SMB = "smb"          # Samba
    NFS = "nfs"          # NFS Server
    WEBDAV = "webdav"    # Nginx/Apache WebDAV


class ServiceStatus(str, enum.Enum):
    """Service status"""
    NOT_INSTALLED = "not_installed"
    INSTALLED = "installed"
    RUNNING = "running"
    STOPPED = "stopped"
    ERROR = "error"
    INSTALLING = "installing"
    UNINSTALLING = "uninstalling"


class Service(Base):
    """Service model for file server services"""
    __tablename__ = 'services'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(50), unique=True, nullable=False, index=True)
    display_name = Column(String(100), nullable=False)
    service_type = Column(SQLEnum(ServiceType), nullable=False)
    package_name = Column(String(100), nullable=True)
    service_name = Column(String(100), nullable=True)  # systemd service name
    
    # Status
    status = Column(SQLEnum(ServiceStatus), default=ServiceStatus.NOT_INSTALLED, nullable=False)
    is_enabled = Column(Boolean, default=False, nullable=False)  # Start on boot
    auto_start = Column(Boolean, default=True, nullable=False)
    
    # Configuration
    config_path = Column(String(255), nullable=True)
    config_content = Column(Text, nullable=True)
    port = Column(Integer, nullable=True)
    protocol = Column(String(20), nullable=True)  # tcp/udp
    
    # Settings stored as JSON
    settings = Column(JSON, default=dict, nullable=True)
    
    # Security settings
    tls_enabled = Column(Boolean, default=False, nullable=False)
    tls_cert_path = Column(String(255), nullable=True)
    tls_key_path = Column(String(255), nullable=True)
    
    # Version info
    version = Column(String(50), nullable=True)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    last_started = Column(DateTime, nullable=True)
    last_stopped = Column(DateTime, nullable=True)
    
    # Error tracking
    last_error = Column(Text, nullable=True)
    
    def __repr__(self):
        return f"<Service(name='{self.name}', type={self.service_type}, status={self.status})>"
    
    @property
    def is_running(self) -> bool:
        """Check if service is running"""
        return self.status == ServiceStatus.RUNNING
    
    @property
    def is_installed(self) -> bool:
        """Check if service is installed"""
        return self.status in [
            ServiceStatus.INSTALLED,
            ServiceStatus.RUNNING,
            ServiceStatus.STOPPED
        ]
    
    def get_settings(self, key: str = None, default: Any = None) -> Any:
        """Get settings value(s)"""
        if not self.settings:
            return default
        if key:
            return self.settings.get(key, default)
        return self.settings
    
    def set_settings(self, key: str, value: Any) -> None:
        """Set a setting value"""
        if not self.settings:
            self.settings = {}
        self.settings[key] = value
    
    def to_dict(self) -> dict:
        """Convert service to dictionary"""
        return {
            "id": self.id,
            "name": self.name,
            "display_name": self.display_name,
            "service_type": self.service_type.value if self.service_type else None,
            "package_name": self.package_name,
            "service_name": self.service_name,
            "status": self.status.value if self.status else None,
            "is_enabled": self.is_enabled,
            "auto_start": self.auto_start,
            "config_path": self.config_path,
            "port": self.port,
            "protocol": self.protocol,
            "settings": self.settings,
            "tls_enabled": self.tls_enabled,
            "tls_cert_path": self.tls_cert_path,
            "version": self.version,
            "is_running": self.is_running,
            "is_installed": self.is_installed,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "last_started": self.last_started.isoformat() if self.last_started else None,
            "last_stopped": self.last_stopped.isoformat() if self.last_stopped else None,
            "last_error": self.last_error
        }


# Predefined service configurations
SERVICE_DEFINITIONS = {
    ServiceType.FTP: {
        "name": "ftp",
        "display_name": "FTP Server (vsftpd)",
        "package_name": "vsftpd",
        "service_name": "vsftpd",
        "config_path": "/etc/vsftpd.conf",
        "port": 21,
        "protocol": "tcp",
        "default_settings": {
            "anonymous_enable": False,
            "local_enable": True,
            "write_enable": True,
            "chroot_local_user": True,
            "ssl_enable": True,
            "force_local_data_ssl": True,
            "force_local_logins_ssl": True,
            "pasv_min_port": 40000,
            "pasv_max_port": 40100
        }
    },
    ServiceType.SFTP: {
        "name": "sftp",
        "display_name": "SFTP Server (OpenSSH)",
        "package_name": "openssh-server",
        "service_name": "sshd",
        "config_path": "/etc/ssh/sshd_config",
        "port": 22,
        "protocol": "tcp",
        "default_settings": {
            "permit_root_login": False,
            "password_authentication": True,
            "pubkey_authentication": True,
            "sftp_subsystem": "/usr/lib/openssh/sftp-server",
            "chroot_directory": "/home/%u"
        }
    },
    ServiceType.SMB: {
        "name": "smb",
        "display_name": "SMB/CIFS Server (Samba)",
        "package_name": "samba",
        "service_name": "smbd",
        "config_path": "/etc/samba/smb.conf",
        "port": 445,
        "protocol": "tcp",
        "default_settings": {
            "workgroup": "WORKGROUP",
            "server_string": "File Server",
            "security": "user",
            "map_to_guest": "Bad User",
            "min_protocol": "SMB3",
            "max_protocol": "SMB3",
            "encrypt_passwords": True
        }
    },
    ServiceType.NFS: {
        "name": "nfs",
        "display_name": "NFS Server",
        "package_name": "nfs-kernel-server",
        "service_name": "nfs-kernel-server",
        "config_path": "/etc/exports",
        "port": 2049,
        "protocol": "tcp",
        "default_settings": {
            "fsid": 0,
            "secure": True,
            "rw": True,
            "async": False,
            "no_subtree_check": True
        }
    },
    ServiceType.WEBDAV: {
        "name": "webdav",
        "display_name": "WebDAV Server (Nginx)",
        "package_name": "nginx",
        "service_name": "nginx",
        "config_path": "/etc/nginx/sites-available/webdav.conf",
        "port": 443,
        "protocol": "tcp",
        "default_settings": {
            "dav_methods": ["PUT", "DELETE", "MKCOL", "COPY", "MOVE"],
            "autoindex": True,
            "client_body_temp_path": "/tmp/webdav",
            "dav_access": "user:rw group:rw all:r"
        }
    }
}