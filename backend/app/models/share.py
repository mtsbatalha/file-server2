"""
Share Model for file sharing configuration
"""

from datetime import datetime
from typing import Optional, List
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, ForeignKey, Enum as SQLEnum, JSON
from sqlalchemy.orm import relationship
import enum

from .base import Base


class ShareType(str, enum.Enum):
    """Types of shares"""
    SMB = "smb"        # Samba share
    NFS = "nfs"        # NFS export
    WEBDAV = "webdav"  # WebDAV location
    FTP = "ftp"        # FTP directory


class SharePermission(str, enum.Enum):
    """Share permission levels"""
    READ_ONLY = "ro"         # Read only
    READ_WRITE = "rw"        # Read and write
    READ_WRITE_NO_DELETE = "rwnd"  # Read/write without delete
    FULL = "full"            # Full control


class ShareAccessType(str, enum.Enum):
    """Share access type"""
    PUBLIC = "public"        # No authentication required
    PRIVATE = "private"      # Authentication required
    GUEST = "guest"          # Guest access allowed


class ShareStatus(str, enum.Enum):
    """Share status"""
    ACTIVE = "active"
    INACTIVE = "inactive"
    ERROR = "error"


class Share(Base):
    """Share model for file sharing configuration"""
    __tablename__ = 'shares'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(100), unique=True, nullable=False, index=True)
    description = Column(String(255), nullable=True)
    
    # Share type and configuration
    share_type = Column(SQLEnum(ShareType), nullable=False)
    permission = Column(SQLEnum(SharePermission), default=SharePermission.READ_WRITE, nullable=False)
    access_type = Column(SQLEnum(ShareAccessType), default=ShareAccessType.PRIVATE, nullable=False)
    status = Column(SQLEnum(ShareStatus), default=ShareStatus.ACTIVE, nullable=False)
    
    # Path configuration
    path = Column(String(500), nullable=False)  # Physical path on disk
    virtual_path = Column(String(255), nullable=True)  # Virtual path for WebDAV/NFS
    
    # Owner and permissions
    owner_id = Column(Integer, ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    owner_user = Column(String(50), nullable=True)   # System user owner
    owner_group = Column(String(50), nullable=True)  # System group owner
    mode = Column(String(10), default="0755", nullable=False)  # Unix permissions
    
    # Access control
    allowed_users = Column(JSON, default=list, nullable=True)   # List of usernames
    allowed_groups = Column(JSON, default=list, nullable=True)  # List of group names
    allowed_hosts = Column(JSON, default=list, nullable=True)   # List of allowed IPs/networks
    denied_hosts = Column(JSON, default=list, nullable=True)    # List of denied IPs/networks
    
    # Quota settings
    quota_enabled = Column(Boolean, default=False, nullable=False)
    quota_bytes = Column(Integer, default=0, nullable=False)  # 0 = unlimited
    quota_used = Column(Integer, default=0, nullable=False)
    
    # SMB-specific settings
    smb_browseable = Column(Boolean, default=True, nullable=False)
    smb_guest_ok = Column(Boolean, default=False, nullable=False)
    smb_create_mask = Column(String(10), default="0644", nullable=True)
    smb_directory_mask = Column(String(10), default="0755", nullable=True)
    smb_vfs_objects = Column(String(255), nullable=True)  # e.g., "recycle, shadow_copy"
    
    # NFS-specific settings
    nfs_options = Column(String(255), default="rw,sync,no_subtree_check", nullable=True)
    
    # WebDAV-specific settings
    webdav_methods = Column(JSON, default=lambda: ["GET", "PUT", "DELETE", "MKCOL", "COPY", "MOVE"], nullable=True)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    
    # Relationships
    owner = relationship("User", back_populates="shares")
    
    def __repr__(self):
        return f"<Share(name='{self.name}', type={self.share_type}, path='{self.path}')>"
    
    @property
    def quota_usage_percent(self) -> float:
        """Calculate quota usage percentage"""
        if not self.quota_enabled or self.quota_bytes == 0:
            return 0.0
        return (self.quota_used / self.quota_bytes) * 100
    
    def is_user_allowed(self, username: str, groups: List[str] = None) -> bool:
        """Check if user is allowed to access this share"""
        # If no restrictions, everyone is allowed
        if not self.allowed_users and not self.allowed_groups:
            return True
        
        # Check user list
        if self.allowed_users and username in self.allowed_users:
            return True
        
        # Check group list
        if self.allowed_groups and groups:
            if any(g in self.allowed_groups for g in groups):
                return True
        
        return False
    
    def is_host_allowed(self, ip_address: str) -> bool:
        """Check if host IP is allowed to access this share"""
        import ipaddress
        
        # Check denied hosts first
        if self.denied_hosts:
            for denied in self.denied_hosts:
                try:
                    if '/' in denied:
                        # Network CIDR
                        network = ipaddress.ip_network(denied, strict=False)
                        if ipaddress.ip_address(ip_address) in network:
                            return False
                    elif ip_address == denied:
                        return False
                except ValueError:
                    continue
        
        # If no allowed_hosts, all are allowed (except denied)
        if not self.allowed_hosts:
            return True
        
        # Check allowed hosts
        for allowed in self.allowed_hosts:
            try:
                if '/' in allowed:
                    network = ipaddress.ip_network(allowed, strict=False)
                    if ipaddress.ip_address(ip_address) in network:
                        return True
                elif ip_address == allowed:
                    return True
            except ValueError:
                continue
        
        return False
    
    def get_smb_config(self) -> str:
        """Generate Samba share configuration"""
        config = f"[{self.name}]\n"
        config += f"    path = {self.path}\n"
        config += f"    comment = {self.description or self.name}\n"
        config += f"    browseable = {'yes' if self.smb_browseable else 'no'}\n"
        config += f"    guest ok = {'yes' if self.smb_guest_ok or self.access_type == ShareAccessType.GUEST else 'no'}\n"
        
        # Permissions
        if self.permission == SharePermission.READ_ONLY:
            config += "    read only = yes\n"
        elif self.permission == SharePermission.READ_WRITE_NO_DELETE:
            config += "    read only = no\n"
            config += "    delete readonly = yes\n"
        else:
            config += "    read only = no\n"
        
        # Access control
        if self.allowed_users:
            config += f"    valid users = {', '.join(self.allowed_users)}\n"
        if self.allowed_groups:
            config += f"    valid users = @{', @'.join(self.allowed_groups)}\n"
        
        # File masks
        config += f"    create mask = {self.smb_create_mask}\n"
        config += f"    directory mask = {self.smb_directory_mask}\n"
        
        # VFS objects
        if self.smb_vfs_objects:
            config += f"    vfs objects = {self.smb_vfs_objects}\n"
        
        return config
    
    def get_nfs_export(self) -> str:
        """Generate NFS export configuration"""
        options = []
        
        if self.permission == SharePermission.READ_ONLY:
            options.append("ro")
        else:
            options.append("rw")
        
        # Add base options
        if self.nfs_options:
            base_opts = [o.strip() for o in self.nfs_options.split(',')]
            for opt in base_opts:
                if opt not in options:
                    options.append(opt)
        
        # Host access
        hosts = "*(rw,no_subtree_check)"  # Default
        if self.allowed_hosts:
            host_strs = []
            for host in self.allowed_hosts:
                host_strs.append(f"{host}({','.join(options)})")
            hosts = ' '.join(host_strs)
        else:
            hosts = f"*({','.join(options)})"
        
        return f"{self.path} {hosts}"
    
    def get_webdav_config(self) -> str:
        """Generate WebDAV nginx location configuration"""
        methods = ' '.join(self.webdav_methods or ['GET', 'PUT', 'DELETE', 'MKCOL', 'COPY', 'MOVE'])
        
        config = f"""
location {self.virtual_path or f'/dav/{self.name}'} {{
    alias {self.path};
    
    dav_methods {methods};
    dav_ext_methods PROPFIND OPTIONS;
    dav_access user:rw group:rw all:r;
    
    create_full_put_path on;
    autoindex {'on' if self.permission != SharePermission.READ_ONLY else 'off'};
    
    auth_basic "{self.name}";
    auth_basic_user_file /etc/nginx/.htpasswd;
    
    # Access control
    {'allow all;' if not self.allowed_hosts else ''}
    {chr(10).join([f'allow {h};' for h in self.allowed_hosts]) if self.allowed_hosts else ''}
    deny all;
}}
"""
        return config
    
    def to_dict(self) -> dict:
        """Convert share to dictionary"""
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "share_type": self.share_type.value if self.share_type else None,
            "permission": self.permission.value if self.permission else None,
            "access_type": self.access_type.value if self.access_type else None,
            "status": self.status.value if self.status else None,
            "path": self.path,
            "virtual_path": self.virtual_path,
            "owner_id": self.owner_id,
            "owner_user": self.owner_user,
            "owner_group": self.owner_group,
            "mode": self.mode,
            "allowed_users": self.allowed_users,
            "allowed_groups": self.allowed_groups,
            "allowed_hosts": self.allowed_hosts,
            "denied_hosts": self.denied_hosts,
            "quota_enabled": self.quota_enabled,
            "quota_bytes": self.quota_bytes,
            "quota_used": self.quota_used,
            "quota_usage_percent": self.quota_usage_percent,
            "smb_browseable": self.smb_browseable,
            "smb_guest_ok": self.smb_guest_ok,
            "nfs_options": self.nfs_options,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None
        }