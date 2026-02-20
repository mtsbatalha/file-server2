"""
Base Service Class
Abstract base class for all file server services
"""

import os
import re
import shutil
import subprocess
from abc import ABC, abstractmethod
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any
from enum import Enum
import logging
import json

from pydantic import BaseModel


logger = logging.getLogger(__name__)


class ServiceStatus(str, Enum):
    """Service status"""
    NOT_INSTALLED = "not_installed"
    INSTALLED = "installed"
    RUNNING = "running"
    STOPPED = "stopped"
    ERROR = "error"
    INSTALLING = "installing"
    UNINSTALLING = "uninstalling"


class ServiceResult(BaseModel):
    """Result of a service operation"""
    success: bool
    message: str
    data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    timestamp: datetime = datetime.utcnow()


class BaseService(ABC):
    """
    Abstract base class for file server services.
    Provides common functionality for installation, configuration, and management.
    """
    
    def __init__(self):
        self._detect_os()
        self.backup_dir = Path("/var/backups/fileserver-manager")
        self.backup_dir.mkdir(parents=True, exist_ok=True)
    
    def _detect_os(self) -> str:
        """Detect the operating system"""
        self.os_type = "unknown"
        self.package_manager = None
        
        # Check for Debian/Ubuntu
        if os.path.exists("/etc/debian_version"):
            self.os_type = "debian"
            self.package_manager = "apt"
            self.install_cmd = ["apt", "install", "-y"]
            self.update_cmd = ["apt", "update"]
        # Check for RHEL/CentOS/AlmaLinux
        elif os.path.exists("/etc/redhat-release"):
            self.os_type = "rhel"
            self.package_manager = "dnf"
            self.install_cmd = ["dnf", "install", "-y"]
            self.update_cmd = ["dnf", "makecache"]
        
        return self.os_type
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Service name"""
        pass
    
    @property
    @abstractmethod
    def display_name(self) -> str:
        """Human-readable service name"""
        pass
    
    @property
    @abstractmethod
    def package_name(self) -> str:
        """Package name to install"""
        pass
    
    @property
    @abstractmethod
    def service_name(self) -> str:
        """Systemd service name"""
        pass
    
    @property
    @abstractmethod
    def config_path(self) -> str:
        """Configuration file path"""
        pass
    
    @property
    @abstractmethod
    def port(self) -> int:
        """Default port"""
        pass
    
    @property
    def protocol(self) -> str:
        """Network protocol"""
        return "tcp"
    
    @property
    def default_settings(self) -> Dict[str, Any]:
        """Default service settings"""
        return {}
    
    def _run_command(
        self,
        command: List[str],
        check: bool = True,
        capture_output: bool = True,
        input_text: str = None
    ) -> subprocess.CompletedProcess:
        """Run a shell command safely"""
        try:
            result = subprocess.run(
                command,
                capture_output=capture_output,
                text=True,
                check=check,
                input=input_text
            )
            return result
        except subprocess.CalledProcessError as e:
            logger.error(f"Command failed: {' '.join(command)}")
            logger.error(f"Error: {e.stderr}")
            raise
    
    def _backup_file(self, filepath: str) -> Optional[str]:
        """Create a backup of a file before modifying"""
        if not os.path.exists(filepath):
            return None
        
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        backup_name = f"{Path(filepath).name}.{timestamp}.bak"
        backup_path = self.backup_dir / backup_name
        
        shutil.copy2(filepath, backup_path)
        logger.info(f"Backed up {filepath} to {backup_path}")
        
        return str(backup_path)
    
    def _write_config(self, content: str, filepath: str = None) -> bool:
        """Write configuration to file"""
        filepath = filepath or self.config_path
        
        # Backup existing config
        if os.path.exists(filepath):
            self._backup_file(filepath)
        
        # Ensure directory exists
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        
        with open(filepath, 'w') as f:
            f.write(content)
        
        logger.info(f"Wrote configuration to {filepath}")
        return True
    
    def _read_config(self, filepath: str = None) -> Optional[str]:
        """Read configuration from file"""
        filepath = filepath or self.config_path
        
        if not os.path.exists(filepath):
            return None
        
        with open(filepath, 'r') as f:
            return f.read()
    
    def is_installed(self) -> bool:
        """Check if the service is installed"""
        # Check if package is installed
        try:
            if self.package_manager == "apt":
                result = self._run_command(
                    ["dpkg", "-l", self.package_name],
                    check=False
                )
                return result.returncode == 0
            elif self.package_manager == "dnf":
                result = self._run_command(
                    ["rpm", "-q", self.package_name],
                    check=False
                )
                return result.returncode == 0
        except Exception:
            pass
        
        return False
    
    def get_status(self) -> ServiceStatus:
        """Get current service status"""
        if not self.is_installed():
            return ServiceStatus.NOT_INSTALLED
        
        try:
            result = self._run_command(
                ["systemctl", "is-active", self.service_name],
                check=False
            )
            
            if result.returncode == 0:
                return ServiceStatus.RUNNING
            else:
                return ServiceStatus.STOPPED
                
        except Exception as e:
            logger.error(f"Error checking service status: {e}")
            return ServiceStatus.ERROR
    
    def is_enabled(self) -> bool:
        """Check if service is enabled at boot"""
        try:
            result = self._run_command(
                ["systemctl", "is-enabled", self.service_name],
                check=False
            )
            return result.returncode == 0
        except Exception:
            return False
    
    def install(self, settings: Dict[str, Any] = None) -> ServiceResult:
        """Install the service"""
        if self.is_installed():
            return ServiceResult(
                success=False,
                message=f"{self.display_name} is already installed"
            )
        
        try:
            # Update package cache
            if self.update_cmd:
                self._run_command(self.update_cmd, check=False)
            
            # Install package
            install_cmd = self.install_cmd + [self.package_name]
            self._run_command(install_cmd)
            
            # Apply configuration
            settings = settings or self.default_settings
            self.configure(settings)
            
            # Enable service
            self.enable()
            
            logger.info(f"Successfully installed {self.display_name}")
            
            return ServiceResult(
                success=True,
                message=f"Successfully installed {self.display_name}",
                data={
                    "package": self.package_name,
                    "config_path": self.config_path,
                    "port": self.port
                }
            )
            
        except Exception as e:
            logger.error(f"Failed to install {self.display_name}: {e}")
            return ServiceResult(
                success=False,
                message=f"Failed to install {self.display_name}",
                error=str(e)
            )
    
    def uninstall(self, purge: bool = False) -> ServiceResult:
        """Uninstall the service"""
        if not self.is_installed():
            return ServiceResult(
                success=False,
                message=f"{self.display_name} is not installed"
            )
        
        try:
            # Stop service first
            self.stop()
            
            # Disable service
            self.disable()
            
            # Remove package
            if self.package_manager == "apt":
                cmd = ["apt", "purge", "-y"] if purge else ["apt", "remove", "-y"]
                self._run_command(cmd + [self.package_name])
            elif self.package_manager == "dnf":
                cmd = ["dnf", "remove", "-y"]
                self._run_command(cmd + [self.package_name])
            
            # Remove config if purge
            if purge and os.path.exists(self.config_path):
                os.remove(self.config_path)
            
            logger.info(f"Successfully uninstalled {self.display_name}")
            
            return ServiceResult(
                success=True,
                message=f"Successfully uninstalled {self.display_name}"
            )
            
        except Exception as e:
            logger.error(f"Failed to uninstall {self.display_name}: {e}")
            return ServiceResult(
                success=False,
                message=f"Failed to uninstall {self.display_name}",
                error=str(e)
            )
    
    def start(self) -> ServiceResult:
        """Start the service"""
        if not self.is_installed():
            return ServiceResult(
                success=False,
                message=f"{self.display_name} is not installed"
            )
        
        try:
            self._run_command(["systemctl", "start", self.service_name])
            
            logger.info(f"Started {self.display_name}")
            
            return ServiceResult(
                success=True,
                message=f"Started {self.display_name}"
            )
            
        except Exception as e:
            logger.error(f"Failed to start {self.display_name}: {e}")
            return ServiceResult(
                success=False,
                message=f"Failed to start {self.display_name}",
                error=str(e)
            )
    
    def stop(self) -> ServiceResult:
        """Stop the service"""
        if not self.is_installed():
            return ServiceResult(
                success=False,
                message=f"{self.display_name} is not installed"
            )
        
        try:
            self._run_command(["systemctl", "stop", self.service_name])
            
            logger.info(f"Stopped {self.display_name}")
            
            return ServiceResult(
                success=True,
                message=f"Stopped {self.display_name}"
            )
            
        except Exception as e:
            logger.error(f"Failed to stop {self.display_name}: {e}")
            return ServiceResult(
                success=False,
                message=f"Failed to stop {self.display_name}",
                error=str(e)
            )
    
    def restart(self) -> ServiceResult:
        """Restart the service"""
        if not self.is_installed():
            return ServiceResult(
                success=False,
                message=f"{self.display_name} is not installed"
            )
        
        try:
            self._run_command(["systemctl", "restart", self.service_name])
            
            logger.info(f"Restarted {self.display_name}")
            
            return ServiceResult(
                success=True,
                message=f"Restarted {self.display_name}"
            )
            
        except Exception as e:
            logger.error(f"Failed to restart {self.display_name}: {e}")
            return ServiceResult(
                success=False,
                message=f"Failed to restart {self.display_name}",
                error=str(e)
            )
    
    def reload(self) -> ServiceResult:
        """Reload service configuration"""
        if not self.is_installed():
            return ServiceResult(
                success=False,
                message=f"{self.display_name} is not installed"
            )
        
        try:
            self._run_command(["systemctl", "reload", self.service_name])
            
            logger.info(f"Reloaded {self.display_name}")
            
            return ServiceResult(
                success=True,
                message=f"Reloaded {self.display_name}"
            )
            
        except Exception as e:
            # Some services don't support reload, try restart
            logger.warning(f"Reload not supported, restarting: {e}")
            return self.restart()
    
    def enable(self) -> ServiceResult:
        """Enable service at boot"""
        if not self.is_installed():
            return ServiceResult(
                success=False,
                message=f"{self.display_name} is not installed"
            )
        
        try:
            self._run_command(["systemctl", "enable", self.service_name])
            
            logger.info(f"Enabled {self.display_name} at boot")
            
            return ServiceResult(
                success=True,
                message=f"Enabled {self.display_name} at boot"
            )
            
        except Exception as e:
            logger.error(f"Failed to enable {self.display_name}: {e}")
            return ServiceResult(
                success=False,
                message=f"Failed to enable {self.display_name}",
                error=str(e)
            )
    
    def disable(self) -> ServiceResult:
        """Disable service at boot"""
        if not self.is_installed():
            return ServiceResult(
                success=False,
                message=f"{self.display_name} is not installed"
            )
        
        try:
            self._run_command(["systemctl", "disable", self.service_name])
            
            logger.info(f"Disabled {self.display_name} at boot")
            
            return ServiceResult(
                success=True,
                message=f"Disabled {self.display_name} at boot"
            )
            
        except Exception as e:
            logger.error(f"Failed to disable {self.display_name}: {e}")
            return ServiceResult(
                success=False,
                message=f"Failed to disable {self.display_name}",
                error=str(e)
            )
    
    @abstractmethod
    def configure(self, settings: Dict[str, Any]) -> ServiceResult:
        """
        Configure the service.
        Must be implemented by each service.
        """
        pass
    
    @abstractmethod
    def get_config(self) -> Dict[str, Any]:
        """
        Get current configuration.
        Must be implemented by each service.
        """
        pass
    
    def get_info(self) -> Dict[str, Any]:
        """Get comprehensive service information"""
        return {
            "name": self.name,
            "display_name": self.display_name,
            "package_name": self.package_name,
            "service_name": self.service_name,
            "config_path": self.config_path,
            "port": self.port,
            "protocol": self.protocol,
            "is_installed": self.is_installed(),
            "status": self.get_status().value,
            "is_enabled": self.is_enabled(),
            "default_settings": self.default_settings,
            "current_config": self.get_config() if self.is_installed() else None
        }
    
    def get_logs(self, lines: int = 100) -> str:
        """Get service logs"""
        try:
            result = self._run_command(
                ["journalctl", "-u", self.service_name, "-n", str(lines), "--no-pager"]
            )
            return result.stdout
        except Exception as e:
            return f"Error retrieving logs: {e}"
    
    def validate_config(self) -> Dict[str, Any]:
        """Validate service configuration"""
        result = {
            "valid": True,
            "errors": [],
            "warnings": []
        }
        
        # Check if config file exists
        if not os.path.exists(self.config_path):
            result["valid"] = False
            result["errors"].append(f"Configuration file not found: {self.config_path}")
            return result
        
        # Check file permissions
        stat_info = os.stat(self.config_path)
        if stat_info.st_mode & 0o077:
            result["warnings"].append(
                f"Configuration file has group/world permissions"
            )
        
        return result
    
    def get_version(self) -> Optional[str]:
        """Get installed version"""
        try:
            if self.package_manager == "apt":
                result = self._run_command(
                    ["dpkg", "-s", self.package_name],
                    check=False
                )
                for line in result.stdout.split('\n'):
                    if line.startswith("Version:"):
                        return line.split()[1]
            elif self.package_manager == "dnf":
                result = self._run_command(
                    ["rpm", "-q", "--queryformat", "%{VERSION}-%{RELEASE}", self.package_name],
                    check=False
                )
                if result.returncode == 0:
                    return result.stdout.strip()
        except Exception:
            pass
        
        return None