"""
Service Manager
Unified management for all file server services
"""

from typing import Dict, List, Any, Optional, Type
import logging

from .base import BaseService, ServiceResult, ServiceStatus
from .ftp import FTPService
from .sftp import SFTPService
from .smb import SMBService
from .nfs import NFSService
from .webdav import WebDAVService


logger = logging.getLogger(__name__)


class ServiceManager:
    """
    Unified service manager for all file server services.
    Provides a single interface for managing multiple services.
    """
    
    def __init__(self):
        self._services: Dict[str, BaseService] = {}
        self._register_services()
    
    def _register_services(self) -> None:
        """Register all available services"""
        service_classes: List[Type[BaseService]] = [
            FTPService,
            SFTPService,
            SMBService,
            NFSService,
            WebDAVService
        ]
        
        for service_class in service_classes:
            service = service_class()
            self._services[service.name] = service
    
    def get_service(self, name: str) -> Optional[BaseService]:
        """Get a service by name"""
        return self._services.get(name.lower())
    
    def get_all_services(self) -> Dict[str, BaseService]:
        """Get all registered services"""
        return self._services
    
    def list_services(self) -> List[Dict[str, Any]]:
        """List all services with their status"""
        services = []
        
        for name, service in self._services.items():
            services.append({
                "name": name,
                "display_name": service.display_name,
                "package_name": service.package_name,
                "port": service.port,
                "protocol": service.protocol,
                "is_installed": service.is_installed(),
                "status": service.get_status().value,
                "is_enabled": service.is_enabled()
            })
        
        return services
    
    def get_services_status(self) -> Dict[str, Any]:
        """Get status summary of all services"""
        status_counts = {
            "total": len(self._services),
            "running": 0,
            "stopped": 0,
            "not_installed": 0,
            "error": 0
        }
        
        services_by_status = {
            "running": [],
            "stopped": [],
            "not_installed": [],
            "error": []
        }
        
        for name, service in self._services.items():
            status = service.get_status()
            
            if status == ServiceStatus.RUNNING:
                status_counts["running"] += 1
                services_by_status["running"].append(name)
            elif status == ServiceStatus.STOPPED:
                status_counts["stopped"] += 1
                services_by_status["stopped"].append(name)
            elif status == ServiceStatus.NOT_INSTALLED:
                status_counts["not_installed"] += 1
                services_by_status["not_installed"].append(name)
            else:
                status_counts["error"] += 1
                services_by_status["error"].append(name)
        
        return {
            "counts": status_counts,
            "services": services_by_status
        }
    
    def install_service(
        self,
        name: str,
        settings: Dict[str, Any] = None
    ) -> ServiceResult:
        """Install a specific service"""
        service = self.get_service(name)
        
        if not service:
            return ServiceResult(
                success=False,
                message=f"Unknown service: {name}"
            )
        
        return service.install(settings)
    
    def install_all(self, settings: Dict[str, Dict[str, Any]] = None) -> Dict[str, ServiceResult]:
        """Install all services"""
        results = {}
        settings = settings or {}
        
        for name, service in self._services.items():
            service_settings = settings.get(name, {})
            results[name] = service.install(service_settings)
        
        return results
    
    def install_selected(
        self,
        services: List[str],
        settings: Dict[str, Dict[str, Any]] = None
    ) -> Dict[str, ServiceResult]:
        """Install selected services"""
        results = {}
        settings = settings or {}
        
        for name in services:
            service = self.get_service(name)
            if service:
                service_settings = settings.get(name, {})
                results[name] = service.install(service_settings)
            else:
                results[name] = ServiceResult(
                    success=False,
                    message=f"Unknown service: {name}"
                )
        
        return results
    
    def uninstall_service(self, name: str, purge: bool = False) -> ServiceResult:
        """Uninstall a specific service"""
        service = self.get_service(name)
        
        if not service:
            return ServiceResult(
                success=False,
                message=f"Unknown service: {name}"
            )
        
        return service.uninstall(purge)
    
    def start_service(self, name: str) -> ServiceResult:
        """Start a specific service"""
        service = self.get_service(name)
        
        if not service:
            return ServiceResult(
                success=False,
                message=f"Unknown service: {name}"
            )
        
        return service.start()
    
    def stop_service(self, name: str) -> ServiceResult:
        """Stop a specific service"""
        service = self.get_service(name)
        
        if not service:
            return ServiceResult(
                success=False,
                message=f"Unknown service: {name}"
            )
        
        return service.stop()
    
    def restart_service(self, name: str) -> ServiceResult:
        """Restart a specific service"""
        service = self.get_service(name)
        
        if not service:
            return ServiceResult(
                success=False,
                message=f"Unknown service: {name}"
            )
        
        return service.restart()
    
    def start_all(self) -> Dict[str, ServiceResult]:
        """Start all installed services"""
        results = {}
        
        for name, service in self._services.items():
            if service.is_installed():
                results[name] = service.start()
        
        return results
    
    def stop_all(self) -> Dict[str, ServiceResult]:
        """Stop all running services"""
        results = {}
        
        for name, service in self._services.items():
            if service.get_status() == ServiceStatus.RUNNING:
                results[name] = service.stop()
        
        return results
    
    def get_service_info(self, name: str) -> Optional[Dict[str, Any]]:
        """Get detailed info for a specific service"""
        service = self.get_service(name)
        
        if not service:
            return None
        
        return service.get_info()
    
    def get_service_config(self, name: str) -> Optional[Dict[str, Any]]:
        """Get configuration for a specific service"""
        service = self.get_service(name)
        
        if not service:
            return None
        
        return service.get_config()
    
    def configure_service(
        self,
        name: str,
        settings: Dict[str, Any]
    ) -> ServiceResult:
        """Configure a specific service"""
        service = self.get_service(name)
        
        if not service:
            return ServiceResult(
                success=False,
                message=f"Unknown service: {name}"
            )
        
        return service.configure(settings)
    
    def get_service_logs(self, name: str, lines: int = 100) -> Optional[str]:
        """Get logs for a specific service"""
        service = self.get_service(name)
        
        if not service:
            return None
        
        return service.get_logs(lines)
    
    def validate_service_config(self, name: str) -> Optional[Dict[str, Any]]:
        """Validate configuration for a specific service"""
        service = self.get_service(name)
        
        if not service:
            return None
        
        return service.validate_config()
    
    def get_all_connections(self) -> Dict[str, List[Dict[str, Any]]]:
        """Get connections for all running services"""
        connections = {}
        
        for name, service in self._services.items():
            if service.get_status() == ServiceStatus.RUNNING:
                try:
                    service_connections = service.get_connections()
                    if service_connections:
                        connections[name] = service_connections
                except Exception:
                    pass
        
        return connections
    
    def get_resource_usage(self) -> Dict[str, Any]:
        """Get resource usage summary"""
        import psutil
        import shutil
        
        usage = {
            "cpu": {
                "percent": psutil.cpu_percent(interval=1),
                "count": psutil.cpu_count(),
                "load_avg": list(psutil.getloadavg()) if hasattr(psutil, 'getloadavg') else None
            },
            "memory": {
                "total": psutil.virtual_memory().total,
                "available": psutil.virtual_memory().available,
                "used": psutil.virtual_memory().used,
                "percent": psutil.virtual_memory().percent
            },
            "disk": {},
            "network": {
                "bytes_sent": psutil.net_io_counters().bytes_sent,
                "bytes_recv": psutil.net_io_counters().bytes_recv,
                "packets_sent": psutil.net_io_counters().packets_sent,
                "packets_recv": psutil.net_io_counters().packets_recv
            }
        }
        
        # Disk usage for common mount points
        for partition in psutil.disk_partitions():
            try:
                usage_info = shutil.disk_usage(partition.mountpoint)
                usage["disk"][partition.mountpoint] = {
                    "total": usage_info.total,
                    "used": usage_info.used,
                    "free": usage_info.free,
                    "percent": (usage_info.used / usage_info.total) * 100
                }
            except PermissionError:
                continue
        
        return usage
    
    def health_check(self) -> Dict[str, Any]:
        """Perform a health check on all services"""
        health = {
            "overall_status": "healthy",
            "services": {},
            "issues": []
        }
        
        for name, service in self._services.items():
            service_health = {
                "name": name,
                "status": service.get_status().value,
                "installed": service.is_installed(),
                "enabled": service.is_enabled(),
                "issues": []
            }
            
            # Check for issues
            if service.is_installed():
                status = service.get_status()
                
                if status == ServiceStatus.ERROR:
                    service_health["issues"].append("Service is in error state")
                    health["issues"].append(f"{name}: Service is in error state")
                    health["overall_status"] = "degraded"
                
                elif status == ServiceStatus.STOPPED:
                    if service.is_enabled():
                        service_health["issues"].append("Service is enabled but stopped")
                        health["issues"].append(f"{name}: Service is enabled but stopped")
            
            health["services"][name] = service_health
        
        return health


# Singleton instance
_service_manager: Optional[ServiceManager] = None


def get_service_manager() -> ServiceManager:
    """Get the service manager singleton"""
    global _service_manager
    if _service_manager is None:
        _service_manager = ServiceManager()
    return _service_manager