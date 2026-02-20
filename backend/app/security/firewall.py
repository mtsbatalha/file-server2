"""
Firewall Manager
Unified interface for UFW and firewalld
"""

import os
import subprocess
from datetime import datetime
from typing import Dict, List, Optional, Any
from enum import Enum
import logging

from pydantic import BaseModel


logger = logging.getLogger(__name__)


class FirewallAction(str, Enum):
    """Firewall actions"""
    ALLOW = "allow"
    DENY = "deny"
    REJECT = "reject"
    LIMIT = "limit"


class Protocol(str, Enum):
    """Network protocols"""
    TCP = "tcp"
    UDP = "udp"
    BOTH = "both"


class FirewallRule(BaseModel):
    """Firewall rule model"""
    id: Optional[str] = None
    port: Optional[int] = None
    port_range: Optional[str] = None  # e.g., "40000:40100"
    protocol: Protocol = Protocol.TCP
    action: FirewallAction = FirewallAction.ALLOW
    source: Optional[str] = None  # IP or CIDR
    destination: Optional[str] = None
    service: Optional[str] = None  # e.g., "ssh", "http"
    comment: Optional[str] = None
    enabled: bool = True
    direction: str = "in"  # in or out


class FirewallStatus(BaseModel):
    """Firewall status model"""
    enabled: bool
    default_incoming: str
    default_outgoing: str
    rules: List[Dict[str, Any]]
    active_zones: List[str] = []


class FirewallManager:
    """
    Unified firewall management for UFW and firewalld.
    Supports Debian/Ubuntu (UFW) and RHEL/AlmaLinux (firewalld).
    """
    
    def __init__(self):
        self._detect_firewall()
    
    def _detect_firewall(self) -> str:
        """Detect available firewall"""
        self.firewall_type = None
        
        # Check for UFW (Debian/Ubuntu)
        if self._command_exists("ufw"):
            self.firewall_type = "ufw"
        # Check for firewalld (RHEL/AlmaLinux)
        elif self._command_exists("firewall-cmd"):
            self.firewall_type = "firewalld"
        # Check for iptables as fallback
        elif self._command_exists("iptables"):
            self.firewall_type = "iptables"
        
        return self.firewall_type
    
    def _command_exists(self, command: str) -> bool:
        """Check if a command exists"""
        try:
            subprocess.run(
                ["which", command],
                capture_output=True,
                check=True
            )
            return True
        except subprocess.CalledProcessError:
            return False
    
    def _run_command(
        self,
        command: List[str],
        check: bool = True
    ) -> subprocess.CompletedProcess:
        """Run a shell command"""
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=check
            )
            return result
        except subprocess.CalledProcessError as e:
            logger.error(f"Command failed: {' '.join(command)}")
            logger.error(f"Error: {e.stderr}")
            raise
    
    def is_available(self) -> bool:
        """Check if firewall management is available"""
        return self.firewall_type is not None
    
    def get_status(self) -> FirewallStatus:
        """Get current firewall status"""
        if self.firewall_type == "ufw":
            return self._get_ufw_status()
        elif self.firewall_type == "firewalld":
            return self._get_firewalld_status()
        else:
            raise RuntimeError("No supported firewall found")
    
    def _get_ufw_status(self) -> FirewallStatus:
        """Get UFW status"""
        result = self._run_command(["ufw", "status", "verbose"], check=False)
        output = result.stdout
        
        enabled = "Status: active" in output
        
        # Parse default policies
        default_incoming = "deny"
        default_outgoing = "allow"
        
        for line in output.split('\n'):
            if "Default:" in line:
                parts = line.split()
                if len(parts) >= 4:
                    default_incoming = parts[1]
                    default_outgoing = parts[3]
        
        # Parse rules
        rules = []
        in_rules = False
        for line in output.split('\n'):
            if in_rules and line.strip():
                parts = line.split()
                if len(parts) >= 2:
                    rule = {
                        "port": parts[0],
                        "action": parts[1] if len(parts) > 1 else "allow",
                        "protocol": "tcp" if "/" not in parts[0] else parts[0].split("/")[1],
                    }
                    if len(parts) > 2:
                        rule["source"] = parts[2]
                    rules.append(rule)
            if "----" in line:
                in_rules = True
        
        return FirewallStatus(
            enabled=enabled,
            default_incoming=default_incoming,
            default_outgoing=default_outgoing,
            rules=rules
        )
    
    def _get_firewalld_status(self) -> FirewallStatus:
        """Get firewalld status"""
        result = self._run_command(["firewall-cmd", "--state"], check=False)
        enabled = "running" in result.stdout
        
        # Get default zone
        result = self._run_command(["firewall-cmd", "--get-default-zone"])
        default_zone = result.stdout.strip()
        
        # Get active zones
        result = self._run_command(["firewall-cmd", "--get-active-zones"])
        active_zones = [z.strip() for z in result.stdout.strip().split('\n') if z.strip()]
        
        # Get rules for default zone
        rules = []
        result = self._run_command(["firewall-cmd", "--list-all"])
        
        for line in result.stdout.split('\n'):
            line = line.strip()
            if line.startswith("ports:"):
                ports = line.replace("ports:", "").strip().split()
                for port in ports:
                    rules.append({"port": port.split('/')[0], "protocol": port.split('/')[1] if '/' in port else "tcp", "action": "allow"})
            elif line.startswith("services:"):
                services = line.replace("services:", "").strip().split()
                for service in services:
                    rules.append({"service": service, "action": "allow"})
        
        return FirewallStatus(
            enabled=enabled,
            default_incoming="deny",
            default_outgoing="allow",
            rules=rules,
            active_zones=active_zones
        )
    
    def enable(self) -> bool:
        """Enable the firewall"""
        if self.firewall_type == "ufw":
            self._run_command(["ufw", "--force", "enable"])
            logger.info("UFW firewall enabled")
            return True
        elif self.firewall_type == "firewalld":
            self._run_command(["systemctl", "start", "firewalld"])
            self._run_command(["systemctl", "enable", "firewalld"])
            logger.info("Firewalld enabled")
            return True
        return False
    
    def disable(self) -> bool:
        """Disable the firewall"""
        if self.firewall_type == "ufw":
            self._run_command(["ufw", "disable"])
            logger.info("UFW firewall disabled")
            return True
        elif self.firewall_type == "firewalld":
            self._run_command(["systemctl", "stop", "firewalld"])
            self._run_command(["systemctl", "disable", "firewalld"])
            logger.info("Firewalld disabled")
            return True
        return False
    
    def add_rule(self, rule: FirewallRule) -> bool:
        """Add a firewall rule"""
        if self.firewall_type == "ufw":
            return self._add_ufw_rule(rule)
        elif self.firewall_type == "firewalld":
            return self._add_firewalld_rule(rule)
        return False
    
    def _add_ufw_rule(self, rule: FirewallRule) -> bool:
        """Add a UFW rule"""
        cmd = ["ufw"]
        
        # Build command
        if rule.direction == "out":
            cmd.append("route")
        
        cmd.append(rule.action.value)
        
        if rule.source:
            cmd.extend(["from", rule.source])
        
        if rule.port:
            cmd.extend(["to", "any", "port", str(rule.port)])
        elif rule.port_range:
            cmd.extend(["to", "any", "port", rule.port_range])
        elif rule.service:
            cmd.extend(["to", "any", "port", rule.service])
        
        if rule.protocol != Protocol.BOTH:
            cmd.append("proto")
            cmd.append(rule.protocol.value)
        
        if rule.comment:
            cmd.extend(["comment", rule.comment])
        
        self._run_command(cmd)
        logger.info(f"Added UFW rule: {rule}")
        return True
    
    def _add_firewalld_rule(self, rule: FirewallRule) -> bool:
        """Add a firewalld rule"""
        zone = "public"
        
        if rule.service:
            cmd = ["firewall-cmd", "--permanent", f"--add-service={rule.service}", f"--zone={zone}"]
        elif rule.port:
            proto = rule.protocol.value if rule.protocol != Protocol.BOTH else "tcp"
            cmd = ["firewall-cmd", "--permanent", f"--add-port={rule.port}/{proto}", f"--zone={zone}"]
        elif rule.port_range:
            proto = rule.protocol.value if rule.protocol != Protocol.BOTH else "tcp"
            cmd = ["firewall-cmd", "--permanent", f"--add-port={rule.port_range}/{proto}", f"--zone={zone}"]
        else:
            return False
        
        if rule.source:
            cmd.extend([f"--add-rich-rule=rule family=ipv4 source address={rule.source} {'accept' if rule.action == FirewallAction.ALLOW else 'drop'}"])
        
        self._run_command(cmd)
        self._run_command(["firewall-cmd", "--reload"])
        logger.info(f"Added firewalld rule: {rule}")
        return True
    
    def remove_rule(self, rule: FirewallRule) -> bool:
        """Remove a firewall rule"""
        if self.firewall_type == "ufw":
            return self._remove_ufw_rule(rule)
        elif self.firewall_type == "firewalld":
            return self._remove_firewalld_rule(rule)
        return False
    
    def _remove_ufw_rule(self, rule: FirewallRule) -> bool:
        """Remove a UFW rule"""
        cmd = ["ufw", "delete"]
        
        # Build command based on rule number or specification
        if rule.id:
            self._run_command(["ufw", "--force", "delete", rule.id], check=False)
        else:
            # Delete by rule spec
            delete_cmd = ["ufw", "delete", rule.action.value]
            if rule.port:
                delete_cmd.append(str(rule.port))
            if rule.protocol != Protocol.BOTH:
                delete_cmd.append("proto")
                delete_cmd.append(rule.protocol.value)
            self._run_command(delete_cmd, check=False)
        
        logger.info(f"Removed UFW rule: {rule}")
        return True
    
    def _remove_firewalld_rule(self, rule: FirewallRule) -> bool:
        """Remove a firewalld rule"""
        zone = "public"
        
        if rule.service:
            cmd = ["firewall-cmd", "--permanent", f"--remove-service={rule.service}", f"--zone={zone}"]
        elif rule.port:
            proto = rule.protocol.value if rule.protocol != Protocol.BOTH else "tcp"
            cmd = ["firewall-cmd", "--permanent", f"--remove-port={rule.port}/{proto}", f"--zone={zone}"]
        elif rule.port_range:
            proto = rule.protocol.value if rule.protocol != Protocol.BOTH else "tcp"
            cmd = ["firewall-cmd", "--permanent", f"--remove-port={rule.port_range}/{proto}", f"--zone={zone}"]
        else:
            return False
        
        self._run_command(cmd, check=False)
        self._run_command(["firewall-cmd", "--reload"])
        logger.info(f"Removed firewalld rule: {rule}")
        return True
    
    def allow_port(
        self,
        port: int,
        protocol: Protocol = Protocol.TCP,
        source: str = None,
        comment: str = None
    ) -> bool:
        """Allow a port"""
        rule = FirewallRule(
            port=port,
            protocol=protocol,
            action=FirewallAction.ALLOW,
            source=source,
            comment=comment
        )
        return self.add_rule(rule)
    
    def deny_port(
        self,
        port: int,
        protocol: Protocol = Protocol.TCP,
        source: str = None,
        comment: str = None
    ) -> bool:
        """Deny a port"""
        rule = FirewallRule(
            port=port,
            protocol=protocol,
            action=FirewallAction.DENY,
            source=source,
            comment=comment
        )
        return self.add_rule(rule)
    
    def allow_service(self, service: str, source: str = None) -> bool:
        """Allow a service by name"""
        rule = FirewallRule(
            service=service,
            action=FirewallAction.ALLOW,
            source=source
        )
        return self.add_rule(rule)
    
    def set_default_policy(self, direction: str, policy: str) -> bool:
        """Set default policy for incoming/outgoing"""
        if self.firewall_type == "ufw":
            cmd = ["ufw", "default", policy, direction]
            self._run_command(cmd)
            logger.info(f"Set default policy: {direction} {policy}")
            return True
        return False
    
    def get_allowed_ports(self) -> List[int]:
        """Get list of allowed ports"""
        status = self.get_status()
        ports = []
        for rule in status.rules:
            if rule.get("action") == "allow" and rule.get("port"):
                try:
                    ports.append(int(rule["port"]))
                except ValueError:
                    pass
        return ports
    
    def reset(self) -> bool:
        """Reset firewall to defaults"""
        if self.firewall_type == "ufw":
            self._run_command(["ufw", "--force", "reset"])
            self._run_command(["ufw", "default", "deny", "incoming"])
            self._run_command(["ufw", "default", "allow", "outgoing"])
            logger.info("UFW firewall reset to defaults")
            return True
        elif self.firewall_type == "firewalld":
            self._run_command(["firewall-cmd", "--permanent", "--reset-to-defaults"])
            self._run_command(["firewall-cmd", "--reload"])
            logger.info("Firewalld reset to defaults")
            return True
        return False
    
    def setup_fileserver_rules(self, services: List[str] = None) -> Dict[str, bool]:
        """Setup firewall rules for file server services"""
        results = {}
        
        # Default services
        default_services = {
            "ssh": 22,
            "ftp": 21,
            "ftp_data": 20,
            "sftp": 22,
            "smb": [139, 445],
            "nfs": [111, 2049],
            "webdav": [80, 443],
            "passive_ftp": "40000:40100"
        }
        
        if services is None:
            services = ["ssh"]
        
        for service in services:
            service_lower = service.lower()
            
            if service_lower in default_services:
                port = default_services[service_lower]
                
                if isinstance(port, list):
                    for p in port:
                        results[f"{service_lower}_{p}"] = self.allow_port(
                            p, comment=f"{service_lower} service"
                        )
                elif isinstance(port, str):  # Port range
                    rule = FirewallRule(
                        port_range=port,
                        protocol=Protocol.TCP,
                        action=FirewallAction.ALLOW,
                        comment=f"{service_lower} service"
                    )
                    results[service_lower] = self.add_rule(rule)
                else:
                    results[service_lower] = self.allow_port(
                        port, comment=f"{service_lower} service"
                    )
        
        return results


# Convenience function
def get_firewall_manager() -> FirewallManager:
    """Get firewall manager instance"""
    return FirewallManager()