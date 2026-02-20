"""
System Hardening Service
Applies security best practices automatically
"""

import os
import re
import shutil
import subprocess
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any
from pathlib import Path
import logging

from pydantic import BaseModel


logger = logging.getLogger(__name__)


class HardeningReport(BaseModel):
    """Report of hardening actions applied"""
    category: str
    action: str
    status: str  # success, failed, skipped
    message: str
    details: Optional[Dict[str, Any]] = None
    timestamp: datetime = datetime.utcnow()


class HardeningConfig(BaseModel):
    """Hardening configuration"""
    # SSH Hardening
    ssh_disable_root_login: bool = True
    ssh_disable_password_auth: bool = False
    ssh_disable_empty_passwords: bool = True
    ssh_max_auth_tries: int = 3
    ssh_port: int = 22
    ssh_allow_groups: List[str] = []
    ssh_permit_root_login: str = "no"
    
    # FTP Hardening
    ftp_require_tls: bool = True
    ftp_disable_anonymous: bool = True
    ftp_chroot_users: bool = True
    ftp_pasv_ports: Tuple[int, int] = (40000, 40100)
    
    # SMB Hardening
    smb_min_protocol: str = "SMB3"
    smb_disable_guest: bool = True
    smb_encrypt_data: bool = True
    smb_signing_required: bool = True
    
    # Firewall
    firewall_enabled: bool = True
    firewall_default_policy: str = "deny"
    firewall_allowed_ports: List[int] = [22, 80, 443, 445, 21]
    
    # Fail2ban
    fail2ban_enabled: bool = True
    fail2ban_max_retries: int = 5
    fail2ban_ban_time: int = 3600  # 1 hour
    fail2ban_find_time: int = 600  # 10 minutes
    
    # General
    disable_root_account: bool = False
    enable_auto_updates: bool = True
    set_hostname: Optional[str] = None
    configure_timezone: str = "UTC"
    
    # TLS/SSL
    tls_enabled: bool = False
    tls_cert_path: Optional[str] = None
    tls_key_path: Optional[str] = None
    tls_generate_self_signed: bool = True
    tls_country: str = "US"
    tls_state: str = "State"
    tls_city: str = "City"
    tls_org: str = "Organization"
    tls_cn: str = "fileserver.local"


class HardeningService:
    """
    Service for applying system hardening measures.
    Supports both Debian/Ubuntu and RHEL/AlmaLinux.
    """
    
    def __init__(self, config: HardeningConfig = None):
        self.config = config or HardeningConfig()
        self.reports: List[HardeningReport] = []
        self.backup_dir = Path("/var/backups/fileserver-manager")
        self._detect_os()
    
    def _detect_os(self) -> str:
        """Detect the operating system"""
        self.os_type = "unknown"
        
        # Check for Debian/Ubuntu
        if os.path.exists("/etc/debian_version"):
            self.os_type = "debian"
            self.package_manager = "apt"
            self.firewall_type = "ufw"
        # Check for RHEL/CentOS/AlmaLinux
        elif os.path.exists("/etc/redhat-release"):
            self.os_type = "rhel"
            self.package_manager = "dnf"
            self.firewall_type = "firewalld"
        
        return self.os_type
    
    def _run_command(
        self,
        command: List[str],
        check: bool = True,
        capture_output: bool = True
    ) -> subprocess.CompletedProcess:
        """Run a shell command safely"""
        try:
            result = subprocess.run(
                command,
                capture_output=capture_output,
                text=True,
                check=check
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
        
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        backup_name = f"{Path(filepath).name}.{timestamp}.bak"
        backup_path = self.backup_dir / backup_name
        
        shutil.copy2(filepath, backup_path)
        logger.info(f"Backed up {filepath} to {backup_path}")
        
        return str(backup_path)
    
    def _report(
        self,
        category: str,
        action: str,
        status: str,
        message: str,
        details: Dict = None
    ) -> HardeningReport:
        """Create and store a hardening report"""
        report = HardeningReport(
            category=category,
            action=action,
            status=status,
            message=message,
            details=details
        )
        self.reports.append(report)
        return report
    
    def apply_all(self) -> List[HardeningReport]:
        """Apply all hardening measures"""
        logger.info("Starting full system hardening...")
        
        # Apply each category
        self.harden_ssh()
        self.harden_firewall()
        self.setup_fail2ban()
        self.configure_auto_updates()
        self.harden_kernel()
        self.setup_tls()
        
        logger.info(f"Hardening complete. {len(self.reports)} actions performed.")
        return self.reports
    
    def harden_ssh(self) -> HardeningReport:
        """Apply SSH hardening configuration"""
        sshd_config = "/etc/ssh/sshd_config"
        
        try:
            # Backup original config
            self._backup_file(sshd_config)
            
            # Read current config
            with open(sshd_config, 'r') as f:
                config_lines = f.readlines()
            
            # Parse and modify config
            config_dict = {}
            for line in config_lines:
                line = line.strip()
                if line and not line.startswith('#'):
                    if ' ' in line:
                        key, value = line.split(None, 1)
                        config_dict[key] = value
            
            # Apply hardening settings
            changes = {}
            
            if self.config.ssh_disable_root_login:
                config_dict['PermitRootLogin'] = self.config.ssh_permit_root_login
                changes['PermitRootLogin'] = self.config.ssh_permit_root_login
            
            config_dict['MaxAuthTries'] = str(self.config.ssh_max_auth_tries)
            changes['MaxAuthTries'] = str(self.config.ssh_max_auth_tries)
            
            config_dict['PasswordAuthentication'] = "no" if self.config.ssh_disable_password_auth else "yes"
            changes['PasswordAuthentication'] = config_dict['PasswordAuthentication']
            
            config_dict['PermitEmptyPasswords'] = "no"
            changes['PermitEmptyPasswords'] = "no"
            
            config_dict['X11Forwarding'] = "no"
            changes['X11Forwarding'] = "no"
            
            config_dict['UsePAM'] = "yes"
            changes['UsePAM'] = "yes"
            
            if self.config.ssh_port != 22:
                config_dict['Port'] = str(self.config.ssh_port)
                changes['Port'] = str(self.config.ssh_port)
            
            if self.config.ssh_allow_groups:
                config_dict['AllowGroups'] = ' '.join(self.config.ssh_allow_groups)
                changes['AllowGroups'] = config_dict['AllowGroups']
            
            # Additional security settings
            config_dict['ClientAliveInterval'] = "300"
            config_dict['ClientAliveCountMax'] = "2"
            config_dict['LoginGraceTime'] = "60"
            config_dict['StrictModes'] = "yes"
            
            # Write updated config
            with open(sshd_config, 'w') as f:
                for key, value in config_dict.items():
                    f.write(f"{key} {value}\n")
            
            # Restart SSH service
            self._run_command(["systemctl", "restart", "sshd"])
            
            return self._report(
                category="ssh",
                action="harden",
                status="success",
                message="SSH hardened successfully",
                details={"changes": changes, "file": sshd_config}
            )
            
        except Exception as e:
            return self._report(
                category="ssh",
                action="harden",
                status="failed",
                message=f"Failed to harden SSH: {str(e)}"
            )
    
    def harden_firewall(self) -> List[HardeningReport]:
        """Configure system firewall"""
        reports = []
        
        if not self.config.firewall_enabled:
            reports.append(self._report(
                category="firewall",
                action="configure",
                status="skipped",
                message="Firewall disabled in configuration"
            ))
            return reports
        
        try:
            if self.firewall_type == "ufw":
                reports.extend(self._configure_ufw())
            elif self.firewall_type == "firewalld":
                reports.extend(self._configure_firewalld())
            
        except Exception as e:
            reports.append(self._report(
                category="firewall",
                action="configure",
                status="failed",
                message=f"Failed to configure firewall: {str(e)}"
            ))
        
        return reports
    
    def _configure_ufw(self) -> List[HardeningReport]:
        """Configure UFW firewall (Debian/Ubuntu)"""
        reports = []
        
        # Reset UFW
        self._run_command(["ufw", "--force", "reset"])
        
        # Set default policies
        self._run_command(["ufw", "default", "deny", "incoming"])
        self._run_command(["ufw", "default", "allow", "outgoing"])
        
        reports.append(self._report(
            category="firewall",
            action="default_policy",
            status="success",
            message="Set default deny incoming, allow outgoing"
        ))
        
        # Allow configured ports
        for port in self.config.firewall_allowed_ports:
            self._run_command(["ufw", "allow", str(port)])
            reports.append(self._report(
                category="firewall",
                action="allow_port",
                status="success",
                message=f"Allowed port {port}",
                details={"port": port}
            ))
        
        # Enable UFW
        self._run_command(["ufw", "--force", "enable"])
        
        reports.append(self._report(
            category="firewall",
            action="enable",
            status="success",
            message="UFW firewall enabled"
        ))
        
        return reports
    
    def _configure_firewalld(self) -> List[HardeningReport]:
        """Configure firewalld (RHEL/AlmaLinux)"""
        reports = []
        
        # Start and enable firewalld
        self._run_command(["systemctl", "start", "firewalld"])
        self._run_command(["systemctl", "enable", "firewalld"])
        
        # Set default zone
        self._run_command(["firewall-cmd", "--set-default-zone=public"])
        
        # Remove all services first
        services = self._run_command(
            ["firewall-cmd", "--list-services"],
            check=False
        ).stdout.strip().split()
        
        for service in services:
            self._run_command(["firewall-cmd", "--permanent", "--remove-service", service])
        
        # Allow configured ports
        for port in self.config.firewall_allowed_ports:
            self._run_command(["firewall-cmd", "--permanent", "--add-port", f"{port}/tcp"])
            reports.append(self._report(
                category="firewall",
                action="allow_port",
                status="success",
                message=f"Allowed port {port}/tcp",
                details={"port": port}
            ))
        
        # Reload firewall
        self._run_command(["firewall-cmd", "--reload"])
        
        reports.append(self._report(
            category="firewall",
            action="enable",
            status="success",
            message="Firewalld configured and enabled"
        ))
        
        return reports
    
    def setup_fail2ban(self) -> HardeningReport:
        """Setup and configure Fail2ban"""
        if not self.config.fail2ban_enabled:
            return self._report(
                category="fail2ban",
                action="setup",
                status="skipped",
                message="Fail2ban disabled in configuration"
            )
        
        try:
            # Install fail2ban
            if self.package_manager == "apt":
                self._run_command(["apt", "install", "-y", "fail2ban"])
            elif self.package_manager == "dnf":
                self._run_command(["dnf", "install", "-y", "fail2ban"])
            
            # Create jail.local
            jail_config = f"""[DEFAULT]
bantime = {self.config.fail2ban_ban_time}
findtime = {self.config.fail2ban_find_time}
maxretry = {self.config.fail2ban_max_retries}
ignoreip = 127.0.0.1/8

[sshd]
enabled = true
port = {self.config.ssh_port}
maxretry = {self.config.fail2ban_max_retries}

[vsftpd]
enabled = true
port = ftp,ftp-data,ftps,ftps-data
maxretry = {self.config.fail2ban_max_retries}

[samba]
enabled = true
port = 139,445
maxretry = {self.config.fail2ban_max_retries}
"""
            
            jail_path = "/etc/fail2ban/jail.local"
            with open(jail_path, 'w') as f:
                f.write(jail_config)
            
            # Enable and start fail2ban
            self._run_command(["systemctl", "enable", "fail2ban"])
            self._run_command(["systemctl", "restart", "fail2ban"])
            
            return self._report(
                category="fail2ban",
                action="setup",
                status="success",
                message="Fail2ban installed and configured",
                details={
                    "bantime": self.config.fail2ban_ban_time,
                    "maxretry": self.config.fail2ban_max_retries
                }
            )
            
        except Exception as e:
            return self._report(
                category="fail2ban",
                action="setup",
                status="failed",
                message=f"Failed to setup Fail2ban: {str(e)}"
            )
    
    def configure_auto_updates(self) -> HardeningReport:
        """Configure automatic security updates"""
        if not self.config.enable_auto_updates:
            return self._report(
                category="updates",
                action="auto_updates",
                status="skipped",
                message="Auto-updates disabled in configuration"
            )
        
        try:
            if self.package_manager == "apt":
                # Install unattended-upgrades
                self._run_command(["apt", "install", "-y", "unattended-upgrades"])
                
                # Configure
                config_content = """Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}";
    "${distro_id}:${distro_codename}-security";
    "${distro_id}ESMApps:${distro_codename}-apps-security";
    "${distro_id}ESM:${distro_codename}-infra-security";
};

Unattended-Upgrade::Package-Blacklist {
};

Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
"""
                
                with open("/etc/apt/apt.conf.d/50unattended-upgrades", 'w') as f:
                    f.write(config_content)
                
                # Enable auto updates
                self._run_command(["dpkg-reconfigure", "-f", "noninteractive", "unattended-upgrades"])
                
            elif self.package_manager == "dnf":
                # Install dnf-automatic
                self._run_command(["dnf", "install", "-y", "dnf-automatic"])
                
                config_content = f"""[commands]
upgrade_type = security
download_updates = yes
apply_updates = yes

[emitters]
emit_via = stdio

[email]
email_from = root
email_to = root
email_host = localhost
"""
                
                with open("/etc/dnf/automatic.conf", 'w') as f:
                    f.write(config_content)
                
                self._run_command(["systemctl", "enable", "--now", "dnf-automatic.timer"])
            
            return self._report(
                category="updates",
                action="auto_updates",
                status="success",
                message="Automatic security updates configured"
            )
            
        except Exception as e:
            return self._report(
                category="updates",
                action="auto_updates",
                status="failed",
                message=f"Failed to configure auto-updates: {str(e)}"
            )
    
    def harden_kernel(self) -> HardeningReport:
        """Apply kernel security parameters via sysctl"""
        sysctl_config = """
# Security hardening kernel parameters

# Disable IP forwarding
net.ipv4.ip_forward = 0

# Disable ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Don't send ICMP redirects
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Ignore ICMP echo requests (ping)
net.ipv4.icmp_echo_ignore_all = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Ignore bogus ICMP errors
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Enable TCP SYN cookies
net.ipv4.tcp_syncookies = 1

# Disable source routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Enable reverse path filtering
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Log martian packets
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# Disable IP spoofing protection
net.ipv4.conf.all.rp_filter = 1

# TCP hardening
net.ipv4.tcp_rfc1337 = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5

# Restrict dmesg access
kernel.dmesg_restrict = 1

# Restrict kernel pointer access
kernel.kptr_restrict = 2

# Disable core dumps
fs.suid_dumpable = 0

# Enable ASLR
kernel.randomize_va_space = 2

# Disable magic SysRq key
kernel.sysrq = 0

# Restrict unprivileged users from using syslog
kernel.printk = 3 4 1 3
"""
        
        try:
            config_path = "/etc/sysctl.d/99-security.conf"
            with open(config_path, 'w') as f:
                f.write(sysctl_config)
            
            # Apply sysctl settings
            self._run_command(["sysctl", "-p", config_path])
            
            return self._report(
                category="kernel",
                action="harden",
                status="success",
                message="Kernel security parameters applied",
                details={"file": config_path}
            )
            
        except Exception as e:
            return self._report(
                category="kernel",
                action="harden",
                status="failed",
                message=f"Failed to apply kernel hardening: {str(e)}"
            )
    
    def setup_tls(self) -> HardeningReport:
        """Setup TLS/SSL certificates"""
        if not self.config.tls_enabled:
            return self._report(
                category="tls",
                action="setup",
                status="skipped",
                message="TLS disabled in configuration"
            )
        
        try:
            # Check if certificates already exist
            if (self.config.tls_cert_path and 
                os.path.exists(self.config.tls_cert_path) and
                self.config.tls_key_path and
                os.path.exists(self.config.tls_key_path)):
                
                return self._report(
                    category="tls",
                    action="setup",
                    status="skipped",
                    message="TLS certificates already exist"
                )
            
            if self.config.tls_generate_self_signed:
                # Generate self-signed certificate
                cert_path = self.config.tls_cert_path or "/etc/ssl/certs/server.crt"
                key_path = self.config.tls_key_path or "/etc/ssl/private/server.key"
                
                # Ensure directories exist
                os.makedirs(os.path.dirname(cert_path), exist_ok=True)
                os.makedirs(os.path.dirname(key_path), exist_ok=True)
                
                # Generate private key and certificate
                subj = f"/C={self.config.tls_country}/ST={self.config.tls_state}/L={self.config.tls_city}/O={self.config.tls_org}/CN={self.config.tls_cn}"
                
                self._run_command([
                    "openssl", "req", "-x509", "-nodes",
                    "-days", "365",
                    "-newkey", "rsa:2048",
                    "-keyout", key_path,
                    "-out", cert_path,
                    "-subj", subj
                ])
                
                # Set proper permissions
                os.chmod(key_path, 0o600)
                os.chmod(cert_path, 0o644)
                
                return self._report(
                    category="tls",
                    action="setup",
                    status="success",
                    message="Self-signed TLS certificate generated",
                    details={
                        "cert_path": cert_path,
                        "key_path": key_path
                    }
                )
            
            return self._report(
                category="tls",
                action="setup",
                status="skipped",
                message="No certificate configuration provided"
            )
            
        except Exception as e:
            return self._report(
                category="tls",
                action="setup",
                status="failed",
                message=f"Failed to setup TLS: {str(e)}"
            )
    
    def get_report_summary(self) -> Dict[str, Any]:
        """Get a summary of all hardening reports"""
        total = len(self.reports)
        success = sum(1 for r in self.reports if r.status == "success")
        failed = sum(1 for r in self.reports if r.status == "failed")
        skipped = sum(1 for r in self.reports if r.status == "skipped")
        
        return {
            "total_actions": total,
            "successful": success,
            "failed": failed,
            "skipped": skipped,
            "reports": [r.model_dump() for r in self.reports]
        }
    
    def check_security_status(self) -> Dict[str, Any]:
        """Check current security status"""
        status = {
            "ssh": self._check_ssh_status(),
            "firewall": self._check_firewall_status(),
            "fail2ban": self._check_fail2ban_status(),
            "kernel": self._check_kernel_hardening(),
            "tls": self._check_tls_status()
        }
        return status
    
    def _check_ssh_status(self) -> Dict[str, Any]:
        """Check SSH hardening status"""
        status = {}
        sshd_config = "/etc/ssh/sshd_config"
        
        try:
            with open(sshd_config, 'r') as f:
                content = f.read()
            
            status["root_login_disabled"] = "PermitRootLogin no" in content
            status["password_auth"] = "PasswordAuthentication yes" in content
            status["empty_passwords_disabled"] = "PermitEmptyPasswords no" in content
            
        except Exception:
            status["error"] = "Could not read sshd_config"
        
        return status
    
    def _check_firewall_status(self) -> Dict[str, Any]:
        """Check firewall status"""
        status = {"type": self.firewall_type}
        
        try:
            if self.firewall_type == "ufw":
                result = self._run_command(["ufw", "status"], check=False)
                status["active"] = "Status: active" in result.stdout
                status["output"] = result.stdout
            
            elif self.firewall_type == "firewalld":
                result = self._run_command(["firewall-cmd", "--state"], check=False)
                status["active"] = "running" in result.stdout
            
        except Exception:
            status["active"] = False
        
        return status
    
    def _check_fail2ban_status(self) -> Dict[str, Any]:
        """Check Fail2ban status"""
        status = {}
        
        try:
            result = self._run_command(["systemctl", "is-active", "fail2ban"], check=False)
            status["active"] = result.returncode == 0
            
            if status["active"]:
                result = self._run_command(["fail2ban-client", "status"], check=False)
                status["jails"] = result.stdout if result.returncode == 0 else ""
            
        except Exception:
            status["active"] = False
        
        return status
    
    def _check_kernel_hardening(self) -> Dict[str, Any]:
        """Check kernel hardening status"""
        status = {}
        
        try:
            for param in ["net.ipv4.tcp_syncookies", "kernel.dmesg_restrict"]:
                result = self._run_command(["sysctl", "-n", param], check=False)
                status[param] = result.stdout.strip()
        
        except Exception:
            status["error"] = "Could not read sysctl parameters"
        
        return status
    
    def _check_tls_status(self) -> Dict[str, Any]:
        """Check TLS certificate status"""
        status = {}
        
        cert_path = self.config.tls_cert_path or "/etc/ssl/certs/server.crt"
        
        if os.path.exists(cert_path):
            status["cert_exists"] = True
            
            # Check certificate expiry
            result = self._run_command(
                ["openssl", "x509", "-in", cert_path, "-noout", "-enddate"],
                check=False
            )
            status["cert_info"] = result.stdout.strip()
        else:
            status["cert_exists"] = False
        
        return status