# client/system/vm_detector.py
import platform
import psutil
import winreg
import subprocess
import logging
from rat_config import Config

class VMDetector:
    @staticmethod
    def is_virtual_machine():
        """
        بررسی می‌کند که آیا سیستم یک ماشین مجازی است یا خیر.
        اگر حداقل یکی از روش‌ها VM را شناسایی کند، True برمی‌گرداند.
        """
        try:
            if Config.DEBUG_MODE:
                logging.info("Starting VM detection...")

            # روش‌های مختلف بررسی
            checks = [
                VMDetector.check_hardware(),
                VMDetector.check_processes(),
                VMDetector.check_registry(),
                VMDetector.check_bios(),
                VMDetector.check_drivers()
            ]

            is_vm = any(checks)
            if Config.DEBUG_MODE:
                logging.info(f"VM detection result: {'Virtual Machine' if is_vm else 'Physical Machine'}")
                logging.info(f"Check results: hardware={checks[0]}, processes={checks[1]}, registry={checks[2]}, bios={checks[3]}, drivers={checks[4]}")
            return is_vm

        except Exception as e:
            if Config.DEBUG_MODE:
                logging.error(f"VM detection error: {str(e)}")
            return False

    @staticmethod
    def check_hardware():
        """
        بررسی مشخصات سخت‌افزاری برای نشانه‌های VM.
        """
        try:
            if platform.system().lower() != "windows":
                if Config.DEBUG_MODE:
                    logging.info("Hardware check only supported on Windows")
                return False

            # بررسی مدل CPU
            cpu_info = subprocess.check_output("wmic cpu get caption", shell=True).decode().lower()
            if "virtual" in cpu_info or "vmware" in cpu_info or "kvm" in cpu_info:
                return True

            # بررسی سازنده مادربورد
            board_info = subprocess.check_output("wmic baseboard get manufacturer", shell=True).decode().lower()
            vm_indicators = ["vmware", "virtualbox", "microsoft corporation", "parallels"]
            return any(indicator in board_info for indicator in vm_indicators)

        except Exception as e:
            if Config.DEBUG_MODE:
                logging.error(f"Hardware check error: {str(e)}")
            return False

    @staticmethod
    def check_processes():
        """
        بررسی فرآیندهای در حال اجرا برای فرآیندهای مرتبط با VM.
        """
        try:
            vm_processes = [
                "vmtoolsd.exe",  # VMware
                "vboxservice.exe",  # VirtualBox
                "vmsrvc.exe",  # Parallels
                "qemu-ga.exe"  # QEMU
            ]
            for proc in psutil.process_iter(['name']):
                if proc.info['name'].lower() in vm_processes:
                    if Config.DEBUG_MODE:
                        logging.info(f"VM process detected: {proc.info['name']}")
                    return True
            return False

        except Exception as e:
            if Config.DEBUG_MODE:
                logging.error(f"Process check error: {str(e)}")
            return False

    @staticmethod
    def check_registry():
        """
        بررسی کلیدهای رجیستری ویندوز برای نشانه‌های VM.
        """
        try:
            if platform.system().lower() != "windows":
                if Config.DEBUG_MODE:
                    logging.info("Registry check only supported on Windows")
                return False

            registry_paths = [
                (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\ControlSet001\Services\vmtools"),
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\VMware, Inc.\VMware Tools"),
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Oracle\VirtualBox Guest Additions"),
                (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\ControlSet001\Services\VBoxService")
            ]

            for hive, path in registry_paths:
                try:
                    winreg.OpenKey(hive, path)
                    if Config.DEBUG_MODE:
                        logging.info(f"VM registry key detected: {path}")
                    return True
                except FileNotFoundError:
                    continue
                except Exception as e:
                    if Config.DEBUG_MODE:
                        logging.error(f"Registry key check error for {path}: {str(e)}")
            return False

        except Exception as e:
            if Config.DEBUG_MODE:
                logging.error(f"Registry check error: {str(e)}")
            return False

    @staticmethod
    def check_bios():
        """
        بررسی اطلاعات BIOS برای نشانه‌های VM.
        """
        try:
            if platform.system().lower() != "windows":
                if Config.DEBUG_MODE:
                    logging.info("BIOS check only supported on Windows")
                return False

            bios_info = subprocess.check_output("wmic bios get manufacturer,smbiosbiosversion", shell=True).decode().lower()
            vm_indicators = ["vmware", "virtualbox", "innotek", "american megatrends inc. virtual"]
            return any(indicator in bios_info for indicator in vm_indicators)

        except Exception as e:
            if Config.DEBUG_MODE:
                logging.error(f"BIOS check error: {str(e)}")
            return False

    @staticmethod
    def check_drivers():
        """
        بررسی درایورهای نصب‌شده برای نشانه‌های VM.
        """
        try:
            if platform.system().lower() != "windows":
                if Config.DEBUG_MODE:
                    logging.info("Driver check only supported on Windows")
                return False

            driver_info = subprocess.check_output("driverquery", shell=True).decode().lower()
            vm_drivers = ["vmxnet", "vmhgfs", "vboxvideo", "vmmouse"]
            return any(driver in driver_info for driver in vm_drivers)

        except Exception as e:
            if Config.DEBUG_MODE:
                logging.error(f"Driver check error: {str(e)}")
            return False

    @staticmethod
    def get_vm_details():
        """
        جزئیات شناسایی VM را برمی‌گرداند.
        """
        details = {
            "is_vm": VMDetector.is_virtual_machine(),
            "checks": {
                "hardware": VMDetector.check_hardware(),
                "processes": VMDetector.check_processes(),
                "registry": VMDetector.check_registry(),
                "bios": VMDetector.check_bios(),
                "drivers": VMDetector.check_drivers()
            }
        }
        return details