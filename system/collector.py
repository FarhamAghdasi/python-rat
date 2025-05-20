# ------------ system/collector.py ------------
import platform
import psutil
import winreg
import os
import requests
from config import Config
from datetime import datetime  # Ensure this is present
import logging  # Add for debugging

class SystemCollector:
    @staticmethod
    def get_platform_info():
        return {
            "os": platform.system(),
            "version": platform.version(),
            "architecture": platform.architecture(),
            "hostname": platform.node(),
            "user": os.getlogin()
        }

    @staticmethod
    def get_hardware_info():
        return {
            "cpu_cores": os.cpu_count(),
            "total_memory": psutil.virtual_memory().total,
            "disk_usage": psutil.disk_usage('/')._asdict()
        }

    @staticmethod
    def get_network_info():
        try:
            return {
                "ip_address": requests.get('https://fasitheme.ir/ip.php', timeout=5).text,
                "mac_address": ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff) for elements in range(5, -1, -1)])
            }
        except:
            return {"ip_address": "unknown"}

    @staticmethod
    def get_security_info():
        try:
            winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows Defender")
            return {"antivirus": "Windows Defender"}
        except:
            return {"antivirus": "Unknown"}

    @staticmethod
    def collect_full():
        logging.info("Collecting system info with datetime")  # Debug log
        return {
            **SystemCollector.get_platform_info(),
            **SystemCollector.get_hardware_info(),
            **SystemCollector.get_network_info(),
            **SystemCollector.get_security_info(),
            "timestamp": datetime.now().isoformat()
        }