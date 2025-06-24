import platform
import psutil
import winreg
import os
from config import Config
from datetime import datetime
import logging
from network.communicator import ServerCommunicator, CommunicationError
from encryption.manager import EncryptionManager

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
            communicator = ServerCommunicator(Config.get_client_id(), EncryptionManager(Config.ENCRYPTION_KEY))
            response = communicator._send_request(
                "action=get_ip",
                data={"client_id": Config.get_client_id()}
            )
            ip_address = response[0].get('ip_address', 'unknown') if response else 'unknown'
            return {
                "ip_address": ip_address,
                "mac_address": ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff) for elements in range(5, -1, -1)])
            }
        except CommunicationError as e:
            logging.error(f"Network info retrieval error: {str(e)}")
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
        logging.info("Collecting system info with datetime")
        return {
            **SystemCollector.get_platform_info(),
            **SystemCollector.get_hardware_info(),
            **SystemCollector.get_network_info(),
            **SystemCollector.get_security_info(),
            "timestamp": datetime.now().isoformat()
        }