import os
import logging
import winreg
from typing import Dict, List, Optional

class BrowserDetector:
    """سیستم تشخیص خودکار مرورگرهای نصب شده"""
    
    def __init__(self):
        self.logger = logging.getLogger("BrowserDetector")
        self.detected_browsers = {}
        
    def detect_installed_browsers(self) -> Dict:
        """تشخیص مرورگرهای نصب شده با استفاده از رجیستری و مسیرهای فایل"""
        self.logger.info("Starting browser detection...")
        browsers = {}
        
        # لیست مرورگرهای شناخته شده
        browser_paths = {
            "Chrome": {
                "registry": r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe",
                "paths": [
                    os.path.expanduser("~\\AppData\\Local\\Google\\Chrome"),
                    os.path.expanduser("~\\AppData\\Local\\Google\\Chrome\\User Data")
                ]
            },
            "Firefox": {
                "registry": r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\\firefox.exe",
                "paths": [
                    os.path.expanduser("~\\AppData\\Roaming\\Mozilla\\Firefox"),
                    os.path.expanduser("~\\AppData\\Local\\Mozilla\\Firefox")
                ]
            },
            "Edge": {
                "registry": r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\\msedge.exe",
                "paths": [
                    os.path.expanduser("~\\AppData\\Local\\Microsoft\\Edge"),
                    os.path.expanduser("~\\AppData\\Local\\Microsoft\\Edge\\User Data")
                ]
            },
            "Opera": {
                "registry": r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\\opera.exe",
                "paths": [
                    os.path.expanduser("~\\AppData\\Roaming\\Opera Software"),
                    os.path.expanduser("~\\AppData\\Local\\Opera Software")
                ]
            },
            "Brave": {
                "registry": r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\\brave.exe",
                "paths": [
                    os.path.expanduser("~\\AppData\\Local\\BraveSoftware"),
                    os.path.expanduser("~\\AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data")
                ]
            }
        }
        
        for browser_name, browser_info in browser_paths.items():
            browser_data = {
                "installed": False,
                "paths": {},
                "profiles": []
            }
            
            # بررسی رجیستری
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, browser_info["registry"]) as key:
                    browser_data["installed"] = True
                    browser_data["registry_path"] = browser_info["registry"]
                    self.logger.info(f"Detected {browser_name} in registry")
            except FileNotFoundError:
                try:
                    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, browser_info["registry"]) as key:
                        browser_data["installed"] = True
                        browser_data["registry_path"] = browser_info["registry"]
                        self.logger.info(f"Detected {browser_name} in registry (HKCU)")
                except FileNotFoundError:
                    pass
            except Exception as e:
                self.logger.warning(f"Registry check failed for {browser_name}: {str(e)}")
            
            # بررسی مسیرهای فایل
            for path in browser_info["paths"]:
                if os.path.exists(path):
                    browser_data["paths"][path] = True
                    self.logger.info(f"Found {browser_name} path: {path}")
                    
                    # پیدا کردن پروفایل‌ها
                    profiles = self._find_browser_profiles(browser_name, path)
                    if profiles:
                        browser_data["profiles"] = profiles
                        self.logger.info(f"Found {len(profiles)} profiles for {browser_name}")
            
            if browser_data["installed"] or browser_data["paths"]:
                browsers[browser_name] = browser_data
                self.logger.info(f"Browser {browser_name} detected successfully")
        
        self.detected_browsers = browsers
        self.logger.info(f"Browser detection completed. Found: {list(browsers.keys())}")
        return browsers
    
    def _find_browser_profiles(self, browser_name: str, base_path: str) -> List[Dict]:
        """پیدا کردن پروفایل‌های مرورگر"""
        profiles = []
        
        try:
            if browser_name.lower() in ["chrome", "edge", "brave"]:
                user_data_dir = base_path
                if not base_path.endswith("User Data"):
                    user_data_dir = os.path.join(base_path, "User Data")
                
                if os.path.exists(user_data_dir):
                    for item in os.listdir(user_data_dir):
                        item_path = os.path.join(user_data_dir, item)
                        if os.path.isdir(item_path) and any(x in item.lower() for x in ['default', 'profile']):
                            profile_info = {
                                "name": item,
                                "path": item_path,
                                "type": "default" if "default" in item.lower() else "profile"
                            }
                            
                            # بررسی وجود فایل‌های مهم
                            important_files = ["History", "Cookies", "Login Data", "Bookmarks", "Web Data"]
                            for file in important_files:
                                file_path = os.path.join(item_path, file)
                                if os.path.exists(file_path):
                                    profile_info[f"has_{file.lower().replace(' ', '_')}"] = True
                                    self.logger.info(f"Found {file} at {file_path}")
                                else:
                                    self.logger.warning(f"File not found: {file_path}")
                            
                            profiles.append(profile_info)
            
            elif browser_name.lower() == "firefox":
                profiles_file = os.path.join(base_path, "profiles.ini")
                if os.path.exists(profiles_file):
                    # پردازش profiles.ini برای Firefox
                    with open(profiles_file, 'r') as f:
                        lines = f.readlines()
                    
                    current_profile = {}
                    for line in lines:
                        line = line.strip()
                        if line.startswith('[Profile'):
                            if current_profile:
                                profiles.append(current_profile)
                            current_profile = {}
                        elif '=' in line:
                            key, value = line.split('=', 1)
                            current_profile[key] = value
                    
                    if current_profile:
                        profiles.append(current_profile)
        
        except Exception as e:
            self.logger.error(f"Error finding profiles for {browser_name}: {str(e)}")
        
        return profiles

    def get_detection_summary(self) -> Dict:
        """خلاصه وضعیت تشخیص"""
        return {
            "total_detected": len(self.detected_browsers),
            "browsers": list(self.detected_browsers.keys()),
            "details": self.detected_browsers
        }