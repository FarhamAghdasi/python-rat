import subprocess
import socket
import winreg
import requests
import logging
import os
import ctypes
import time
import json
from datetime import datetime

# Setup logging
LOG_FILE = "rdp_diagnostic.log"
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        logging.StreamHandler()
    ]
)

class RDPDiagnostic:
    def __init__(self):
        self.results = {
            "timestamp": datetime.now().isoformat(),
            "tests": {}
        }
        self.logger = logging.getLogger("RDPDiagnostic")

    def _is_admin(self) -> bool:
        """Check if the script is running with admin privileges."""
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False

    def _run_command(self, cmd: list, timeout: int = 30) -> dict:
        """Run a command and capture output."""
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

    def test_admin_privileges(self):
        """Test if the script is running with admin privileges."""
        self.logger.info("Testing admin privileges...")
        is_admin = self._is_admin()
        result = {
            "status": "success" if is_admin else "error",
            "message": "Script is running with admin privileges" if is_admin else "Admin privileges required"
        }
        self.results["tests"]["admin_privileges"] = result
        self.logger.info(result["message"])

    def test_rdp_registry(self):
        """Test RDP registry settings."""
        self.logger.info("Testing RDP registry settings...")
        try:
            reg_path = r"SYSTEM\CurrentControlSet\Control\Terminal Server"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path, 0, winreg.KEY_QUERY_VALUE) as key:
                fDenyTSConnections, _ = winreg.QueryValueEx(key, "fDenyTSConnections")
                result = {
                    "status": "success" if fDenyTSConnections == 0 else "error",
                    "message": "RDP is enabled in registry" if fDenyTSConnections == 0 else "RDP is disabled in registry",
                    "fDenyTSConnections": fDenyTSConnections
                }
            reg_path_tcp = r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path_tcp, 0, winreg.KEY_QUERY_VALUE) as key:
                port_number, _ = winreg.QueryValueEx(key, "PortNumber")
                result["port_number"] = port_number
                if port_number != 3389:
                    result["status"] = "error"
                    result["message"] += f"; RDP port is {port_number}, expected 3389"
        except Exception as e:
            result = {"status": "error", "message": f"Failed to check registry: {str(e)}"}
        self.results["tests"]["rdp_registry"] = result
        self.logger.info(result["message"])

    def test_rdp_services(self):
        """Test RDP-related services."""
        self.logger.info("Testing RDP services...")
        services = ["TermService", "SessionEnv", "UmRdpService"]
        result = {"status": "success", "services": {}, "message": ""}
        for service in services:
            cmd_result = self._run_command(["sc", "query", service])
            if cmd_result["status"] == "success" and "RUNNING" in cmd_result["stdout"]:
                result["services"][service] = "running"
            else:
                result["services"][service] = "not running"
                result["status"] = "error"
                result["message"] += f"Service {service} is not running; "
        if result["status"] == "success":
            result["message"] = "All RDP services are running"
        self.results["tests"]["rdp_services"] = result
        self.logger.info(result["message"])

    def test_firewall(self):
        """Test firewall rules for RDP (port 3389)."""
        self.logger.info("Testing firewall rules...")
        cmd_result = self._run_command(["netsh", "advfirewall", "firewall", "show", "rule", "name=Allow RDP"])
        if cmd_result["status"] == "success" and "Enabled: Yes" in cmd_result["stdout"]:
            result = {"status": "success", "message": "Firewall rule for RDP (port 3389) is enabled"}
        else:
            result = {"status": "error", "message": "Firewall rule for RDP (port 3389) is missing or disabled"}
        self.results["tests"]["firewall"] = result
        self.logger.info(result["message"])

    def test_port_3389(self):
        """Test if port 3389 is listening."""
        self.logger.info("Testing port 3389...")
        cmd_result = self._run_command(["netstat", "-an"])
        if cmd_result["status"] == "success" and ":3389" in cmd_result["stdout"] and "LISTENING" in cmd_result["stdout"]:
            result = {"status": "success", "message": "Port 3389 is listening (netstat check)"}
        else:
            try:
                ps_command = "Get-NetTCPConnection -LocalPort 3389 -State Listen -ErrorAction SilentlyContinue"
                ps_result = self._run_command(["powershell", "-Command", ps_command])
                if ps_result["status"] == "success" and ps_result["stdout"].strip():
                    result = {"status": "success", "message": "Port 3389 is listening (PowerShell check)"}
                else:
                    result = {"status": "error", "message": "Port 3389 is not listening"}
            except Exception:
                result = {"status": "error", "message": "Port 3389 is not listening"}
        self.results["tests"]["port_3389"] = result
        self.logger.info(result["message"])

    def test_local_connection(self):
        """Test local connection to port 3389."""
        self.logger.info("Testing local RDP connection...")
        try:
            local_ip = self._get_local_ip()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result_code = sock.connect_ex((local_ip, 3389))
            sock.close()
            if result_code == 0:
                result = {"status": "success", "message": "Local connection to port 3389 successful"}
            else:
                result = {"status": "error", "message": f"Local connection to port 3389 failed (error code: {result_code})"}
        except Exception as e:
            result = {"status": "error", "message": f"Local connection test failed: {str(e)}"}
        self.results["tests"]["local_connection"] = result
        self.logger.info(result["message"])

    def test_network(self):
        """Test network configuration (local and public IP)."""
        self.logger.info("Testing network configuration...")
        local_ip = self._get_local_ip()
        public_ip = self._get_public_ip()
        result = {
            "status": "success",
            "local_ip": local_ip,
            "public_ip": public_ip,
            "message": "Network configuration retrieved"
        }
        if local_ip == "unknown" or public_ip == "unknown":
            result["status"] = "error"
            result["message"] = "Failed to retrieve IP addresses"
        elif local_ip != public_ip:
            result["message"] += "; NAT detected - port 3389 must be forwarded on the router"
        self.results["tests"]["network"] = result
        self.logger.info(result["message"])

    def test_rdp_user(self):
        """Test RDP user existence and group membership."""
        self.logger.info("Testing RDP user...")
        username = None
        for user in ["rat_admin_" + str(i) for i in range(1000)]:  # Check for any rat_admin_ user
            if self._user_exists(user):
                username = user
                break
        if not username:
            result = {"status": "error", "message": "No RDP user (rat_admin_*) found"}
        else:
            admin_group = self._is_user_in_group(username, "Administrators")
            rdp_group = self._is_user_in_group(username, "Remote Desktop Users")
            if admin_group and rdp_group:
                result = {
                    "status": "success",
                    "message": f"RDP user {username} exists and is in Administrators and Remote Desktop Users groups"
                }
            else:
                result = {
                    "status": "error",
                    "message": f"RDP user {username} exists but missing group membership: "
                               f"Administrators={admin_group}, Remote Desktop Users={rdp_group}"
                }
        self.results["tests"]["rdp_user"] = result
        self.logger.info(result["message"])

    def test_event_logs(self):
        """Test Windows event logs for RDP-related errors."""
        self.logger.info("Testing event logs...")
        try:
            ps_command = (
                "Get-WinEvent -LogName 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational' "
                "-MaxEvents 10 -ErrorAction SilentlyContinue | "
                "Select-Object TimeCreated,Message | ConvertTo-Json"
            )
            cmd_result = self._run_command(["powershell", "-Command", ps_command])
            if cmd_result["status"] == "success" and cmd_result["stdout"].strip():
                events = json.loads(cmd_result["stdout"])
                result = {
                    "status": "success",
                    "message": "Retrieved recent RDP event logs",
                    "events": [
                        {"time": e["TimeCreated"], "message": e["Message"]} for e in events
                    ]
                }
            else:
                result = {"status": "error", "message": "No recent RDP event logs found"}
        except Exception as e:
            result = {"status": "error", "message": f"Failed to check event logs: {str(e)}"}
        self.results["tests"]["event_logs"] = result
        self.logger.info(result["message"])

    def _user_exists(self, username: str) -> bool:
        """Check if a user exists."""
        cmd_result = self._run_command(["net", "user", username])
        return cmd_result["status"] == "success"

    def _is_user_in_group(self, username: str, group: str) -> bool:
        """Check if a user is in a specific group."""
        cmd_result = self._run_command(["net", "localgroup", group])
        return cmd_result["status"] == "success" and username in cmd_result["stdout"]

    def _get_local_ip(self) -> str:
        """Get local IP address."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except Exception:
            return "unknown"

    def _get_public_ip(self) -> str:
        """Get public IP address."""
        try:
            response = requests.get("https://api.ipify.org", timeout=5)
            return response.text.strip()
        except Exception:
            return "unknown"

    def run_all_tests(self):
        """Run all diagnostic tests."""
        self.logger.info("Starting RDP diagnostic tests...")
        self.test_admin_privileges()
        self.test_rdp_registry()
        self.test_rdp_services()
        self.test_firewall()
        self.test_port_3389()
        self.test_local_connection()
        self.test_network()
        self.test_rdp_user()
        self.test_event_logs()
        self.logger.info("Diagnostic tests completed")

    def save_results(self):
        """Save test results to a JSON file."""
        output_file = "rdp_diagnostic_results.json"
        try:
            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(self.results, f, indent=4, ensure_ascii=False)
            self.logger.info(f"Results saved to {output_file}")
        except Exception as e:
            self.logger.error(f"Failed to save results: {str(e)}")

    def print_summary(self):
        """Print a summary of test results."""
        print("\n=== RDP Diagnostic Summary ===")
        for test_name, result in self.results["tests"].items():
            status = "PASS" if result["status"] == "success" else "FAIL"
            print(f"{test_name}: {status} - {result['message']}")
        print(f"\nDetailed results saved to {LOG_FILE} and rdp_diagnostic_results.json")
        if any(result["status"] == "error" for result in self.results["tests"].values()):
            print("\nRecommended actions:")
            if self.results["tests"]["admin_privileges"]["status"] == "error":
                print("- Run the script as Administrator.")
            if self.results["tests"]["rdp_registry"]["status"] == "error":
                print("- Enable RDP in registry (set fDenyTSConnections to 0) or check port number.")
            if self.results["tests"]["rdp_services"]["status"] == "error":
                print("- Start RDP services (net start TermService, SessionEnv, UmRdpService).")
            if self.results["tests"]["firewall"]["status"] == "error":
                print("- Add firewall rule for port 3389 (netsh advfirewall firewall add rule ...).")
            if self.results["tests"]["port_3389"]["status"] == "error":
                print("- Ensure port 3389 is open and listening (restart TermService if needed).")
            if self.results["tests"]["local_connection"]["status"] == "error":
                print("- Check local connectivity to port 3389 (possible firewall or service issue).")
            if self.results["tests"]["network"]["status"] == "error":
                print("- Verify network connectivity and IP addresses.")
            if "NAT detected" in self.results["tests"]["network"]["message"]:
                print("- Forward port 3389 on your router to the local IP.")
            if self.results["tests"]["rdp_user"]["status"] == "error":
                print("- Create or configure RDP user with correct group memberships.")
            if self.results["tests"]["event_logs"]["status"] == "error":
                print("- Check Windows Event Viewer for RDP-related errors.")

if __name__ == "__main__":
    diagnostic = RDPDiagnostic()
    diagnostic.run_all_tests()
    diagnostic.save_results()
    diagnostic.print_summary()