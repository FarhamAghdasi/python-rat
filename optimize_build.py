import os
import subprocess
import sys

def optimize_build():
    """بهینه‌سازی نهایی برای کاهش حجم فایل"""
    
    print("Performing final optimizations...")
    
    # نصب UPX برای فشرده‌سازی بیشتر
    try:
        subprocess.run([sys.executable, "-m", "pip", "install", "upx"], check=True)
        print("UPX installed for additional compression")
    except:
        print("UPX installation failed, continuing without it")
    
    # حذف فایل‌های غیرضروری
    unnecessary_files = [
        "build",
        "__pycache__",
        "*.pyc",
        "*.log",
        "temp_*",
        "wrapper.py"
    ]
    
    for pattern in unnecessary_files:
        os.system(f"del /Q {pattern}" if os.name == 'nt' else f"rm -rf {pattern}")
    
    print("Build optimization completed")

if __name__ == "__main__":
    optimize_build()