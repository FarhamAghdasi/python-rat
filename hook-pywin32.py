# hook-pywin32.py
from PyInstaller.utils.hooks import collect_all, collect_data_files

# جمع‌آوری تمام ماژول‌های pywin32
datas, binaries, hiddenimports = collect_all('pywin32')

# اضافه کردن ماژول‌های خاص win32
hiddenimports += [
    'win32api',
    'win32con',
    'win32process',
    'win32security',
    'win32file',
    'win32service',
    'win32serviceutil',
    'win32com',
    'win32com.shell',
    'pywintypes',
]

# اضافه کردن فایل‌های سیستمی مورد نیاز
binaries += collect_data_files('pywin32')