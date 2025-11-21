# check_version.py
import os
import subprocess

def check_exe_version(exe_path):
    """Check version information in executable file"""
    try:
        print(f"Checking version info for: {exe_path}")
        
        if not os.path.exists(exe_path):
            print(f"Executable not found: {exe_path}")
            return

        # Method 1: Using PowerShell with correct encoding
        ps_script = f"""
        $exe = Get-Item "{exe_path}"
        $versionInfo = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($exe.FullName)
        Write-Output "=== Version Information ==="
        Write-Output "Company: $($versionInfo.CompanyName)"
        Write-Output "Product: $($versionInfo.ProductName)" 
        Write-Output "Description: $($versionInfo.FileDescription)"
        Write-Output "Version: $($versionInfo.FileVersion)"
        Write-Output "Copyright: $($versionInfo.LegalCopyright)"
        Write-Output "Comments: $($versionInfo.Comments)"
        Write-Output "=== End ==="
        """
        
        # Run PowerShell with UTF-8 encoding
        result = subprocess.run(
            ["powershell", "-Command", ps_script], 
            capture_output=True, 
            text=True,
            encoding='utf-8',
            errors='ignore'
        )
        
        if result.returncode == 0:
            print("PowerShell version info:")
            print(result.stdout)
        else:
            print("Failed to read version info via PowerShell")
            print("Error:", result.stderr)
            
    except Exception as e:
        print(f"Error checking version: {e}")

def check_with_file_properties(exe_path):
    """Check by opening file properties"""
    try:
        print("\nOpening file properties...")
        os.startfile(exe_path, "properties")
        print("File properties window opened - please check manually")
    except Exception as e:
        print(f"Could not open properties window: {e}")

if __name__ == "__main__":
    exe_path = "dist/KeyloggerClient.exe"
    
    if os.path.exists(exe_path):
        print(f"File exists: {exe_path}")
        print(f"File size: {os.path.getsize(exe_path)} bytes")
        
        # Check with PowerShell
        check_exe_version(exe_path)
        
        # Open properties
        check_with_file_properties(exe_path)
        
        print(f"\nYou can also manually check by:")
        print(f"1. Right-click on {exe_path}")
        print(f"2. Select 'Properties'") 
        print(f"3. Go to 'Details' tab")
        
    else:
        print(f"Executable not found: {exe_path}")
        # List files in dist
        if os.path.exists("dist"):
            print("Files in dist directory:")
            for file in os.listdir("dist"):
                print(f"  - {file}")