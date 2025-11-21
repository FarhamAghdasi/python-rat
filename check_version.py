# check_version.py
import os
import subprocess
import sys

def check_exe_version(exe_path):
    """Check version information in executable file"""
    try:
        print(f"\n{'='*60}")
        print(f"Checking version info for: {exe_path}")
        print(f"{'='*60}\n")
        
        if not os.path.exists(exe_path):
            print(f"❌ Executable not found: {exe_path}")
            return

        # Method 1: Using PowerShell
        ps_script = f'''
$exe = Get-Item "{exe_path}"
$versionInfo = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($exe.FullName)
Write-Host "=== Version Information ===" -ForegroundColor Cyan
Write-Host "Company Name    : $($versionInfo.CompanyName)"
Write-Host "Product Name    : $($versionInfo.ProductName)"
Write-Host "File Description: $($versionInfo.FileDescription)"
Write-Host "File Version    : $($versionInfo.FileVersion)"
Write-Host "Product Version : $($versionInfo.ProductVersion)"
Write-Host "Copyright       : $($versionInfo.LegalCopyright)"
Write-Host "Comments        : $($versionInfo.Comments)"
Write-Host "Internal Name   : $($versionInfo.InternalName)"
Write-Host "Original Name   : $($versionInfo.OriginalFilename)"
Write-Host "==========================" -ForegroundColor Cyan
'''
        
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_script],
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='replace'
        )
        
        if result.returncode == 0:
            print(result.stdout)
        else:
            print("❌ Failed to read version info via PowerShell")
            print("Error:", result.stderr)

        # Method 2: Using pefile (if available)
        try:
            import pefile
            pe = pefile.PE(exe_path)
            
            if hasattr(pe, 'VS_VERSIONINFO'):
                print("\n✓ Version info structure detected in EXE")
                if hasattr(pe, 'FileInfo'):
                    for fileinfo in pe.FileInfo:
                        if fileinfo.Key == b'StringFileInfo':
                            for st in fileinfo.StringTable:
                                for entry in st.entries.items():
                                    print(f"  {entry[0].decode()}: {entry[1].decode()}")
            else:
                print("\n⚠ No version info structure found in EXE")
        except ImportError:
            print("\nℹ pefile not installed (pip install pefile)")
        except Exception as e:
            print(f"\n⚠ pefile check failed: {e}")
            
    except Exception as e:
        print(f"❌ Error checking version: {e}")

if __name__ == "__main__":
    exe_path = "dist/KeyloggerClient.exe"
    
    if len(sys.argv) > 1:
        exe_path = sys.argv[1]
    
    if os.path.exists(exe_path):
        print(f"✓ File exists: {exe_path}")
        print(f"✓ File size: {os.path.getsize(exe_path):,} bytes\n")
        check_exe_version(exe_path)
    else:
        print(f"❌ Executable not found: {exe_path}")
        if os.path.exists("dist"):
            print("\n📁 Files in dist directory:")
            for file in os.listdir("dist"):
                print(f"   - {file}")