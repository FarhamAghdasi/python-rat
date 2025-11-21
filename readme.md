# 🚀 Advanced Remote Administration Tool (RAT)

![Version](https://img.shields.io/badge/version-1.5.0-blue)
![Python](https://img.shields.io/badge/python-3.8%2B-green)
![Platform](https://img.shields.io/badge/platform-windows-lightgrey)
![License](https://img.shields.io/badge/license-MIT-orange)

**📖 [مستندات فارسی](README_FA.md) | 📚 [Full Documentation](docs/) | 📋 [Changelog](CHANGELOG.md)**

## ⚠️ DISCLAIMER
**WARNING: This software is intended for educational, research, and authorized penetration testing purposes only. The developers are not responsible for any misuse or damage caused by this program. Users must ensure they have proper authorization before deploying this tool on any system.**

## 🌟 Introduction

**This Project (RAT)** is an advanced remote administration tool built with Python, designed for comprehensive system monitoring and management. It provides a wide range of features for legitimate security research, system administration, and authorized penetration testing.

## 🏗 Architecture & Technical Implementation

### 🔧 Core Mechanisms

#### **Communication Layer**
- **Encrypted HTTP Communication**: AES-256-CBC encryption with PBKDF2 key derivation
- **Server-Client Architecture**: Polling-based command system with configurable intervals
- **Proxy Support**: HTTP/HTTPS proxy configuration for network routing
- **Compressed Data Transfer**: Gzip compression for efficient bandwidth usage

#### **Persistence & Stealth**
- **Windows Registry Integration**: Automatic startup via HKEY_CURRENT_USER Run keys
- **Process Injection**: DLL injection into system processes (svchost.exe)
- **Anti-Detection**: VM detection, antivirus behavior adjustment, and code obfuscation
- **Service Masquerading**: Disguised as "Ita Messenger Service" with legitimate version info

#### **Security Features**
- **AES-256 Encryption**: All data encrypted before transmission
- **Secure Key Derivation**: PBKDF2 with SHA-256 for key generation
- **Base64 Encoding**: Additional encoding layer for binary data
- **Certificate Bypass**: SSL verification disabled for testing environments

## 🛠 COMPREHENSIVE FEATURE SET

### 🔍 **Advanced Monitoring & Surveillance**

#### **Keylogging System**
- **Real-time Keystroke Capture**: Records all keyboard input with timestamps
- **Special Key Detection**: Function keys, modifiers, and system keys
- **Buffer Management**: Configurable buffer size with automatic flushing
- **Clipboard Monitoring**: Tracks copied text and data
- **Unicode Support**: Full international character set compatibility

#### **Visual Surveillance**
- **Screenshot Capture**: Periodic desktop screenshots with configurable intervals
- **Image Optimization**: Adjustable quality settings and PNG compression
- **Multi-monitor Support**: Captures all connected displays
- **Stealth Mode**: Silent operation without user notification

#### **System Activity Monitoring**
- **Process Tracking**: Real-time process creation and termination
- **Window Focus Monitoring**: Tracks active application usage
- **Network Activity**: Monitors connections and bandwidth usage
- **User Activity**: Login sessions and idle time detection

### 💻 **System Management & Control**

#### **Information Gathering**
- **Hardware Inventory**: CPU, RAM, disk, and network adapter details
- **Software Audit**: Installed programs, versions, and installation dates
- **System Configuration**: OS version, updates, and security settings
- **Network Topology**: IP addresses, DNS settings, and network interfaces

#### **Process Management**
- **Process Enumeration**: Detailed process list with PID, memory usage, and CPU
- **Remote Process Control**: Start, stop, and terminate processes
- **Process Injection**: Code injection into running processes
- **Service Management**: Windows service control and configuration

#### **File System Operations**
- **File Explorer**: Browse, search, and navigate file systems
- **File Upload/Download**: Transfer files to and from target system
- **File Manipulation**: Read, edit, delete, and execute files
- **Directory Management**: Create, remove, and list directories
- **File Search**: Pattern-based file searching with filters

### 🌐 **Network & Remote Access**

#### **Remote Desktop Control**
- **RDP Enable/Disable**: Activate and configure Windows Remote Desktop
- **Firewall Configuration**: Automatic firewall rule management
- **User Account Creation**: Automated RDP user setup with admin privileges
- **Tailscale Integration**: VPN connectivity for remote access
- **DNS Configuration**: Custom DNS server setup

#### **Network Reconnaissance**
- **WiFi Credential Extraction**: Recovers stored WiFi passwords and profiles
- **Network Adapter Info**: Detailed network interface configuration
- **Connection Monitoring**: Active network connections and ports
- **DNS Cache Examination**: Review DNS resolution history

### 🔒 **Security & Evasion**

#### **Antivirus Detection & Evasion**
- **AV Product Detection**: Identifies 50+ antivirus and security products
- **Behavioral Adjustment**: Automatically modifies behavior based on detected AV
- **Process Analysis**: Monitors security software processes
- **Registry Scanning**: Detects security software installations
- **Driver Inspection**: Identifies security drivers and filters

#### **Virtual Machine Detection**
- **Multi-method Detection**: Hardware, registry, and process-based VM identification
- **VMware/VirtualBox/Hyper-V**: Specific detection for major hypervisors
- **Self-destruct Capability**: Automatic cleanup if VM environment detected
- **Aggressive Mode**: Enhanced detection for security research

#### **Persistence Mechanisms**
- **Registry Persistence**: Startup entries in multiple registry locations
- **Service Installation**: Windows service installation for elevated persistence
- **Scheduled Tasks**: Task scheduler integration for execution
- **Fileless Techniques**: Memory-based execution where possible

### 🌐 **Browser Data Collection**

#### **Comprehensive Browser Support**
- **Google Chrome**: Full profile data extraction
- **Mozilla Firefox**: History, cookies, and session data
- **Microsoft Edge**: Complete data collection including passwords
- **Brave Browser**: Chromium-based browser support
- **Opera**: Legacy and new versions support

#### **Data Extraction Types**
- **Browsing History**: Complete URL history with timestamps
- **Saved Passwords**: Decrypted login credentials (if enabled)
- **Cookies & Sessions**: Authentication tokens and session data
- **Bookmarks & Favorites**: Organized browsing preferences
- **Download History**: File download records and locations
- **Form Data**: Auto-fill information and saved form entries
- **Credit Card Information**: Saved payment details (if accessible)
- **Extensions & Add-ons**: Installed browser extensions list

#### **Advanced Collection Features**
- **Automatic Browser Detection**: Identifies installed browsers automatically
- **Profile Management**: Handles multiple user profiles
- **Encrypted Data Decryption**: Master key extraction for Chromium browsers
- **SQLite Database Handling**: Direct database access for data extraction

### ⚡ **Advanced Capabilities**

#### **Command & Control**
- **Remote Command Execution**: PowerShell, CMD, and system commands
- **Script Execution**: Batch files, VBScript, and other scripting languages
- **Dynamic Command Processing**: Real-time command parsing and execution
- **Result Collection**: Comprehensive output capture and reporting

#### **System Control**
- **Power Management**: Shutdown, restart, sleep, and hibernate
- **User Session Control**: Logoff, lock, and session management
- **Application Control**: Start and stop applications remotely
- **System Configuration**: Modify system settings and configurations

#### **Data Exfiltration**
- **Compressed Transfers**: Gzip compression for large data sets
- **Chunked Uploads**: Large file handling with resume capability
- **Encrypted Storage**: Local encrypted caching if server unavailable
- **Bandwidth Management**: Configurable transfer rates and limits

### 🔄 **Update & Maintenance**

#### **Auto-Update System**
- **Version Checking**: Periodic update availability checks
- **Silent Installation**: Background download and installation
- **Rollback Protection**: Version validation and integrity checking
- **Update Verification**: Digital signature verification (if configured)

#### **Self-Preservation**
- **Error Recovery**: Automatic restart on failure
- **Stealth Operation**: Minimal footprint and detection avoidance
- **Cleanup Procedures**: Evidence removal and trace elimination
- **Emergency Protocols**: Self-destruct and cleanup mechanisms

## 📥 Installation & Setup

### System Requirements
- **OS**: Windows 7/8/10/11 (32-bit or 64-bit)
- **Python**: 3.8 or higher (for source version)
- **RAM**: 512MB minimum, 1GB recommended
- **Storage**: 100MB free space
- **Permissions**: Administrator privileges for full functionality

### Quick Deployment
```bash
# Method 1: Pre-built Executable
# Download ItaMessengerService.exe from releases
# Run with administrator privileges

# Method 2: From Source
git clone https://github.com/FarhamAghdasi/python-rat.git
cd python-rat
pip install -r requirements.txt
python build.py
```

### Configuration
Edit `.env` file for customization:
```env
SERVER_URL=https://your-server.com/api
ENCRYPTION_KEY=your_base64_encryption_key
ENABLE_KEYLOGGING=true
ENABLE_SCREENSHOTS=true
# ... additional settings
```

## 🚀 Usage Examples

### Basic Monitoring
```python
# The service starts automatically and begins:
# - Recording keystrokes
# - Capturing screenshots
# - Monitoring system activity
# - Reporting to configured server
```

### Remote Commands
Supported command types include:
- `system_info` - Comprehensive system inventory
- `screenshot` - Capture current desktop
- `file_operation` - Browse and manage files
- `process_management` - Control running processes
- `execute_powershell` - Run PowerShell commands
- `get_wifi_passwords` - Extract WiFi credentials

## 🔧 Technical Details

### Encryption Implementation
- **Algorithm**: AES-256-CBC with PKCS7 padding
- **Key Derivation**: PBKDF2 with 100,000 iterations
- **IV Generation**: Cryptographically secure random IVs
- **Data Format**: base64(ciphertext)::base64(IV)

### Network Protocol
- **Transport**: HTTPS with configurable proxies
- **Polling Interval**: Configurable command check frequency
- **Data Format**: JSON with encrypted payloads
- **Compression**: Gzip for large data transfers

### Persistence Methods
- **Registry**: HKCU\Software\Microsoft\Windows\CurrentVersion\Run
- **Service**: Windows service installation (elevated privileges)
- **Scheduled Task**: Task Scheduler for periodic execution
- **Startup Folder**: User startup directory

## 📊 Performance Characteristics

- **Memory Usage**: 50-100MB typical
- **CPU Usage**: <2% average
- **Network Usage**: Configurable based on features
- **Storage**: <100MB installation size

## 🛡 Security Considerations

### Detection Avoidance
- **Code Signing**: Fake digital signatures and version information
- **Process Names**: Legitimate-sounding process names
- **Behavior Analysis**: Anti-analysis techniques for debuggers
- **Network Stealth**: Encrypted and obfuscated communications

### Operational Security
- **Data Encryption**: All sensitive data encrypted at rest and in transit
- **Secure Deletion**: Proper cleanup of temporary files
- **Log Management**: Configurable logging with size limits
- **Error Handling**: Graceful failure without exposing information

## 📚 Documentation

- **[Full Feature Documentation](docs/features.md)**
- **[Installation Guide](docs/installation.md)**
- **[Configuration Reference](docs/configuration.md)**
- **[API Documentation](docs/api.md)**
- **[Troubleshooting](docs/troubleshooting.md)**

## 📝 Release Notes

### Version 1.5.0 Highlights
- ✅ Advanced automatic browser detection system
- ✅ Comprehensive browser data collection improvements
- ✅ Windows credential extraction capabilities
- ✅ Enhanced error handling and recovery
- ✅ Performance optimizations and bug fixes

**For complete release history, see [CHANGELOG.md](CHANGELOG.md)**

## ⚖️ Legal & Ethical Use

This tool is designed for:
- ✅ Authorized penetration testing
- ✅ Educational and research purposes
- ✅ Legitimate system administration
- ✅ Security research and development

**Prohibited uses include:**
- ❌ Unauthorized system access
- ❌ Illegal surveillance activities
- ❌ Malicious attacks on systems
- ❌ Any activity without proper authorization

## 🤝 Contributing

Contributions are welcome! Please read our contributing guidelines and ensure all code submissions include appropriate tests and documentation.

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

- **Documentation**: [Full Docs](docs/)
- **Issues**: [GitHub Issues](https://github.com/your-repo/issues)
- **Discussions**: [Community Forum](https://github.com/your-repo/discussions)

---

**🔒 Remember: Always obtain proper authorization before using this tool. Responsible use is mandatory.**