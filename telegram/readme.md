# Galaxy Client Commands

Galaxy Client Commands is a PHP-based server application designed to manage and monitor client interactions through a Telegram bot and a web-based dashboard. It provides a robust framework for handling client commands, logging activities, and managing data such as keystrokes, system information, screenshots, Wi-Fi passwords, and RDP connections. The application uses a MySQL database for persistent storage and includes encryption for secure data handling.

## Table of Contents
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Project Structure](#project-structure)
- [Configuration](#configuration)
- [Usage](#usage)
  - [Setting Up the Webhook](#setting-up-the-webhook)
  - [Accessing the Dashboard](#accessing-the-dashboard)
  - [Interacting via Telegram](#interacting-via-telegram)
- [Security Considerations](#security-considerations)
- [Database Schema](#database-schema)
- [Contributing](#contributing)
- [License](#license)

## Features
- **Telegram Bot Integration**: Allows admin users to interact with clients via Telegram commands, including selecting clients, issuing commands, and receiving updates.
- **Web Dashboard**: A responsive, Tailwind CSS-styled dashboard for viewing command logs, client data, VM detection status, Wi-Fi passwords, and RDP connection details.
- **Command Handling**: Supports a variety of client commands such as system status checks, screenshot capture, file operations, and RDP management.
- **Data Encryption**: Uses AES-256-CBC encryption to secure sensitive data like keystrokes, system info, and command results.
- **Database Management**: Stores client commands, logs, and user data in a MySQL database with a well-defined schema.
- **Autoloading**: Implements a custom autoloader for efficient class loading within the `src` directory.
- **Logging**: Comprehensive logging system for errors, webhook activities, and command execution details.
- **Directory Initialization**: Automatically creates necessary directories for logs, screenshots, and uploads.

## Requirements
- **PHP**: Version 7.4 or higher
- **MySQL**: Version 5.7 or higher
- **Web Server**: Apache or Nginx
- **Composer**: For dependency management (optional, as dependencies are minimal)
- **cURL**: PHP extension for making HTTP requests
- **OpenSSL**: PHP extension for encryption
- **PDO**: PHP extension for MySQL database connectivity
- **Telegram Bot Token**: Obtainable from BotFather on Telegram
- **Server with HTTPS**: Required for secure webhook communication

## Installation
1. **Clone the Repository**:
   ```bash
   git clone <repository-url>
   cd galaxy-client-commands
   ```

2. **Set Up the Environment File**:
   - Create a `.env` file in the project root.
   - Add the following environment variables:
     ```plaintext
     BASE_URL=https://your-domain.com
     BOT_TOKEN=your-telegram-bot-token
     WEBHOOK_SECRET=your-webhook-secret-token
     ADMIN_CHAT_ID=your-telegram-chat-id
     DB_HOST=localhost
     DB_NAME=logger
     DB_USER=your-db-user
     DB_PASS=your-db-password
     ```

3. **Install Dependencies**:
   - Ensure PHP extensions (`curl`, `openssl`, `pdo_mysql`) are enabled.
   - No external Composer dependencies are required for this project.

4. **Set Up the Database**:
   - Create a MySQL database named `logger` (or as specified in `.env`).
   - Run the `database-installer/install-db.php` script to initialize the schema:
     ```bash
     php database-installer/install-db.php
     ```

5. **Configure Web Server**:
   - Point your web server to the project root.
   - Ensure the `viewer` and `webhook` directories are accessible.
   - For Apache, enable `.htaccess` support if needed.
   - For Nginx, configure appropriate rewrite rules to handle PHP files.

6. **Set Directory Permissions**:
   - Ensure the `log`, `screenshots`, and `uploads` directories are writable by the web server:
     ```bash
     chmod -R 755 log screenshots uploads
     ```

7. **Set Up the Telegram Webhook**:
   - Run the `webhook/setWebhook.php` script to configure the Telegram webhook:
     ```bash
     php webhook/setWebhook.php
     ```

## Project Structure
The project follows a modular structure for maintainability and scalability:

```
├── api.php                 # Main API endpoint for client and webhook requests
├── config.php              # Configuration class for environment variables
├── ip.php                  # Utility to retrieve client IP address
├── load_env.php            # Loads environment variables from .env file
├── version.php             # Provides version information and update details
├── database-installer/     # Database setup scripts
│   ├── install-db.php      # Initializes database schema and admin user
│   └── schema.sql          # SQL schema for the logger database
├── src/                    # Core application logic
│   ├── Autoloader.php      # Custom autoloader for PHP classes
│   ├── Database/           # Database-related classes
│   │   └── DatabaseConnection.php
│   ├── Handlers/           # Request and webhook handlers
│   │   ├── CallbackQueryHandler.php
│   │   ├── ClientRequestHandler.php
│   │   └── WebhookHandler.php
│   ├── Services/           # Service classes for business logic
│   │   ├── ClientService.php
│   │   ├── EncryptionService.php
│   │   ├── LoggerService.php
│   │   └── TelegramService.php
│   └── Utils/              # Utility classes
│       └── DirectoryInitializer.php
├── viewer/                 # Web dashboard for log and data visualization
│   └── log-viewer.php
├── webhook/                # Webhook configuration
│   └── setWebhook.php
└── .env                    # Environment configuration file (not included)
```

## Configuration
- **.env File**: Contains sensitive configuration such as database credentials, Telegram bot token, and webhook secret. Ensure this file is not publicly accessible.
- **Config.php**: Centralizes configuration loading and provides static access to environment variables.
- **Directory Initialization**: The `DirectoryInitializer` class ensures that directories for logs, screenshots, and uploads are created automatically.

## Usage
### Setting Up the Webhook
Run the `setWebhook.php` script to register the Telegram webhook:
```bash
php webhook/setWebhook.php
```
This sets the webhook to `api.php` with the specified secret token.

### Accessing the Dashboard
- Navigate to `viewer/log-viewer.php` in your browser.
- Log in using the password defined in `log-viewer.php` (default hash: `$2y$12$Y`).
- The dashboard displays:
  - Completed, pending, and failed commands
  - Client data (keystrokes, system info, screenshots)
  - VM detection status
  - Wi-Fi passwords
  - RDP connection details
- Use the modal views to inspect detailed logs and download data.

### Interacting via Telegram
- Use the Telegram bot to issue commands to clients.
- Supported commands include:
  - `/start`: List available clients
  - `/select <client_id>`: Select a client to issue commands
  - `/status`, `/screenshot`, `/upload`, `/exec`, etc. (see `CallbackQueryHandler.php` for full list)
- Only the admin (defined by `ADMIN_CHAT_ID`) can issue commands.

## Security Considerations
- **Encryption**: Sensitive data is encrypted using AES-256-CBC with a key specified in `.env`.
- **Authentication**: The dashboard requires a password (hashed in `log-viewer.php`). Update the `$stored_hash` variable with a secure password hash.
- **HTTPS**: Ensure the server uses HTTPS to protect webhook and API communications.
- **File Permissions**: Restrict access to the `.env` file and log directories to prevent unauthorized access.
- **Webhook Secret**: Use a strong `WEBHOOK_SECRET` to validate Telegram requests.
- **Database Security**: Use a dedicated database user with minimal permissions.

## Database Schema
The database (`logger`) includes the following tables:
- `command_logs`: Stores Telegram command logs with chat and user IDs.
- `users`: Manages user authentication and admin status.
- `clients`: Tracks client information (ID, IP, online status).
- `client_commands`: Queues and tracks client commands with status and results.
- `user_data`: Stores client-submitted data (keystrokes, system info, screenshots).
- `client_vm_status`: Records VM detection results.
- `client_wifi_data`: Stores Wi-Fi network data.
- `client_logs`: General logs for client activities (e.g., self-destruct, updates).
- `user_selections`: Tracks selected clients for Telegram users.

Run `database-installer/install-db.php` to create these tables and initialize the admin user.

## Contributing
Contributions are welcome! Please follow these steps:
1. Fork the repository.
2. Create a feature branch (`git checkout -b feature/your-feature`).
3. Commit your changes (`git commit -m "Add your feature"`).
4. Push to the branch (`git push origin feature/your-feature`).
5. Open a pull request.

## License
This project is licensed under the MIT License. See the `LICENSE` file for details.
By Farham Aghdasi