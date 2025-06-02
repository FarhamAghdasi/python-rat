<?php
class Config {
    // Connection Settings
    public static $SERVER_URL = "https://example.com/api.php"; // آدرس سرور
    public static $BOT_TOKEN = ""; // توکن بات تلگرام
    public static $SECRET_TOKEN = "1"; // توکن مخفی برای کلاینت‌ها
    public static $ENCRYPTION_KEY = "nTds2GHvEWeOGJibjZuaf8kY5T5YWyfMx4J3B1NA0Jo="; // کلید رمزنگاری (base64)
    public static $ADMIN_CHAT_ID = "";
    public static $ONLINE_THRESHOLD = 300;
    public static $WEBHOOK_SECRET = "your-webhook-secret";
    public static $BASE_URL = 'http://your-server.com';

    
    // Database Settings
    public static $DB_HOST = "localhost";
    public static $DB_NAME = "rat";
    public static $DB_USER = "root";
    public static $DB_PASS = "";
    
    // File Paths
    public static $SCREENSHOT_DIR = __DIR__ . "/screenshots/";
    public static $UPLOAD_DIR = __DIR__ . "/uploads/";
    public static $ERROR_LOG = __DIR__ . "/log/error.log";
    public static $WEBHOOK_LOG = __DIR__ . "/log/webhook.log";
    public static $TELEGRAM_LOG = __DIR__ . "/log/telegram_update.log";
    
    // Other Settings
    public static $COMMAND_TIMEOUT = 10; // ثانیه
    public static $MAX_LOG_SIZE = 1024 * 1024; // 1MB
}
?>