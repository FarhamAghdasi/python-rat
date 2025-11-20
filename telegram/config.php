<?php
require_once __DIR__ . '/load_env.php';
loadEnv(__DIR__ . '/.env');

class Config {
    public static $BASE_URL;
    public static $SERVER_URL;
    public static $BOT_TOKEN;
    public static $WEBHOOK_SECRET;
    public static $ADMIN_CHAT_ID;
    public static $SECRET_TOKEN = '1';
    public static $ENCRYPTION_KEY = 'nTds2GHvEWeOGJibjZuaf8kY5T5YWyfMx4J3B1NA0Jo=';

    public static $DB_HOST;
    public static $DB_NAME;
    public static $DB_USER;
    public static $DB_PASS;

    public static $ERROR_LOG;
    public static $WEBHOOK_LOG;
    public static $TELEGRAM_LOG;
    public static $SCREENSHOT_DIR;
    public static $UPLOAD_DIR;
    public static $CLIENT_VERSION;

    public static $COMMAND_TIMEOUT = 10;
    public static $MAX_LOG_SIZE = 1024 * 1024; // 1MB
    public static $ONLINE_THRESHOLD = 300; // 5 minutes

    public static function init() {
        self::$BASE_URL         = $_ENV['BASE_URL'] ?? '';
        self::$SERVER_URL       = self::$BASE_URL . "/api.php";
        self::$BOT_TOKEN        = $_ENV['BOT_TOKEN'] ?? '';
        self::$WEBHOOK_SECRET   = $_ENV['WEBHOOK_SECRET'] ?? '';
        self::$ADMIN_CHAT_ID    = $_ENV['ADMIN_CHAT_ID'] ?? '';
        self::$CLIENT_VERSION   = $_ENV['CLIENT_VERSION'] ?? '1.1';

        self::$DB_HOST = $_ENV['DB_HOST'] ?? 'localhost';
        self::$DB_NAME = $_ENV['DB_NAME'] ?? '';
        self::$DB_USER = $_ENV['DB_USER'] ?? '';
        self::$DB_PASS = $_ENV['DB_PASS'] ?? '';

        // تنظیم مسیرهای لاگ داخل پروژه
        $logDir = __DIR__ . "/logs";
        if (!is_dir($logDir)) {
            mkdir($logDir, 0755, true);
        }

        self::$ERROR_LOG      = $logDir . "/error.log";
        self::$WEBHOOK_LOG    = $logDir . "/webhook.log";
        self::$TELEGRAM_LOG   = $logDir . "/telegram_update.log";

        // تنظیم مسیرهای آپلود و اسکرین‌شات
        self::$SCREENSHOT_DIR = __DIR__ . "/screenshots/";
        self::$UPLOAD_DIR     = __DIR__ . "/uploads/";

        // ایجاد دایرکتوری‌ها
        if (!is_dir(self::$SCREENSHOT_DIR)) {
            mkdir(self::$SCREENSHOT_DIR, 0755, true);
        }
        if (!is_dir(self::$UPLOAD_DIR)) {
            mkdir(self::$UPLOAD_DIR, 0755, true);
        }

        // Override با متغیرهای .env اگر موجود باشند
        if (isset($_ENV['SECRET_TOKEN'])) {
            self::$SECRET_TOKEN = $_ENV['SECRET_TOKEN'];
        }
        if (isset($_ENV['ENCRYPTION_KEY'])) {
            self::$ENCRYPTION_KEY = $_ENV['ENCRYPTION_KEY'];
        }
    }

    public static function validate() {
        $errors = [];
        
        if (empty(self::$BOT_TOKEN)) {
            $errors[] = "BOT_TOKEN is not set";
        }
        if (empty(self::$WEBHOOK_SECRET)) {
            $errors[] = "WEBHOOK_SECRET is not set";
        }
        if (empty(self::$ADMIN_CHAT_ID)) {
            $errors[] = "ADMIN_CHAT_ID is not set";
        }
        if (empty(self::$DB_NAME)) {
            $errors[] = "DB_NAME is not set";
        }
        if (empty(self::$DB_USER)) {
            $errors[] = "DB_USER is not set";
        }
        
        return $errors;
    }
}