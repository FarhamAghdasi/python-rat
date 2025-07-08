<?php
require_once __DIR__ . '/load_env.php';
loadEnv(__DIR__ . '/../.env');

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
    public static $MAX_LOG_SIZE = 1024 * 1024;
    public static $ONLINE_THRESHOLD = 300;

    public static function init() {
        self::$BASE_URL         = $_ENV['BASE_URL'];
        self::$SERVER_URL       = self::$BASE_URL . "/api.php";
        self::$BOT_TOKEN        = $_ENV['BOT_TOKEN'];
        self::$WEBHOOK_SECRET   = $_ENV['WEBHOOK_SECRET'];
        self::$ADMIN_CHAT_ID    = $_ENV['ADMIN_CHAT_ID'];
        self::$CLIENT_VERSION = $_ENV['CLIENT_VERSION'] ?? '0.0';

        self::$DB_HOST = $_ENV['DB_HOST'];
        self::$DB_NAME = $_ENV['DB_NAME'];
        self::$DB_USER = $_ENV['DB_USER'];
        self::$DB_PASS = $_ENV['DB_PASS'];

        self::$ERROR_LOG      = __DIR__ . "/../log/error.log";
        self::$WEBHOOK_LOG    = __DIR__ . "/../log/webhook.log";
        self::$TELEGRAM_LOG   = __DIR__ . "/../log/telegram_update.log";

        self::$SCREENSHOT_DIR = __DIR__ . "/../screenshots/";
        self::$UPLOAD_DIR     = __DIR__ . "/../uploads/";
    }
}
