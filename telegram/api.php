<?php
// تنظیمات خطا برای debugging (در production غیرفعال کنید)
error_reporting(E_ALL);
ini_set('display_errors', 0); // در production باید 0 باشد
ini_set('log_errors', 1);

require_once __DIR__ . '/config.php';
Config::init();

// بررسی تنظیمات
$configErrors = Config::validate();
if (!empty($configErrors)) {
    error_log("Configuration errors: " . implode(", ", $configErrors));
    http_response_code(500);
    die(json_encode(['error' => 'Server configuration error']));
}

require_once __DIR__ . '/src/Autoloader.php';
Autoloader::register();

use Handlers\ClientRequestHandler;
use Handlers\WebhookHandler;
use Utils\DirectoryInitializer;
use Database\DatabaseConnection;

// ایجاد دایرکتوری‌ها
DirectoryInitializer::init([
    Config::$SCREENSHOT_DIR,
    Config::$UPLOAD_DIR,
    dirname(Config::$ERROR_LOG)
]);

// لاگ شروع درخواست
$requestLog = [
    'time' => date('Y-m-d H:i:s'),
    'method' => $_SERVER['REQUEST_METHOD'] ?? 'unknown',
    'uri' => $_SERVER['REQUEST_URI'] ?? 'unknown',
    'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
    'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown'
];
error_log("API Request: " . json_encode($requestLog));

try {
    // اتصال به دیتابیس
    $db = new DatabaseConnection();
    $pdo = $db->getPdo();
    
    error_log("Database connected successfully");

    // خواندن ورودی
    $rawInput = file_get_contents('php://input');
    $input = json_decode($rawInput, true) ?: [];
    
    // لاگ ورودی
    if (!empty($rawInput)) {
        error_log("Raw input: " . substr($rawInput, 0, 500));
    }

    // ایجاد هندلرها
    $clientHandler = new ClientRequestHandler($pdo);
    $webhookHandler = new WebhookHandler($pdo);

    // تشخیص نوع درخواست
    $isWebhook = false;
    $isClient = false;
    $authSource = 'none';

    // بررسی Webhook
    if (
        isset($_SERVER['HTTP_X_TELEGRAM_BOT_API_SECRET_TOKEN']) &&
        $_SERVER['HTTP_X_TELEGRAM_BOT_API_SECRET_TOKEN'] === Config::$WEBHOOK_SECRET
    ) {
        $isWebhook = true;
        $authSource = 'telegram_webhook';
        error_log("Request authenticated as Telegram webhook");
    }
    // بررسی Client
    elseif (
        (isset($_SERVER['HTTP_X_SECRET_TOKEN']) && $_SERVER['HTTP_X_SECRET_TOKEN'] === Config::$SECRET_TOKEN) ||
        (isset($input['token']) && $input['token'] === Config::$SECRET_TOKEN) ||
        (isset($_POST['token']) && $_POST['token'] === Config::$SECRET_TOKEN)
    ) {
        $isClient = true;
        $authSource = 'client_token';
        error_log("Request authenticated as client");
    }

    // پردازش درخواست
    if ($isWebhook) {
        error_log("Processing webhook request");
        $webhookHandler->handle($input);
    } elseif ($isClient) {
        error_log("Processing client request");
        $clientHandler->handle($input);
    } else {
        error_log("Unauthorized access attempt from IP: " . ($_SERVER['REMOTE_ADDR'] ?? 'unknown'));
        error_log("Headers: " . json_encode([
            'X-Secret-Token' => $_SERVER['HTTP_X_SECRET_TOKEN'] ?? 'not set',
            'X-Telegram-Bot-Api-Secret-Token' => $_SERVER['HTTP_X_TELEGRAM_BOT_API_SECRET_TOKEN'] ?? 'not set'
        ]));
        
        http_response_code(401);
        die(json_encode(['error' => 'Unauthorized']));
    }

    error_log("Request processed successfully");

} catch (\Exception $e) {
    error_log("API Error: " . $e->getMessage());
    error_log("Stack trace: " . $e->getTraceAsString());
    
    http_response_code(500);
    die(json_encode(['error' => 'Internal server error']));
}