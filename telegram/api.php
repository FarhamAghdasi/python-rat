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
use Handlers\FileManagerHandler;
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
    $fileManagerHandler = new FileManagerHandler($pdo);

    // تشخیص نوع درخواست
    $isWebhook = false;
    $isClient = false;
    $isFileManager = false;
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
    // بررسی Client (شامل File Manager)
    elseif (
        (isset($_SERVER['HTTP_X_SECRET_TOKEN']) && $_SERVER['HTTP_X_SECRET_TOKEN'] === Config::$SECRET_TOKEN) ||
        (isset($input['token']) && $input['token'] === Config::$SECRET_TOKEN) ||
        (isset($_POST['token']) && $_POST['token'] === Config::$SECRET_TOKEN)
    ) {
        // تشخیص اینکه درخواست File Manager است یا Client Request عادی
        if (isset($input['action']) && str_starts_with($input['action'], 'file_')) {
            $isFileManager = true;
            $authSource = 'file_manager';
            error_log("Request authenticated as file manager");
        } else {
            $isClient = true;
            $authSource = 'client_token';
            error_log("Request authenticated as client");
        }
    }
    // بررسی Client از طریق POST data (برای File Manager)
    elseif (!empty($_POST)) {
        $postToken = $_POST['token'] ?? $_POST['X-Secret-Token'] ?? null;
        if ($postToken === Config::$SECRET_TOKEN) {
            $action = $_POST['action'] ?? $input['action'] ?? null;
            if ($action && str_starts_with($action, 'file_')) {
                $isFileManager = true;
                $authSource = 'file_manager_post';
                error_log("Request authenticated as file manager (POST)");
            } else {
                $isClient = true;
                $authSource = 'client_token_post';
                error_log("Request authenticated as client (POST)");
            }
        }
    }

    // پردازش درخواست
    if ($isWebhook) {
        error_log("Processing webhook request");
        $webhookHandler->handle($input);
    } elseif ($isClient) {
        error_log("Processing client request");
        $clientHandler->handle($input);
    } elseif ($isFileManager) {
        error_log("Processing file manager request");
        // برای File Manager، از $_POST هم استفاده کن
        $fileManagerData = array_merge($input, $_POST);
        $fileManagerHandler->handle($fileManagerData);
    } else {
        error_log("Unauthorized access attempt from IP: " . ($_SERVER['REMOTE_ADDR'] ?? 'unknown'));
        error_log("Headers: " . json_encode([
            'X-Secret-Token' => $_SERVER['HTTP_X_SECRET_TOKEN'] ?? 'not set',
            'X-Telegram-Bot-Api-Secret-Token' => $_SERVER['HTTP_X_TELEGRAM_BOT_API_SECRET_TOKEN'] ?? 'not set'
        ]));
        error_log("POST data: " . json_encode($_POST));
        error_log("Input data: " . json_encode($input));
        
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