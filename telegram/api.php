<?php
require_once __DIR__ . '/config.php';
Config::init();

require_once __DIR__ . '/src/Autoloader.php';

// Register autoloader
Autoloader::register();

use Handlers\ClientRequestHandler;
use Handlers\WebhookHandler;
use Utils\DirectoryInitializer;
use Database\DatabaseConnection;

// Initialize directories
DirectoryInitializer::init([
    Config::$SCREENSHOT_DIR,
    Config::$UPLOAD_DIR,
    dirname(Config::$ERROR_LOG)
]);

// Initialize database
$db = new DatabaseConnection();
$pdo = $db->getPdo();

// Initialize handlers
$clientHandler = new ClientRequestHandler($pdo);
$webhookHandler = new WebhookHandler($pdo);

// Handle incoming request
$rawInput = file_get_contents('php://input');
$input = json_decode($rawInput, true) ?: [];

if (
    isset($_SERVER['HTTP_X_TELEGRAM_BOT_API_SECRET_TOKEN']) &&
    $_SERVER['HTTP_X_TELEGRAM_BOT_API_SECRET_TOKEN'] === Config::$WEBHOOK_SECRET
) {
    $webhookHandler->handle($input);
} elseif (
    (isset($_SERVER['HTTP_X_SECRET_TOKEN']) && $_SERVER['HTTP_X_SECRET_TOKEN'] === Config::$SECRET_TOKEN) ||
    (isset($input['token']) && $input['token'] === Config::$SECRET_TOKEN) ||
    (isset($_POST['token']) && $_POST['token'] === Config::$SECRET_TOKEN)
) {
    $clientHandler->handle($input);
} else {
    http_response_code(401);
    error_log("Unauthorized access attempt. Headers: " . json_encode($_SERVER));
    die(json_encode(['error' => 'Unauthorized']));
}
