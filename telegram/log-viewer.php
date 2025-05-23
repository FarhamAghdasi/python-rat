<?php
// بارگذاری فایل Config.php
require_once __DIR__ . '/Config.php';

// تنظیمات سشن
ini_set('session.cookie_secure', 0); // برای تست روی HTTP (برای تولید به 1 برگردونید)
ini_set('session.cookie_httponly', 1);
ini_set('session.cookie_samesite', 'Lax');

// شروع سشن
session_start();

// اتصال به دیتابیس با PDO
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

// تابع رمزگشایی
function decrypt($encryptedData, $key) {
    try {
        if (!$encryptedData || !is_string($encryptedData)) {
            error_log("Decrypt: No data or invalid type: " . var_export($encryptedData, true), 3, Config::$ERROR_LOG);
            return '[No data]';
        }

        // اگر داده فرمت AES (ciphertext::iv) داره
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

            // چک کردن اینکه داده JSONه یا نه
            $jsonDecoded = json_decode($decrypted, true);
            if ($jsonDecoded !== null) {
                error_log("Decrypt: JSON detected, formatting", 3, Config::$ERROR_LOG);
                return json_encode($jsonDecoded, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
            }

            return $decrypted; // اگر JSON نبود، متن خام
        }

        // اگر داده AES نبود، فرض می‌کنیم base64 + gzipه
        error_log("Decrypt: No IV separator, trying base64 + gzip: " . substr($encryptedData, 0, 50), 3, Config::$ERROR_LOG);

        $base64Decoded = base64_decode($encryptedData, true);
        if ($base64Decoded === false) {
            error_log("Decrypt: Base64 decode failed: " . substr($encryptedData, 0, 50), 3, Config::$ERROR_LOG);
            return $encryptedData; // فال‌بک به داده خام
        }

        $uncompressed = @gzdecode($base64Decoded);
        if ($uncompressed === false) {
            error_log("Decrypt: Gzip decode failed: " . substr($base64Decoded, 0, 50), 3, Config::$ERROR_LOG);
            return $base64Decoded; // فال‌بک به داده base64-decoded
        }

        error_log("Decrypt: Gzip decoded: " . substr($uncompressed, 0, 50), 3, Config::$ERROR_LOG);

        // چک کردن اینکه داده JSONه یا نه
        $jsonDecoded = json_decode($uncompressed, true);
        if ($jsonDecoded !== null) {
            error_log("Decrypt: JSON detected, formatting", 3, Config::$ERROR_LOG);
            return json_encode($jsonDecoded, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        }

        return $uncompressed; // متن خام
    } catch (Exception $e) {
        error_log("Decrypt error: " . $e->getMessage() . ", raw data: " . substr($encryptedData, 0, 50), 3, Config::$ERROR_LOG);
        return '[Decryption error: ' . htmlspecialchars($e->getMessage()) . ']';
    }
}

// رمز عبور هش‌شده برای داشبورد
$stored_hash = '$2y$10$YOUR_HASH_HERE'; // با password_hash('your_password', PASSWORD_BCRYPT) تولید کنید

// بررسی ورود
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

// خروج
if (isset($_GET['logout'])) {
    session_destroy();
    header("Location: log-viewer.php");
    exit;
}

// دریافت لاگ‌ها با AJAX
if (isset($_GET['get_logs']) && $logged_in) {
    header('Content-Type: application/json');
    try {
        $stmt = $pdo->query("
            SELECT id, client_id, command, status, result, created_at, updated_at, completed_at
            FROM client_commands
            ORDER BY created_at DESC LIMIT 100
        ");
        $logs = $stmt->fetchAll();
        
        foreach ($logs as &$log) {
            $log['raw_result'] = $log['result']; // ذخیره داده خام
            $log['command'] = decrypt($log['command'], Config::$ENCRYPTION_KEY);
            $log['result'] = $log['result'] ? decrypt($log['result'], Config::$ENCRYPTION_KEY) : '';
        }
        
        echo json_encode(['logs' => $logs]);
    } catch (PDOException $e) {
        error_log("Failed to fetch logs: " . $e->getMessage(), 3, Config::$ERROR_LOG);
        echo json_encode(['error' => 'Failed to fetch logs: ' . htmlspecialchars($e->getMessage())]);
    }
    exit;
}

// دانلود لاگ
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

        // رمزگشایی
        $raw_result = $log['result'];
        $log['command'] = decrypt($log['command'], Config::$ENCRYPTION_KEY);
        $log['result'] = $log['result'] ? decrypt($log['result'], Config::$ENCRYPTION_KEY) : 'No result';

        // تولید محتوای فایل
        $content = "Client ID: {$log['client_id']}\n";
        $content .= "Command: {$log['command']}\n";
        $content .= "Status: {$log['status']}\n";
        $content .= "Result:\n{$log['result']}\n";
        $content .= "Created At: {$log['created_at']}\n";
        $content .= "Completed At: " . ($log['completed_at'] ? $log['completed_at'] : 'N/A') . "\n";

        // تنظیم هدرها برای دانلود
        header('Content-Type: text/plain');
        header('Content-Disposition: attachment; filename="log_' . $log_id . '.txt"');
        header('Content-Length: ' . strlen($content));
        echo $content;
        exit;
    } catch (PDOException $e) {
        error_log("Failed to download log: " . $e->getMessage(), 3, Config::$ERROR_LOG);
        die("Failed to download log");
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
        .log-entry {
            transition: transform 0.3s ease;
            cursor: pointer;
        }
        .log-entry:hover {
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
            0%, 100% {
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
            <!-- فرم ورود -->
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
            <!-- داشبورد لاگ‌ها -->
            <div class="flex justify-between items-center mb-8 fade-in">
                <h1 class="text-4xl font-bold black-hole-glow">Galaxy Client Commands</h1>
                <a href="?logout" class="py-2 px-4 bg-red-600 hover:bg-red-700 rounded-md text-white">
                    Logout
                </a>
            </div>
            <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
                <!-- لاگ‌های Completed -->
                <div class="glass-card rounded-xl p-6">
                    <h2 class="text-2xl font-semibold text-green-400 mb-4">Completed Commands</h2>
                    <div id="completed-logs" class="space-y-4 max-h-[70vh] overflow-y-auto"></div>
                </div>
                <!-- لاگ‌های Pending -->
                <div class="glass-card rounded-xl p-6">
                    <h2 class="text-2xl font-semibold text-yellow-400 mb-4">Pending Commands</h2>
                    <div id="pending-logs" class="space-y-4 max-h-[70vh] overflow-y-auto"></div>
                </div>
                <!-- لاگ‌های Failed -->
                <div class="glass-card rounded-xl p-6">
                    <h2 class="text-2xl font-semibold text-red-400 mb-4">Failed Commands</h2>
                    <div id="failed-logs" class="space-y-4 max-h-[70vh] overflow-y-auto"></div>
                </div>
            </div>
            <!-- مودال تمام‌صفحه -->
            <div id="log-modal" class="modal">
                <div class="modal-content">
                    <div class="flex justify-between items-center mb-4">
                        <h2 class="text-2xl font-semibold text-yellow-400">Log Details</h2>
                        <button id="close-modal" class="text-gray-400 hover:text-white text-2xl">×</button>
                    </div>
                    <div class="space-y-4">
                        <p><strong>Client ID:</strong> <span id="modal-client-id"></span></p>
                        <p><strong>Command:</strong> <span id="modal-command"></span></p>
                        <p><strong>Status:</strong> <span id="modal-status"></span></p>
                        <p><strong>Created At:</strong> <span id="modal-created-at"></span></p>
                        <p><strong>Completed At:</strong> <span id="modal-completed-at"></span></p>
                        <div>
                            <div class="tabs">
                                <div class="tab active" data-tab="decrypted">Decrypted Result</div>
                                <div class="tab" data-tab="raw">Raw Result</div>
                            </div>
                            <textarea class="editor" id="modal-result-decrypted" readonly></textarea>
                            <textarea class="editor" id="modal-result-raw" readonly style="display: none;"></textarea>
                        </div>
                        <button id="download-log" class="py-2 px-4 bg-green-600 hover:bg-green-700 rounded-md text-white font-semibold">
                            Download Log
                        </button>
                    </div>
                </div>
            </div>
        <?php endif; ?>
    </div>

    <?php if ($logged_in): ?>
        <script>
            function fetchLogs() {
                fetch('?get_logs', {
                    method: 'GET',
                    headers: { 'Accept': 'application/json' }
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
                            logElement.addEventListener('click', () => openModal(log));
                            completedLogs.appendChild(logElement);
                        } else if (log.status === 'pending') {
                            pendingLogs.appendChild(logElement);
                        } else if (log.status === 'failed') {
                            failedLogs.appendChild(logElement);
                        }
                    });
                })
                .catch(error => console.error('Error fetching logs:', error));
            }

            function openModal(log) {
                const modal = document.getElementById('log-modal');
                document.getElementById('modal-client-id').textContent = log.client_id;
                document.getElementById('modal-command').textContent = log.command;
                document.getElementById('modal-status').textContent = log.status;
                document.getElementById('modal-created-at').textContent = new Date(log.created_at).toLocaleString();
                document.getElementById('modal-completed-at').textContent = log.completed_at ? new Date(log.completed_at).toLocaleString() : 'N/A';
                document.getElementById('modal-result-decrypted').value = log.result || 'No result';
                document.getElementById('modal-result-raw').value = log.raw_result || 'No raw result';

                const downloadButton = document.getElementById('download-log');
                downloadButton.onclick = () => {
                    window.location.href = `?download_log&log_id=${log.id}`;
                };

                // مدیریت تب‌ها
                const tabs = document.querySelectorAll('.tab');
                const decryptedEditor = document.getElementById('modal-result-decrypted');
                const rawEditor = document.getElementById('modal-result-raw');

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

                // تنظیم تب اولیه
                tabs[0].classList.add('active');
                decryptedEditor.style.display = 'block';
                rawEditor.style.display = 'none';

                modal.style.display = 'block';
            }

            document.getElementById('close-modal').addEventListener('click', () => {
                document.getElementById('log-modal').style.display = 'none';
            });

            window.addEventListener('click', (event) => {
                if (event.target === document.getElementById('log-modal')) {
                    document.getElementById('log-modal').style.display = 'none';
                }
            });

            // دریافت لاگ‌ها در شروع
            fetchLogs();
            // به‌روزرسانی هر 5 ثانیه
            setInterval(fetchLogs, 5000);
        </script>
    <?php endif; ?>
</body>
</html>