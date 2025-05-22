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
        if (!$encryptedData || !is_string($encryptedData) || !str_contains($encryptedData, '::')) {
            return $encryptedData;
        }

        list($ciphertext, $iv) = explode('::', $encryptedData, 2);
        if (empty($ciphertext) || empty($iv)) {
            return '[Decryption failed: Invalid format]';
        }

        $ivDecoded = base64_decode($iv, true);
        if ($ivDecoded === false || strlen($ivDecoded) !== 16) {
            return '[Decryption failed: Invalid IV]';
        }

        $keyDecoded = base64_decode($key);
        if (!$keyDecoded) {
            return '[Decryption failed: Invalid key]';
        }

        $decrypted = openssl_decrypt(
            $ciphertext,
            'aes-256-cbc',
            $keyDecoded,
            0,
            $ivDecoded
        );

        return $decrypted !== false ? $decrypted : '[Decryption failed]';
    } catch (Exception $e) {
        error_log("Decryption error: " . $e->getMessage(), 3, Config::$ERROR_LOG);
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
        header("Location: index.php");
        exit;
    } else {
        $error = "Invalid password";
    }
}

// خروج
if (isset($_GET['logout'])) {
    session_destroy();
    header("Location: index.php");
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
            background: url('https://images.unsplash.com/photo-1446776811953-b23d57bd21aa?q=80&w=2072&auto=format&fit=crop');
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
                        logElement.innerHTML = `
                            <p class="text-sm text-gray-400">${new Date(log.created_at).toLocaleString()}</p>
                            <p class="text-gray-200"><strong>Client ID:</strong> ${log.client_id}</p>
                            <p class="text-gray-200"><strong>Command:</strong> ${log.command}</p>
                            <p class="text-gray-200"><strong>Result:</strong> ${log.result || 'No result'}</p>
                            <p class="text-gray-200"><strong>Status:</strong> ${log.status}</p>
                            <p class="text-gray-200"><strong>Completed At:</strong> ${log.completed_at ? new Date(log.completed_at).toLocaleString() : 'N/A'}</p>
                        `;

                        if (log.status === 'completed') {
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

            // دریافت لاگ‌ها در شروع
            fetchLogs();
            // به‌روزرسانی هر 5 ثانیه
            setInterval(fetchLogs, 5000);
        </script>
    <?php endif; ?>
</body>
</html>