<?php
require_once __DIR__ . '/../config.php';
Config::init();

ini_set('session.cookie_secure', 0);
ini_set('session.cookie_httponly', 1);
ini_set('session.cookie_samesite', 'Lax');
ini_set('session.use_cookies', 1);
ini_set('session.use_only_cookies', 1);

session_start();

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

$logged_in = isset($_SESSION['logged_in']) && $_SESSION['logged_in'] === true;

// Login check
if (!$logged_in) {
    header('Location: log-viewer.php');
    exit;
}

// پردازش انتخاب کلاینت
$selectedClient = $_SESSION['selected_client'] ?? null;
if (isset($_GET['select_client'])) {
    $clientId = $_GET['select_client'];
    // اعتبارسنجی client_id
    if (preg_match('/^[a-zA-Z0-9_-]{1,32}$/', $clientId)) {
        $_SESSION['selected_client'] = $clientId;
        $selectedClient = $_SESSION['selected_client'];
    }
}

// دریافت لیست کلاینت‌ها
$clients = [];
try {
    $onlineThreshold = date('Y-m-d H:i:s', time() - 300); // 5 minutes
    $stmt = $pdo->prepare(
        "SELECT client_id, ip_address, last_seen,
                IF(last_seen > ?, 1, 0) as is_online
         FROM clients 
         ORDER BY is_online DESC, last_seen DESC"
    );
    $stmt->execute([$onlineThreshold]);
    $clients = $stmt->fetchAll();
} catch (PDOException $e) {
    error_log("Error fetching clients: " . $e->getMessage());
}
?>
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Galaxy File Manager</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <link rel="stylesheet" href="assets/css/file-manager.css">
</head>

<body class="min-h-screen bg-gradient-to-br from-gray-900 to-black text-gray-200">
    <div id="loading-overlay" class="fixed inset-0 bg-black/80 backdrop-blur-sm flex items-center justify-center z-50 hidden">
        <div class="text-center">
            <div class="w-16 h-16 border-4 border-yellow-500/20 border-t-yellow-500 rounded-full animate-spin mx-auto"></div>
            <p class="mt-4 text-yellow-400">Loading...</p>
        </div>
    </div>

    <!-- Context Menu -->
    <div id="context-menu" class="context-menu">
        <div class="context-menu-item" onclick="fileManager.openFile()">
            <i class="fas fa-folder-open"></i> Open
        </div>
        <div class="context-menu-item" onclick="fileManager.downloadFile()">
            <i class="fas fa-download"></i> Download
        </div>
        <div class="context-menu-item" onclick="fileManager.showRenameDialog()">
            <i class="fas fa-edit"></i> Rename
        </div>
        <div class="context-menu-item" onclick="fileManager.copyFile()">
            <i class="fas fa-copy"></i> Copy
        </div>
        <div class="context-menu-item" onclick="fileManager.moveFile()">
            <i class="fas fa-cut"></i> Move
        </div>
        <div class="context-menu-item" onclick="fileManager.deleteFile()">
            <i class="fas fa-trash text-red-400"></i> Delete
        </div>
        <div class="border-t border-gray-700 my-1"></div>
        <div class="context-menu-item" onclick="fileManager.showProperties()">
            <i class="fas fa-info-circle"></i> Properties
        </div>
    </div>

    <div class="container mx-auto p-4">
        <!-- Header -->
        <div class="glass-card p-6 mb-6">
            <div class="flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
                <div>
                    <h1 class="text-3xl font-bold bg-gradient-to-r from-yellow-400 to-orange-500 bg-clip-text text-transparent">
                        <i class="fas fa-folder-tree mr-3"></i>Galaxy File Manager
                    </h1>
                    <p class="text-gray-400 mt-1">Remote file management system</p>
                </div>
                <div class="flex items-center gap-4">
                    <!-- Client Selector -->
                    <div class="relative">
                        <select id="client-select" class="bg-gray-900 border border-gray-700 rounded-lg px-4 py-2 text-sm focus:outline-none focus:border-yellow-500">
                            <option value="">Select Client</option>
                            <?php foreach ($clients as $client): ?>
                                <option value="<?= htmlspecialchars($client['client_id']) ?>"
                                    <?= $selectedClient === $client['client_id'] ? 'selected' : '' ?>
                                    data-online="<?= $client['is_online'] ?>">
                                    <?= htmlspecialchars($client['client_id']) ?>
                                    (<?= htmlspecialchars($client['ip_address']) ?>)
                                    <span class="<?= $client['is_online'] ? 'text-green-400' : 'text-red-400' ?>">
                                        • <?= $client['is_online'] ? '🟢 Online' : '🔴 Offline' ?>
                                    </span>
                                </option>
                            <?php endforeach; ?>
                        </select>
                    </div>
                    <div class="flex gap-2">
                        <button onclick="window.location.href='file-manager.php'" class="btn btn-secondary">
                            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z" />
                            </svg>
                            <span class="ml-2">File Manager</span>
                        </button>
                        <a href="log-viewer.php?logout"
                            class="px-4 py-2 bg-red-900/30 hover:bg-red-800/40 text-red-400 rounded-lg transition flex items-center gap-2">
                            <i class="fas fa-sign-out-alt"></i> Logout
                        </a>
                    </div>
                </div>
            </div>
        </div>

        <?php if (!$selectedClient): ?>
            <!-- No Client Selected -->
            <div class="glass-card p-12 text-center">
                <i class="fas fa-laptop text-6xl text-gray-600 mb-6"></i>
                <h2 class="text-2xl font-bold mb-4">No Client Selected</h2>
                <p class="text-gray-400 mb-8">Please select a client from the dropdown above to start managing files.</p>
            </div>
        <?php else: ?>
            <!-- Main File Manager Interface -->
            <div class="grid grid-cols-1 lg:grid-cols-4 gap-6">
                <!-- Sidebar -->
                <div class="lg:col-span-1">
                    <div class="glass-card p-6 mb-6">
                        <h3 class="font-bold text-lg mb-4 flex items-center gap-2">
                            <i class="fas fa-cogs"></i> Quick Actions
                        </h3>
                        <div class="space-y-2">
                            <button onclick="fileManager.createFolder()"
                                class="w-full px-4 py-3 bg-gray-800 hover:bg-gray-700 rounded-lg transition flex items-center gap-3">
                                <i class="fas fa-folder-plus text-blue-400"></i>
                                <span>New Folder</span>
                            </button>
                            <button onclick="fileManager.createFile()"
                                class="w-full px-4 py-3 bg-gray-800 hover:bg-gray-700 rounded-lg transition flex items-center gap-3">
                                <i class="fas fa-file-circle-plus text-green-400"></i>
                                <span>New File</span>
                            </button>
                            <button onclick="fileManager.uploadFile()"
                                class="w-full px-4 py-3 bg-gray-800 hover:bg-gray-700 rounded-lg transition flex items-center gap-3">
                                <i class="fas fa-upload text-yellow-400"></i>
                                <span>Upload Files</span>
                            </button>
                            <button onclick="fileManager.refresh()"
                                class="w-full px-4 py-3 bg-gray-800 hover:bg-gray-700 rounded-lg transition flex items-center gap-3">
                                <i class="fas fa-sync-alt text-purple-400"></i>
                                <span>Refresh</span>
                            </button>
                        </div>
                    </div>

                    <div class="glass-card p-6">
                        <h3 class="font-bold text-lg mb-4 flex items-center gap-2">
                            <i class="fas fa-search"></i> Search
                        </h3>
                        <div class="space-y-4">
                            <input type="text" id="search-input"
                                placeholder="Search files..."
                                class="w-full px-4 py-2 bg-gray-900 border border-gray-700 rounded-lg focus:outline-none focus:border-yellow-500">
                            <div class="flex gap-2">
                                <select id="search-type" class="flex-1 bg-gray-900 border border-gray-700 rounded-lg px-3 py-2 text-sm">
                                    <option value="both">Files & Folders</option>
                                    <option value="files">Files Only</option>
                                    <option value="folders">Folders Only</option>
                                </select>
                                <button onclick="fileManager.search()"
                                    class="px-4 py-2 bg-yellow-500/20 hover:bg-yellow-500/30 text-yellow-400 rounded-lg transition">
                                    <i class="fas fa-search"></i>
                                </button>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Main Content -->
                <div class="lg:col-span-3">
                    <!-- Breadcrumb & Controls -->
                    <div class="glass-card p-4 mb-6">
                        <div class="flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
                            <div class="flex items-center gap-2 flex-wrap">
                                <button onclick="fileManager.navigateTo('')"
                                    class="px-3 py-1 bg-gray-800 hover:bg-gray-700 rounded-lg transition">
                                    <i class="fas fa-home"></i>
                                </button>
                                <span id="breadcrumb" class="text-gray-400">C:\</span>
                            </div>
                            <div class="flex items-center gap-2">
                                <div class="flex items-center gap-2">
                                    <label class="text-sm text-gray-400">View:</label>
                                    <button id="view-grid" onclick="fileManager.setView('grid')"
                                        class="px-3 py-1 bg-yellow-500/20 text-yellow-400 rounded-lg">
                                        <i class="fas fa-th-large"></i>
                                    </button>
                                    <button id="view-list" onclick="fileManager.setView('list')"
                                        class="px-3 py-1 bg-gray-800 hover:bg-gray-700 rounded-lg">
                                        <i class="fas fa-list"></i>
                                    </button>
                                </div>
                                <select id="sort-by" onchange="fileManager.sortFiles()"
                                    class="bg-gray-900 border border-gray-700 rounded-lg px-3 py-1 text-sm">
                                    <option value="name">Name</option>
                                    <option value="size">Size</option>
                                    <option value="modified">Modified</option>
                                    <option value="type">Type</option>
                                </select>
                                <select id="sort-order" onchange="fileManager.sortFiles()"
                                    class="bg-gray-900 border border-gray-700 rounded-lg px-3 py-1 text-sm">
                                    <option value="asc">Asc</option>
                                    <option value="desc">Desc</option>
                                </select>
                            </div>
                        </div>
                    </div>

                    <!-- File List -->
                    <div id="file-list-container" class="glass-card p-6">
                        <div id="file-list" class="file-grid">
                            <!-- Files will be loaded here -->
                        </div>
                        <div id="empty-state" class="hidden text-center py-12">
                            <i class="fas fa-folder-open text-6xl text-gray-600 mb-4"></i>
                            <p class="text-gray-400">No files found</p>
                        </div>
                    </div>

                    <!-- Statistics -->
                    <div id="statistics" class="glass-card p-6 mt-6 hidden">
                        <div class="grid grid-cols-1 md:grid-cols-4 gap-4">
                            <div class="text-center p-4 bg-gray-800/50 rounded-lg">
                                <div class="text-2xl font-bold text-green-400" id="total-files">0</div>
                                <div class="text-sm text-gray-400">Files</div>
                            </div>
                            <div class="text-center p-4 bg-gray-800/50 rounded-lg">
                                <div class="text-2xl font-bold text-blue-400" id="total-folders">0</div>
                                <div class="text-sm text-gray-400">Folders</div>
                            </div>
                            <div class="text-center p-4 bg-gray-800/50 rounded-lg">
                                <div class="text-2xl font-bold text-yellow-400" id="total-size">0</div>
                                <div class="text-sm text-gray-400">Total Size</div>
                            </div>
                            <div class="text-center p-4 bg-gray-800/50 rounded-lg">
                                <div class="text-2xl font-bold text-purple-400" id="free-space">0</div>
                                <div class="text-sm text-gray-400">Free Space</div>
                            </div>
                        </div>
                    </div>

                    <!-- Upload Progress -->
                    <div id="upload-progress" class="glass-card p-4 mt-6 hidden">
                        <div class="flex justify-between items-center mb-2">
                            <div class="font-medium">Uploading...</div>
                            <div class="text-sm text-gray-400" id="upload-progress-text">0%</div>
                        </div>
                        <div class="progress-bar">
                            <div id="upload-progress-bar" class="progress-bar-fill" style="width: 0%"></div>
                        </div>
                    </div>
                </div>
            </div>
        <?php endif; ?>
    </div>

    <!-- Modals -->
    <div id="modals-container">
        <!-- Properties Modal -->
        <div id="properties-modal" class="fixed inset-0 bg-black/80 hidden items-center justify-center z-50 p-4">
            <div class="bg-gray-900 border border-gray-700 rounded-xl w-full max-w-2xl">
                <div class="border-b border-gray-700 p-6">
                    <div class="flex justify-between items-center">
                        <h3 class="text-xl font-bold">Properties</h3>
                        <button onclick="closeModal('properties-modal')"
                            class="text-gray-400 hover:text-white text-2xl">&times;</button>
                    </div>
                </div>
                <div class="p-6">
                    <div id="properties-content"></div>
                </div>
            </div>
        </div>

        <!-- Rename Modal -->
        <div id="rename-modal" class="fixed inset-0 bg-black/80 hidden items-center justify-center z-50 p-4">
            <div class="bg-gray-900 border border-gray-700 rounded-xl w-full max-w-md">
                <div class="border-b border-gray-700 p-6">
                    <h3 class="text-xl font-bold">Rename</h3>
                </div>
                <div class="p-6">
                    <input type="text" id="rename-input"
                        class="w-full px-4 py-3 bg-gray-800 border border-gray-700 rounded-lg mb-4 focus:outline-none focus:border-yellow-500">
                    <div class="flex justify-end gap-3">
                        <button onclick="closeModal('rename-modal')"
                            class="px-4 py-2 bg-gray-800 hover:bg-gray-700 rounded-lg transition">Cancel</button>
                        <button onclick="fileManager.confirmRename()"
                            class="px-4 py-2 bg-yellow-500 hover:bg-yellow-600 rounded-lg transition">Rename</button>
                    </div>
                </div>
            </div>
        </div>

        <!-- New Folder Modal -->
        <div id="new-folder-modal" class="fixed inset-0 bg-black/80 hidden items-center justify-center z-50 p-4">
            <div class="bg-gray-900 border border-gray-700 rounded-xl w-full max-w-md">
                <div class="border-b border-gray-700 p-6">
                    <h3 class="text-xl font-bold">New Folder</h3>
                </div>
                <div class="p-6">
                    <input type="text" id="folder-name-input" placeholder="Folder Name"
                        class="w-full px-4 py-3 bg-gray-800 border border-gray-700 rounded-lg mb-4 focus:outline-none focus:border-yellow-500">
                    <div class="flex justify-end gap-3">
                        <button onclick="closeModal('new-folder-modal')"
                            class="px-4 py-2 bg-gray-800 hover:bg-gray-700 rounded-lg transition">Cancel</button>
                        <button onclick="fileManager.confirmCreateFolder()"
                            class="px-4 py-2 bg-blue-500 hover:bg-blue-600 rounded-lg transition">Create</button>
                    </div>
                </div>
            </div>
        </div>

        <!-- Upload Modal -->
        <div id="upload-modal" class="fixed inset-0 bg-black/80 hidden items-center justify-center z-50 p-4">
            <div class="bg-gray-900 border border-gray-700 rounded-xl w-full max-w-md">
                <div class="border-b border-gray-700 p-6">
                    <h3 class="text-xl font-bold">Upload Files</h3>
                </div>
                <div class="p-6">
                    <div class="border-2 border-dashed border-gray-700 rounded-lg p-8 text-center mb-4">
                        <i class="fas fa-cloud-upload-alt text-4xl text-gray-600 mb-4"></i>
                        <p class="mb-2">Drag & drop files here or click to browse</p>
                        <input type="file" id="file-upload-input" multiple
                            class="hidden">
                        <button onclick="document.getElementById('file-upload-input').click()"
                            class="px-4 py-2 bg-gray-800 hover:bg-gray-700 rounded-lg transition mt-2">
                            Browse Files
                        </button>
                    </div>
                    <div id="upload-queue" class="space-y-2 max-h-60 overflow-y-auto"></div>
                    <div class="flex justify-end gap-3 mt-6">
                        <button onclick="closeModal('upload-modal')"
                            class="px-4 py-2 bg-gray-800 hover:bg-gray-700 rounded-lg transition">Cancel</button>
                        <button onclick="fileManager.startUpload()"
                            class="px-4 py-2 bg-yellow-500 hover:bg-yellow-600 rounded-lg transition">Upload</button>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        // Pass PHP variables to JavaScript
        const SELECTED_CLIENT = '<?= $selectedClient ?>';
    </script>
    <script src="assets/js/file-manager.js"></script>
</body>

</html>