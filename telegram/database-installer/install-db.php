<?php
require_once __DIR__ . '/config.php';

try {
    $dsn = "mysql:host=" . Config::$DB_HOST . ";charset=utf8mb4";
    $pdo = new PDO($dsn, Config::$DB_USER, Config::$DB_PASS);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    $sql = file_get_contents(__DIR__ . '/schema.sql');
    $pdo->exec($sql);
    echo "Database schema installed successfully.\n";

    $pdo->exec("USE " . Config::$DB_NAME);
    $stmt = $pdo->prepare("INSERT IGNORE INTO users (user_id, is_active, created_at) VALUES (?, 1, NOW())");
    $stmt->execute([Config::$ADMIN_CHAT_ID]);
    echo "Admin user initialized.\n";

} catch (PDOException $e) {
    echo "Database installation failed: " . $e->getMessage() . "\n";
    file_put_contents(Config::$ERROR_LOG, "[" . date('Y-m-d H:i:s') . "] DB INSTALL ERROR: " . $e->getMessage() . "\n", FILE_APPEND);
}
?>