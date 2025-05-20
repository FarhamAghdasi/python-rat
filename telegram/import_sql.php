<?php
// import_sql.php

require_once 'config.php';

try {
    $pdo = new PDO(
        "mysql:host=" . Config::$DB_HOST . ";dbname=" . Config::$DB_NAME . ";charset=utf8mb4",
        Config::$DB_USER,
        Config::$DB_PASS,
        [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        ]
    );

    $sqlFile = __DIR__ . '/database.sql';

    if (!file_exists($sqlFile)) {
        throw new Exception("فایل database.sql پیدا نشد.");
    }

    $sqlContent = file_get_contents($sqlFile);

    $pdo->exec($sqlContent);

    echo "✅ وارد کردن فایل SQL با موفقیت انجام شد.";
} catch (PDOException $e) {
    echo "❌ خطای پایگاه داده: " . $e->getMessage();
} catch (Exception $e) {
    echo "❌ خطا: " . $e->getMessage();
}
