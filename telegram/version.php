<?php
require_once __DIR__ . '/config.php';
Config::init();

header('Content-Type: application/json; charset=utf-8');

$version_info = [
    'current_version' => '1.1',
    'download_url' => Config::$BASE_URL . '/updates/version_1.1.exe',
    'release_notes' => 'Version 1.1: Added auto-update feature and VM detection.'
];

try {
    echo json_encode($version_info, JSON_UNESCAPED_UNICODE);
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode(['error' => 'Failed to fetch version info: ' . $e->getMessage()], JSON_UNESCAPED_UNICODE);
}
