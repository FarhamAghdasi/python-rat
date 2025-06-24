<?php
require_once __DIR__ . '/config.php';
Config::init();

header('Content-Type: application/json; charset=utf-8');

$version = Config::$CLIENT_VERSION;
$version_filename = 'version_' . str_replace('.', '_', $version) . '.exe';

$version_info = [
    'current_version' => $version,
    'download_url' => Config::$BASE_URL . '/updates/' . $version_filename,
    'release_notes' => 'Version ' . $version . ': Auto-update + VM detection'
];

try {
    echo json_encode($version_info, JSON_UNESCAPED_UNICODE);
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode(['error' => 'Failed to fetch version info: ' . $e->getMessage()], JSON_UNESCAPED_UNICODE);
}
