<?php
require_once __DIR__ . '/Config.php';

$webhookUrl = Config::$SERVER_URL;
$secretToken = Config::$WEBHOOK_SECRET;

$url = "https://api.telegram.org/bot" . Config::$BOT_TOKEN . "/setWebhook";
$data = [
    'url' => $webhookUrl,
    'secret_token' => $secretToken,
    'allowed_updates' => json_encode(['message'])
];

$ch = curl_init($url);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($data));

$response = curl_exec($ch);
if (curl_errno($ch)) {
    $error = "Webhook setup failed: " . curl_error($ch);
    file_put_contents(Config::$ERROR_LOG, "[" . date('Y-m-d H:i:s') . "] WEBHOOK SETUP ERROR: $error\n", FILE_APPEND);
    echo $error . "\n";
} else {
    $result = json_decode($response, true);
    if ($result['ok']) {
        echo "Webhook set successfully: " . $webhookUrl . "\n";
    } else {
        $error = "Webhook setup failed: " . $result['description'];
        file_put_contents(Config::$ERROR_LOG, "[" . date('Y-m-d H:i:s') . "] WEBHOOK SETUP ERROR: $error\n", FILE_APPEND);
        echo $error . "\n";
    }
}
curl_close($ch);
?>