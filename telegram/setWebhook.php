<?php
$token  = 'YOUR_NEW_TOKEN';
$webhookUrl    = 'https://your.domain.com/api.php';
$secretToken  = 'YOUR_SECRET_TOKEN';

$params = [
    'url'                   => $webhookUrl,
    'secret_token'          => $secretToken,
    'drop_pending_updates'  => true,
    // 'certificate'        => new CURLFile('/path/to/your/public.pem'), // اگر گواهی سفارشی دارین
];

$ch = curl_init("https://api.telegram.org/bot{$token}/setWebhook");
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_POSTFIELDS, $params);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
$response = curl_exec($ch);
curl_close($ch);

echo $response;  // JSON با نتیجه‌ی عملیات
