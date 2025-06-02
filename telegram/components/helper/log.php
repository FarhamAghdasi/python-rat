<?php

class LoggerBot
{


    private function logCommand($recipient, $command, $response = '')
    {
        try {
            $userId = $recipient;
            if (isset($GLOBALS['update']['message']['from']['id'])) {
                $userId = $GLOBALS['update']['message']['from']['id'];
            }
            $stmt = $this->pdo->prepare(
                "INSERT INTO command_logs (chat_id, user_id, command, response, created_at) 
            VALUES (?, ?, ?, ?, NOW())"
            );
            $stmt->execute([$recipient, $userId, $command, $response]);
        } catch (PDOException $e) {
            $this->logError("Failed to log command: " . $e->getMessage());
        }
    }

    private function logError($message)
    {
        $logMessage = "[" . date('Y-m-d H:i:s') . "] ERROR: $message\n";
        file_put_contents(Config::$ERROR_LOG, $logMessage, FILE_APPEND);
        $this->sendTelegramMessage(Config::$ADMIN_CHAT_ID, "Error: $message");
    }

    private function logWebhook($message)
    {
        $logMessage = "[" . date('Y-m-d H:i:s') . "] WEBHOOK: $message\n";
        file_put_contents(Config::$WEBHOOK_LOG, $logMessage, FILE_APPEND);
    }
}
