<?php
namespace Services;

require_once __DIR__ . '/../../config.php';
use \Config;

class TelegramService
{
    private $logger;

    public function __construct(LoggerService $logger)
    {
        $this->logger = $logger;
    }

    public function sendMessage(string $chatId, string $message, array $options = [])
    {
        $data = array_merge([
            'chat_id' => $chatId,
            'text' => $message,
            'parse_mode' => 'Markdown'
        ], $options);

        $this->makeCurlRequest(
            "https://api.telegram.org/bot" . Config::$BOT_TOKEN . "/sendMessage",
            $data
        );
    }

    public function sendFile(string $chatId, string $filePath, string $caption = '')
    {
        $data = [
            'chat_id' => $chatId,
            'document' => new \CURLFile($filePath),
            'caption' => $caption
        ];

        $this->makeCurlRequest(
            "https://api.telegram.org/bot" . Config::$BOT_TOKEN . "/sendDocument",
            $data,
            true
        );
    }

    public function answerCallbackQuery(string $callbackQueryId, string $text = '', bool $showAlert = false)
    {
        $this->makeCurlRequest(
            "https://api.telegram.org/bot" . Config::$BOT_TOKEN . "/answerCallbackQuery",
            [
                'callback_query_id' => $callbackQueryId,
                'text' => $text,
                'show_alert' => $showAlert
            ],
            false
        );
    }

    private function makeCurlRequest(string $url, array $data, bool $isFile = false)
    {
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_POST, true);

        if ($isFile) {
            curl_setopt($ch, CURLOPT_POSTFIELDS, $data);
        } else {
            curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
            curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
        }

        $response = curl_exec($ch);
        if (curl_errno($ch)) {
            $this->logger->logError("cURL error: " . curl_error($ch));
        } else {
            $this->logger->logWebhook("Telegram API response: $response");
        }
        curl_close($ch);

        return $response;
    }
}