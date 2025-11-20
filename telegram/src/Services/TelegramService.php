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

    /**
     * ارسال پیام با escape کردن خودکار کاراکترهای خاص Markdown
     */
    public function sendMessage(string $chatId, string $message, array $options = [])
    {
        // اگر parse_mode تنظیم نشده، از HTML استفاده کن (امن‌تر از Markdown)
        $parseMode = $options['parse_mode'] ?? 'HTML';
        
        // اگر Markdown است، کاراکترهای خاص را escape کن
        if ($parseMode === 'Markdown' || $parseMode === 'MarkdownV2') {
            $message = $this->escapeMarkdown($message);
        }
        
        // اگر HTML است، کاراکترهای خاص HTML را escape کن
        if ($parseMode === 'HTML') {
            $message = $this->escapeHtml($message);
        }

        $data = array_merge([
            'chat_id' => $chatId,
            'text' => $message,
            'parse_mode' => $parseMode
        ], $options);

        return $this->makeCurlRequest(
            "https://api.telegram.org/bot" . Config::$BOT_TOKEN . "/sendMessage",
            $data
        );
    }

    /**
     * ارسال پیام بدون فرمت (متن ساده)
     */
    public function sendPlainMessage(string $chatId, string $message, array $options = [])
    {
        $data = array_merge([
            'chat_id' => $chatId,
            'text' => $message
            // بدون parse_mode - متن ساده
        ], $options);

        // حذف parse_mode اگر وجود داشته باشد
        unset($data['parse_mode']);

        return $this->makeCurlRequest(
            "https://api.telegram.org/bot" . Config::$BOT_TOKEN . "/sendMessage",
            $data
        );
    }

    public function sendFile(string $chatId, string $filePath, string $caption = '')
    {
        if (!file_exists($filePath)) {
            $this->logger->logError("File not found: $filePath");
            return false;
        }

        $data = [
            'chat_id' => $chatId,
            'document' => new \CURLFile($filePath),
            'caption' => $this->escapeHtml($caption),
            'parse_mode' => 'HTML'
        ];

        return $this->makeCurlRequest(
            "https://api.telegram.org/bot" . Config::$BOT_TOKEN . "/sendDocument",
            $data,
            true
        );
    }

    public function answerCallbackQuery(string $callbackQueryId, string $text = '', bool $showAlert = false)
    {
        return $this->makeCurlRequest(
            "https://api.telegram.org/bot" . Config::$BOT_TOKEN . "/answerCallbackQuery",
            [
                'callback_query_id' => $callbackQueryId,
                'text' => $text,
                'show_alert' => $showAlert
            ],
            false
        );
    }

    /**
     * Escape کردن کاراکترهای خاص Markdown
     */
    private function escapeMarkdown(string $text): string
    {
        $specialChars = ['_', '*', '[', ']', '(', ')', '~', '`', '>', '#', '+', '-', '=', '|', '{', '}', '.', '!'];
        foreach ($specialChars as $char) {
            $text = str_replace($char, '\\' . $char, $text);
        }
        return $text;
    }

    /**
     * Escape کردن کاراکترهای خاص HTML
     */
    private function escapeHtml(string $text): string
    {
        // فقط کاراکترهای خطرناک را escape کن
        $text = str_replace('&', '&amp;', $text);
        $text = str_replace('<', '&lt;', $text);
        $text = str_replace('>', '&gt;', $text);
        return $text;
    }

    /**
     * درخواست cURL با مدیریت خطای بهتر
     */
    private function makeCurlRequest(string $url, array $data, bool $isFile = false)
    {
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 10);
        curl_setopt($ch, CURLOPT_TIMEOUT, 30);

        if ($isFile) {
            curl_setopt($ch, CURLOPT_POSTFIELDS, $data);
        } else {
            curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
            curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
        }

        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        
        if (curl_errno($ch)) {
            $error = curl_error($ch);
            $this->logger->logError("cURL error: $error");
            curl_close($ch);
            return false;
        }
        
        curl_close($ch);

        // لاگ پاسخ
        $this->logger->logWebhook("Telegram API response: $response");

        $result = json_decode($response, true);
        
        // بررسی خطا
        if (isset($result['ok']) && !$result['ok']) {
            $errorMsg = $result['description'] ?? 'Unknown error';
            $this->logger->logError("Telegram API error: $errorMsg");
            
            // اگر خطای parse entities بود، سعی کن بدون فرمت بفرست
            if (strpos($errorMsg, "can't parse entities") !== false) {
                $this->logger->logError("Retrying without parse_mode...");
                unset($data['parse_mode']);
                return $this->makeCurlRequest($url, $data, $isFile);
            }
        }

        return $response;
    }
}