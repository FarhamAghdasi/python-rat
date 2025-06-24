<?php
namespace Services;

require_once __DIR__ . '/../../config.php';
use \Config;

class LoggerService
{
    private string $logFile;

    public function __construct()
    {
        $this->logFile = Config::$ERROR_LOG;
        $this->ensureLogDirectoryExists();
    }

    public function logWebhook(string $message): void
    {
        $this->writeLog("WEBHOOK", $message);
    }

    public function logError(string $message): void
    {
        $this->writeLog("ERROR", $message);
    }

    public function logCommand(string $clientId, string $command, string $details): void
    {
        $log = "client_id=$clientId, command=$command, details=$details";
        $this->writeLog("COMMAND", $log);
    }

    private function writeLog(string $type, string $message): void
    {
        $logEntry = "[" . date('Y-m-d H:i:s') . "] $type: $message\n";
        error_log($logEntry, 3, $this->logFile);
    }

    private function ensureLogDirectoryExists(): void
    {
        $logDir = dirname($this->logFile);
        if (!is_dir($logDir)) {
            mkdir($logDir, 0755, true);
        }
    }
}
