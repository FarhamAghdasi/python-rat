<?php
namespace Services;

require_once __DIR__ . '/../../config.php';
use \Config;

class LoggerService
{
    private string $errorLog;
    private string $webhookLog;
    private string $telegramLog;

    public function __construct()
    {
        // Ensure log directory exists
        $logDir = dirname(Config::$ERROR_LOG);
        if (!is_dir($logDir)) {
            mkdir($logDir, 0755, true);
        }

        $this->errorLog = Config::$ERROR_LOG;
        $this->webhookLog = Config::$WEBHOOK_LOG;
        $this->telegramLog = Config::$TELEGRAM_LOG;
        
        // Ensure all log files exist
        $this->ensureLogFileExists($this->errorLog);
        $this->ensureLogFileExists($this->webhookLog);
        $this->ensureLogFileExists($this->telegramLog);
    }

    private function ensureLogFileExists(string $logFile): void
    {
        if (!file_exists($logFile)) {
            $dir = dirname($logFile);
            if (!is_dir($dir)) {
                mkdir($dir, 0755, true);
            }
            touch($logFile);
            chmod($logFile, 0644);
        }
    }

    public function logWebhook(string $message): void
    {
        $this->writeLog($this->webhookLog, "WEBHOOK", $message);
    }

    public function logError(string $message): void
    {
        $this->writeLog($this->errorLog, "ERROR", $message);
    }

    public function logTelegram(string $message): void
    {
        $this->writeLog($this->telegramLog, "TELEGRAM", $message);
    }

    public function logCommand(string $clientId, string $command, string $details): void
    {
        $log = "client_id=$clientId, command=$command, details=$details";
        $this->writeLog($this->errorLog, "COMMAND", $log);
    }

    private function writeLog(string $logFile, string $type, string $message): void
    {
        try {
            $logEntry = "[" . date('Y-m-d H:i:s') . "] $type: $message\n";
            
            // Check file size and rotate if needed
            if (file_exists($logFile) && filesize($logFile) > Config::$MAX_LOG_SIZE) {
                $this->rotateLog($logFile);
            }
            
            // Write to log file
            $result = file_put_contents($logFile, $logEntry, FILE_APPEND | LOCK_EX);
            
            if ($result === false) {
                error_log("Failed to write to log file: $logFile");
            }
        } catch (\Exception $e) {
            error_log("Logging error: " . $e->getMessage());
        }
    }

    private function rotateLog(string $logFile): void
    {
        try {
            $timestamp = date('Y-m-d_H-i-s');
            $rotatedFile = $logFile . '.' . $timestamp;
            
            // Rename current log file
            if (file_exists($logFile)) {
                rename($logFile, $rotatedFile);
                
                // Create new empty log file
                touch($logFile);
                chmod($logFile, 0644);
                
                // Keep only last 5 rotated logs
                $this->cleanOldLogs(dirname($logFile), basename($logFile));
            }
        } catch (\Exception $e) {
            error_log("Log rotation error: " . $e->getMessage());
        }
    }

    private function cleanOldLogs(string $dir, string $baseName): void
    {
        try {
            $pattern = $dir . '/' . $baseName . '.*';
            $files = glob($pattern);
            
            if ($files && count($files) > 5) {
                // Sort by modification time (oldest first)
                usort($files, function($a, $b) {
                    return filemtime($a) - filemtime($b);
                });
                
                // Delete oldest files, keep only 5 most recent
                $filesToDelete = array_slice($files, 0, count($files) - 5);
                foreach ($filesToDelete as $file) {
                    unlink($file);
                }
            }
        } catch (\Exception $e) {
            error_log("Clean old logs error: " . $e->getMessage());
        }
    }

    public function getRecentLogs(string $logType = 'error', int $lines = 100): array
    {
        try {
            $logFile = $this->errorLog;
            if ($logType === 'webhook') {
                $logFile = $this->webhookLog;
            } elseif ($logType === 'telegram') {
                $logFile = $this->telegramLog;
            }

            if (!file_exists($logFile)) {
                return [];
            }

            // Read last N lines
            $file = new \SplFileObject($logFile, 'r');
            $file->seek(PHP_INT_MAX);
            $lastLine = $file->key();
            $startLine = max(0, $lastLine - $lines);
            
            $logs = [];
            $file->seek($startLine);
            while (!$file->eof()) {
                $line = $file->current();
                if (!empty(trim($line))) {
                    $logs[] = $line;
                }
                $file->next();
            }

            return $logs;
        } catch (\Exception $e) {
            error_log("Get recent logs error: " . $e->getMessage());
            return [];
        }
    }
}