<?php
namespace Services;

use PDO;

require_once __DIR__ . '/../../config.php';

class ClientService
{
    private $pdo;
    private $logger;

    public function __construct(PDO $pdo, LoggerService $logger)
    {
        $this->pdo = $pdo;
        $this->logger = $logger;
    }

    public function updateClientStatus(string $clientId, string $ipAddress): void
    {
        try {
            $stmt = $this->pdo->prepare(
                "INSERT INTO clients (client_id, ip_address, is_online, last_seen, created_at) 
                VALUES (?, ?, 1, NOW(), NOW()) 
                ON DUPLICATE KEY UPDATE is_online = 1, last_seen = NOW(), ip_address = ?"
            );
            $stmt->execute([$clientId, $ipAddress, $ipAddress]);
            $this->logger->logWebhook("Updated client status for client_id: $clientId, ip: $ipAddress");
        } catch (\PDOException $e) {
            $this->logger->logError("Failed to update client status: " . $e->getMessage());
        }
    }

    public function getClientCommands(string $clientId): array
    {
        try {
            $stmt = $this->pdo->prepare(
                "SELECT id, command FROM client_commands 
                WHERE client_id = ? AND status = 'pending' 
                LIMIT 10"
            );
            $stmt->execute([$clientId]);
            $commands = $stmt->fetchAll();
            $this->logger->logWebhook("Fetched commands for client_id: $clientId, count: " . count($commands));
            return ['commands' => $commands];
        } catch (\PDOException $e) {
            $this->logger->logError("Failed to fetch client commands for client_id: $clientId, error: " . $e->getMessage());
            return ['error' => 'Failed to fetch commands'];
        }
    }

    public function clientExists(string $clientId): bool
    {
        try {
            $stmt = $this->pdo->prepare("SELECT 1 FROM clients WHERE client_id = ?");
            $stmt->execute([$clientId]);
            return $stmt->fetch() !== false;
        } catch (\PDOException $e) {
            $this->logger->logError("Client existence check failed for client_id: $clientId, error: " . $e->getMessage());
            return false;
        }
    }

    public function isUserAuthorized(string $userId): bool
    {
        try {
            $stmt = $this->pdo->prepare("SELECT is_admin FROM users WHERE user_id = ? AND is_active = 1");
            $stmt->execute([$userId]);
            $user = $stmt->fetch();
            $isAuthorized = $user && $user['is_admin'] == 1;
            $this->logger->logWebhook("Authorization check for user_id: $userId, authorized: " . ($isAuthorized ? 'yes' : 'no'));
            return $isAuthorized;
        } catch (\PDOException $e) {
            $this->logger->logError("Authorization check failed: " . $e->getMessage());
            return false;
        }
    }

    public function setSelectedClient(string $userId, string $clientId): void
    {
        try {
            $stmt = $this->pdo->prepare(
                "INSERT INTO user_selections (user_id, selected_client, updated_at) 
                VALUES (?, ?, NOW()) 
                ON DUPLICATE KEY UPDATE selected_client = ?, updated_at = NOW()"
            );
            $stmt->execute([$userId, $clientId, $clientId]);
            $this->logger->logWebhook("Set selected client: $clientId for user_id: $userId");
        } catch (\PDOException $e) {
            $this->logger->logError("Failed to set selected client for user_id: $userId, error: " . $e->getMessage());
        }
    }

    public function getSelectedClient(string $userId): ?string
    {
        try {
            $stmt = $this->pdo->prepare("SELECT selected_client FROM user_selections WHERE user_id = ?");
            $stmt->execute([$userId]);
            $result = $stmt->fetch();
            $clientId = $result ? $result['selected_client'] : null;
            $this->logger->logWebhook("Retrieved selected client: " . ($clientId ?: 'none') . " for user_id: $userId");
            return $clientId;
        } catch (\PDOException $e) {
            $this->logger->logError("Failed to get selected client for user_id: $userId, error: " . $e->getMessage());
            return null;
        }
    }
}