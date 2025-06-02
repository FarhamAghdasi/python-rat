<?php
class LoggerBot
{


    private function addAdmin($recipient, $newAdminId, $isClient = false)
    {
        try {
            $stmt = $this->pdo->prepare(
                "INSERT INTO users (user_id, is_active, is_admin, created_at) 
            VALUES (?, 1, 1, NOW()) 
            ON DUPLICATE KEY UPDATE is_admin = 1, is_active = 1"
            );
            $stmt->execute([$newAdminId]);
            $message = "Admin $newAdminId added successfully.";
        } catch (PDOException $e) {
            $message = "Failed to add admin: " . $e->getMessage();
            $this->logError("Add admin failed: " . $e->getMessage());
        }

        if ($isClient) {
            return $message;
        }
        $this->sendTelegramMessage($recipient, $message);
        return $message;
    }

    private function listUsers($recipient, $isClient = false)
    {
        try {
            $stmt = $this->pdo->prepare("SELECT user_id, is_admin FROM users WHERE is_active = 1");
            $stmt->execute();
            $users = $stmt->fetchAll();

            $message = "Active users:\n";
            foreach ($users as $user) {
                $role = $user['is_admin'] ? '(Admin)' : '(User)';
                $message .= "- {$user['user_id']} $role\n";
            }
            $message = $message ?: "No active users.";
        } catch (PDOException $e) {
            $message = "Failed to list users: " . $e->getMessage();
            $this->logError("List users failed: " . $e->getMessage());
        }

        if ($isClient) {
            return $message;
        }
        $this->sendTelegramMessage($recipient, $message);
        return "Users listed";
    }

    private function isUserAuthorized($userId)
    {
        try {
            $stmt = $this->pdo->prepare("SELECT is_admin FROM users WHERE user_id = ? AND is_active = 1");
            $stmt->execute([$userId]);
            $user = $stmt->fetch();
            $isAuthorized = $user && $user['is_admin'] == 1;
            $this->logWebhook("Authorization check for user_id: $userId, authorized: " . ($isAuthorized ? 'yes' : 'no'));
            return $isAuthorized;
        } catch (PDOException $e) {
            $this->logError("Authorization check failed: " . $e->getMessage());
            return false;
        }
    }

    private function clientExists($clientId)
    {
        try {
            $stmt = $this->pdo->prepare("SELECT 1 FROM clients WHERE client_id = ?");
            $stmt->execute([$clientId]);
            return $stmt->fetch() !== false;
        } catch (PDOException $e) {
            $this->logError("Client existence check failed for client_id: $clientId, error: " . $e->getMessage());
            return false;
        }
    }
}
