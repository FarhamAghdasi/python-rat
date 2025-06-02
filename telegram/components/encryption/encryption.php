<?php

class LoggerBot
{

    private function encrypt($data)
    {
        $iv = openssl_random_pseudo_bytes(16);
        $ciphertext = openssl_encrypt(
            $data,
            'aes-256-cbc',
            base64_decode(Config::$ENCRYPTION_KEY),
            0,
            $iv
        );
        if ($ciphertext === false) {
            $this->logError("Encryption failed for data: " . substr($data, 0, 50) . "...");
            return '';
        }
        return $ciphertext . '::' . base64_encode($iv);
    }

    private function decrypt($encryptedData)
    {
        try {
            if (!$encryptedData || !is_string($encryptedData)) {
                $this->logError("Invalid encrypted data: Not a string or empty: " . json_encode($encryptedData));
                return '';
            }

            if (!str_contains($encryptedData, '::')) {
                $this->logError("Invalid encrypted data format: Missing '::' separator: " . substr($encryptedData, 0, 50) . "...");
                return '';
            }

            list($ciphertext, $iv) = explode('::', $encryptedData, 2);
            if (empty($ciphertext) || empty($iv)) {
                $this->logError("Invalid encrypted data: Empty ciphertext or IV: " . substr($encryptedData, 0, 50) . "...");
                return '';
            }

            $ivDecoded = base64_decode($iv, true);
            if ($ivDecoded === false || strlen($ivDecoded) !== 16) {
                $this->logError("Invalid IV: Failed to decode or incorrect length: $iv");
                return '';
            }

            $key = base64_decode(Config::$ENCRYPTION_KEY);
            if (!$key) {
                $this->logError("Invalid encryption key: Failed to decode Config::$ENCRYPTION_KEY");
                return '';
            }

            $decrypted = openssl_decrypt(
                $ciphertext,
                'aes-256-cbc',
                $key,
                0,
                $ivDecoded
            );

            if ($decrypted === false) {
                $this->logError("Decryption failed for data: " . substr($encryptedData, 0, 50) . "...");
                return '';
            }

            $this->logWebhook("Successfully decrypted data: " . substr($decrypted, 0, 50) . "...");
            return $decrypted;
        } catch (Exception $e) {
            $this->logError("Decryption error: " . $e->getMessage() . ", data: " . substr($encryptedData, 0, 50) . "...");
            return '';
        }
    }
}
