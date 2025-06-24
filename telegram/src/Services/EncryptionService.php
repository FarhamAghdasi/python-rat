<?php
namespace Services;

require_once __DIR__ . '/../../config.php';
use \Config;

class EncryptionService
{
    private $logger;

    public function __construct(LoggerService $logger)
    {
        $this->logger = $logger;
    }

    public function decrypt(string $encryptedData): string
    {
        try {
            if (str_contains($encryptedData, '::')) {
                list($ciphertext, $iv) = explode('::', $encryptedData, 2);
                $ivDecoded = base64_decode($iv);
                $keyDecoded = base64_decode(Config::$ENCRYPTION_KEY);
                if (strlen($keyDecoded) !== 32) {
                    $this->logger->logError("Encryption key is invalid length: " . strlen($keyDecoded));
                    return '';
                }                
                $decrypted = openssl_decrypt($ciphertext, 'aes-256-cbc', $keyDecoded, 0, $ivDecoded);
                return $decrypted !== false ? $decrypted : '';
            }
            return '';
        } catch (\Exception $e) {
            $this->logger->logError("Decryption failed: " . $e->getMessage());
            return '';
        }
    }

    public function encrypt(string $data): string
    {
        try {
            $iv = openssl_random_pseudo_bytes(16);
            $keyDecoded = base64_decode(Config::$ENCRYPTION_KEY);
            if (strlen($keyDecoded) !== 32) {
                $this->logger->logError("Encryption key is invalid length: " . strlen($keyDecoded));
                return '';
            }            
            $ciphertext = openssl_encrypt($data, 'aes-256-cbc', $keyDecoded, 0, $iv);
            return $ciphertext . '::' . base64_encode($iv);
        } catch (\Exception $e) {
            $this->logger->logError("Encryption failed: " . $e->getMessage());
            return '';
        }
    }
}