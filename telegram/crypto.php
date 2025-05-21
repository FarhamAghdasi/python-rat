<?php
require_once 'config.php';

class Crypto {
    private $key;

    public function __construct() {
        $this->key = base64_decode(Config::$ENCRYPTION_KEY);
        $this->validate_key();
    }

    private function validate_key() {
        if (strlen($this->key) !== 32) {
            throw new Exception("Invalid encryption key length");
        }
    }

    public function encrypt($data) {
        $iv = openssl_random_pseudo_bytes(16);
        $ciphertext = openssl_encrypt(
            is_array($data) ? json_encode($data) : $data,
            'AES-256-CBC',
            $this->key,
            OPENSSL_RAW_DATA,
            $iv
        );
        return base64_encode($ciphertext) . '::' . base64_encode($iv);
    }

    public function decrypt($data) {
        if (empty($data) || !is_string($data) || !strpos($data, '::')) {
            throw new Exception("Invalid encrypted data format: Data must contain '::' separator");
        }
        list($ciphertext_b64, $iv_b64) = explode('::', $data);
        $ciphertext = base64_decode($ciphertext_b64);
        $iv = base64_decode($iv_b64);
        if ($ciphertext === false || $iv === false) {
            throw new Exception("Base64 decoding failed for ciphertext or IV");
        }
        $plaintext = openssl_decrypt(
            $ciphertext,
            'AES-256-CBC',
            $this->key,
            OPENSSL_RAW_DATA,
            $iv
        );
        if ($plaintext === false) {
            throw new Exception("Decryption failed: Invalid key or corrupted data");
        }
        return $plaintext;
    }
}
?>