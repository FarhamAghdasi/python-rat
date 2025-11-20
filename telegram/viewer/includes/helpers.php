<?php

function decrypt($encryptedData, $key) {
    try {
        if (!$encryptedData || !is_string($encryptedData)) {
            error_log("Decrypt: No data or invalid type");
            return '[No data]';
        }

        // اگر داده از قبل decrypt شده باشد، برگردان
        if (strpos($encryptedData, '{"type":') === 0 || strpos($encryptedData, '{"status":') === 0) {
            return $encryptedData;
        }

        if (str_contains($encryptedData, '::')) {
            list($ciphertext, $iv) = explode('::', $encryptedData, 2);

            if (empty($ciphertext) || empty($iv)) {
                error_log("Decrypt: Empty ciphertext or IV");
                return '[Decryption failed: Invalid format]';
            }

            $ivDecoded = base64_decode($iv, true);
            $keyDecoded = base64_decode($key);

            if ($ivDecoded === false || $keyDecoded === false) {
                error_log("Decrypt: Invalid base64 encoding");
                return '[Decryption failed: Invalid key or IV]';
            }

            $decrypted = openssl_decrypt(
                $ciphertext,
                'aes-256-cbc',
                $keyDecoded,
                0,
                $ivDecoded
            );

            if ($decrypted === false) {
                $error = openssl_error_string();
                error_log("Decrypt AES error: " . $error);
                return '[Decryption failed: AES error - ' . $error . ']';
            }

            error_log("Decrypt successful: " . substr($decrypted, 0, 100));
            return $decrypted;
        }

        // اگر فرمت encrypt نبود، داده اصلی را برگردان
        error_log("Decrypt: Not encrypted format, returning original");
        return $encryptedData;

    } catch (Exception $e) {
        error_log("Decrypt error: " . $e->getMessage());
        return '[Decryption error: ' . $e->getMessage() . ']';
    }
}

function formatJsonForDownload($jsonString) {
    // اگر داده decrypt شده JSON است، آن را format کن
    if (strpos($jsonString, '{') === 0 || strpos($jsonString, '[') === 0) {
        $jsonDecoded = json_decode($jsonString, true);
        if ($jsonDecoded === null) {
            return $jsonString;
        }

        $output = [];
        foreach ($jsonDecoded as $key => $value) {
            if (is_array($value)) {
                $value = json_encode($value, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
            }
            $output[] = "$key: $value";
        }
        return implode("\n", $output);
    }
    
    return $jsonString;
}

function validateSession() {
    // Check if session is still valid (optional: add timeout check)
    if (isset($_SESSION['login_time'])) {
        $session_duration = 8 * 60 * 60; // 8 hours
        if (time() - $_SESSION['login_time'] > $session_duration) {
            session_destroy();
            return false;
        }
    }
    return isset($_SESSION['logged_in']) && $_SESSION['logged_in'] === true;
}