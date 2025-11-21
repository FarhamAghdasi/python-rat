<?php

// ===== LOGGING SYSTEM =====
define('LOG_FILE', __DIR__ . '/../output/log.txt');
define('LOG_ENABLED', true);
define('LOG_LEVEL', 'DEBUG'); // DEBUG, INFO, WARNING, ERROR

function writeLog($message, $level = 'INFO', $data = null) {
    if (!LOG_ENABLED) return;
    
    $levels = ['DEBUG' => 0, 'INFO' => 1, 'WARNING' => 2, 'ERROR' => 3];
    if (!isset($levels[$level]) || $levels[$level] < $levels[LOG_LEVEL]) return;
    
    $logDir = dirname(LOG_FILE);
    if (!is_dir($logDir)) {
        mkdir($logDir, 0755, true);
    }
    
    $timestamp = date('Y-m-d H:i:s');
    $logEntry = "[{$timestamp}] [{$level}] {$message}";
    
    if ($data !== null) {
        if (is_array($data) || is_object($data)) {
            $logEntry .= " | Data: " . json_encode($data, JSON_UNESCAPED_UNICODE | JSON_PARTIAL_OUTPUT_ON_ERROR);
        } else {
            $logEntry .= " | Data: " . substr((string)$data, 0, 500);
        }
    }
    
    $logEntry .= PHP_EOL;
    
    error_log($logEntry);
    file_put_contents(LOG_FILE, $logEntry, FILE_APPEND | LOCK_EX);
}

function logDebug($msg, $data = null) { writeLog($msg, 'DEBUG', $data); }
function logInfo($msg, $data = null) { writeLog($msg, 'INFO', $data); }
function logWarning($msg, $data = null) { writeLog($msg, 'WARNING', $data); }
function logError($msg, $data = null) { writeLog($msg, 'ERROR', $data); }

// ===== DECRYPTION FUNCTION =====
function decrypt($encryptedData, $key) {
    try {
        if (!$encryptedData || !is_string($encryptedData)) {
            logDebug("Decrypt: No data or invalid type", gettype($encryptedData));
            return '[No data]';
        }

        // Check if already JSON (not encrypted)
        if (preg_match('/^\s*[\{\[]/', $encryptedData)) {
            logDebug("Decrypt: Data is already JSON");
            return $encryptedData;
        }

        // Not encrypted format (no :: separator)
        if (strpos($encryptedData, '::') === false) {
            // Try base64 decode
            $decoded = base64_decode($encryptedData, true);
            if ($decoded !== false) {
                // Check for gzip magic bytes
                if (substr($decoded, 0, 2) === "\x1f\x8b") {
                    $decompressed = @gzdecode($decoded);
                    if ($decompressed !== false) {
                        logDebug("Decrypt: Decompressed gzip data");
                        return $decompressed;
                    }
                }
                // Check if decoded is printable
                if (ctype_print($decoded) || mb_check_encoding($decoded, 'UTF-8')) {
                    logDebug("Decrypt: Decoded base64 data");
                    return $decoded;
                }
            }
            logDebug("Decrypt: Plain text data");
            return $encryptedData;
        }

        // Encrypted format: ciphertext::iv
        $parts = explode('::', $encryptedData, 2);
        if (count($parts) !== 2) {
            logError("Decrypt: Invalid format - no :: separator");
            return '[Decryption failed: Invalid format]';
        }
        
        list($ciphertext, $iv) = $parts;

        if (empty($ciphertext) || empty($iv)) {
            logError("Decrypt: Empty ciphertext or IV");
            return '[Decryption failed: Empty data]';
        }

        // Decode IV from base64
        $ivDecoded = base64_decode($iv, true);
        if ($ivDecoded === false) {
            logError("Decrypt: Invalid IV base64");
            return '[Decryption failed: Invalid IV]';
        }
        
        logDebug("IV info", ['iv_b64_len' => strlen($iv), 'iv_decoded_len' => strlen($ivDecoded)]);

        // ===== KEY PREPARATION =====
        // Your key: nTds2GHvEWeOGJibjZuaf8kY5T5YWyfMx4J3B1NA0Jo=
        // This is a base64-encoded 32-byte key
        
        $keyDecoded = base64_decode($key, true);
        
        if ($keyDecoded === false) {
            logError("Decrypt: Key is not valid base64, using raw key");
            $keyDecoded = $key;
        }
        
        $keyLen = strlen($keyDecoded);
        logDebug("Key info", ['key_b64_len' => strlen($key), 'key_decoded_len' => $keyLen]);
        
        // If key is not 32 bytes after base64 decode, try other methods
        if ($keyLen !== 32) {
            // Try hex decode
            if (strlen($key) === 64 && ctype_xdigit($key)) {
                $keyDecoded = hex2bin($key);
                logDebug("Key converted from hex");
            }
            // Try using raw key if it's 32 bytes
            elseif (strlen($key) === 32) {
                $keyDecoded = $key;
                logDebug("Using raw 32-byte key");
            }
            // Hash the key as fallback
            else {
                $keyDecoded = hash('sha256', $key, true);
                logDebug("Key hashed with SHA256");
            }
        }

        if (strlen($keyDecoded) !== 32) {
            logError("Decrypt: Key length still invalid after processing", strlen($keyDecoded));
            return '[Decryption failed: Invalid key length]';
        }

        // ===== DECRYPTION ATTEMPTS =====
        
        // Method 1: ciphertext is base64 encoded (most common)
        $decrypted = openssl_decrypt(
            $ciphertext,
            'aes-256-cbc',
            $keyDecoded,
            0, // This means input is base64
            $ivDecoded
        );

        if ($decrypted !== false) {
            logDebug("Decrypt: AES-256-CBC (base64 input) success");
            return $decrypted;
        }

        // Method 2: ciphertext needs base64 decode first
        $ciphertextRaw = base64_decode($ciphertext, true);
        if ($ciphertextRaw !== false) {
            $decrypted = openssl_decrypt(
                $ciphertextRaw,
                'aes-256-cbc',
                $keyDecoded,
                OPENSSL_RAW_DATA,
                $ivDecoded
            );
            if ($decrypted !== false) {
                logDebug("Decrypt: AES-256-CBC (raw input) success");
                return $decrypted;
            }
        }

        // Method 3: Try without padding
        $decrypted = openssl_decrypt(
            $ciphertext,
            'aes-256-cbc',
            $keyDecoded,
            OPENSSL_ZERO_PADDING,
            $ivDecoded
        );
        if ($decrypted !== false) {
            $decrypted = rtrim($decrypted, "\0");
            logDebug("Decrypt: AES-256-CBC (zero padding) success");
            return $decrypted;
        }

        // Method 4: Try AES-128-CBC
        $key128 = substr($keyDecoded, 0, 16);
        $decrypted = openssl_decrypt($ciphertext, 'aes-128-cbc', $key128, 0, $ivDecoded);
        if ($decrypted !== false) {
            logDebug("Decrypt: AES-128-CBC success");
            return $decrypted;
        }

        $opensslError = openssl_error_string();
        logError("Decrypt: All methods failed", [
            'openssl_error' => $opensslError,
            'ciphertext_len' => strlen($ciphertext),
            'iv_len' => strlen($ivDecoded),
            'key_len' => strlen($keyDecoded)
        ]);
        
        return '[Decryption failed: ' . ($opensslError ?: 'Unknown error') . ']';

    } catch (Exception $e) {
        logError("Decrypt exception", $e->getMessage());
        return '[Decryption error: ' . $e->getMessage() . ']';
    }
}

function formatJsonForDownload($jsonString) {
    if (empty($jsonString)) return 'No data';

    if (preg_match('/^\s*[\{\[]/', $jsonString)) {
        $jsonDecoded = json_decode($jsonString, true);
        if ($jsonDecoded !== null) {
            return json_encode($jsonDecoded, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
        }
    }
    return $jsonString;
}

function validateSession() {
    if (isset($_SESSION['login_time'])) {
        $session_duration = 8 * 60 * 60;
        if (time() - $_SESSION['login_time'] > $session_duration) {
            logInfo("Session expired");
            session_destroy();
            return false;
        }
    }
    return isset($_SESSION['logged_in']) && $_SESSION['logged_in'] === true;
}

function detectDataType($data) {
    if (empty($data)) return 'empty';
    if (strpos($data, '::') !== false) return 'encrypted';

    $decoded = base64_decode($data, true);
    if ($decoded !== false) {
        if (substr($decoded, 0, 2) === "\x1f\x8b") return 'gzipped';
        if (preg_match('/[^\x20-\x7E\t\r\n]/', substr($decoded, 0, 100))) return 'binary';
        return 'base64';
    }

    if (preg_match('/^\s*[\{\[]/', $data)) return 'json';
    return 'plain';
}

// ===== DEBUG HELPER =====
function testDecryption($encryptedSample = null) {
    $key = Config::$ENCRYPTION_KEY;
    
    $info = [
        'key_original' => substr($key, 0, 20) . '...',
        'key_length' => strlen($key),
    ];
    
    // Decode key
    $keyDecoded = base64_decode($key, true);
    if ($keyDecoded !== false) {
        $info['key_decoded_length'] = strlen($keyDecoded);
        $info['key_is_valid_32_bytes'] = (strlen($keyDecoded) === 32);
    } else {
        $info['key_decode_failed'] = true;
    }
    
    // Test with sample if provided
    if ($encryptedSample && strpos($encryptedSample, '::') !== false) {
        list($cipher, $iv) = explode('::', $encryptedSample, 2);
        $info['sample_cipher_len'] = strlen($cipher);
        $info['sample_iv_len'] = strlen($iv);
        $info['sample_iv_decoded_len'] = strlen(base64_decode($iv, true) ?: '');
    }
    
    logInfo("Decryption Test Info", $info);
    return $info;
}
?>