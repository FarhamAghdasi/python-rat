<?php
require_once 'config.php';

class Utils {
    public static function sanitize_input($input) {
        return htmlspecialchars(strip_tags(trim($input)));
    }

    public static function get_admin_chat_id($pdo) {
        return Config::$ADMIN_CHAT_ID;
    }

    public static function log_error($message) {
        $log_entry = [
            'time' => date('Y-m-d H:i:s'),
            'message' => $message
        ];
        file_put_contents(Config::$ERROR_LOG, json_encode($log_entry, JSON_UNESCAPED_UNICODE) . PHP_EOL, FILE_APPEND);
    }
}
?>