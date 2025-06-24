<?php
namespace Database;

use PDO;
use PDOException;
use \Config;
require_once __DIR__ . '/../../config.php';

class DatabaseConnection
{
    private $pdo;

    public function __construct()
    {
        try {
            $dsn = "mysql:host=" . Config::$DB_HOST . ";dbname=" . Config::$DB_NAME . ";charset=utf8mb4";
            $this->pdo = new PDO($dsn, Config::$DB_USER, Config::$DB_PASS);
            $this->pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            $this->pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
        } catch (PDOException $e) {
            error_log("Database connection failed: " . $e->getMessage());
            die("Database connection error");
        }
    }

    public function getPdo(): PDO
    {
        return $this->pdo;
    }
}