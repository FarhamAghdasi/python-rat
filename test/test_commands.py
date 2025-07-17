import unittest
from unittest.mock import patch
from commands.handler import CommandHandler, CommandError
from config import Config

class TestCommandHandler(unittest.TestCase):
    def setUp(self):
        Config.TEST_MODE = True
        Config.DEBUG_MODE = True

    @patch('commands.handler.subprocess.run')
    def test_handle_system_command(self, mock_subprocess):
        mock_subprocess.return_value = MagicMock(stdout="Success", stderr="", returncode=0)
        result = CommandHandler.handle_system_command({"command": "shutdown"})
        self.assertEqual(result["returncode"], 0)
        mock_subprocess.assert_called_with(
            ['cmd.exe', '/c', 'shutdown /s /t 0'],
            capture_output=True,
            text=True,
            timeout=300
        )

    @patch('commands.handler.pyautogui.screenshot')
    def test_handle_screenshot(self, mock_screenshot):
        mock_screenshot.return_value = MagicMock(save=lambda x: None)
        with patch('builtins.open', create=True) as mock_open:
            result = CommandHandler.handle_screenshot({})
            self.assertIn('screenshot', result)
            mock_open.assert_called_with('screenshot_temp.png', 'rb')

    def tearDown(self):
        Config.TEST_MODE = False
        Config.DEBUG_MODE = False

if __name__ == '__main__':
    unittest.main()