import unittest
from encryption.manager import EncryptionManager, EncryptionError
from rat_config import Config

class TestEncryptionManager(unittest.TestCase):
    def setUp(self):
        self.encryption = EncryptionManager(Config.ENCRYPTION_KEY)

    def test_encrypt_decrypt(self):
        plaintext = "test message"
        encrypted = self.encryption.encrypt(plaintext)
        decrypted = self.encryption.decrypt(encrypted)
        self.assertEqual(plaintext, decrypted)

    def test_invalid_key(self):
        with self.assertRaises(ValueError):
            EncryptionManager(b"invalid_key")

    def test_decrypt_invalid_data(self):
        with self.assertRaises(EncryptionError):
            self.encryption.decrypt("invalid::data")

if __name__ == '__main__':
    unittest.main()