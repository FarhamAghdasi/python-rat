# ------------ encryption/manager.py ------------
import base64
import hashlib
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from config import Config  # اضافه کردن ایمپورت


class EncryptionManager:
    def __init__(self, encryption_key):
        self.key = encryption_key
        self._validate_key()

    def _validate_key(self):
        if len(self.key) != 32:
            raise ValueError("Encryption key must be 32 bytes")

    def encrypt(self, plaintext):
        try:
            iv = os.urandom(Config.IV_LENGTH)
            cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            
            padder = padding.PKCS7(128).padder()
            padded_data = padder.update(plaintext.encode()) + padder.finalize()
            
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()
            return f"{base64.b64encode(ciphertext).decode()}::{base64.b64encode(iv).decode()}"
        except Exception as e:
            raise EncryptionError(f"Encryption failed: {str(e)}")

    def decrypt(self, encrypted_data):
        try:
            ciphertext_b64, iv_b64 = encrypted_data.split('::')
            ciphertext = base64.b64decode(ciphertext_b64)
            iv = base64.b64decode(iv_b64)
            
            cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            
            decrypted = decryptor.update(ciphertext) + decryptor.finalize()
            
            unpadder = padding.PKCS7(128).unpadder()
            return (unpadder.update(decrypted) + unpadder.finalize()).decode()
        except Exception as e:
            raise EncryptionError(f"Decryption failed: {str(e)}")

class EncryptionError(Exception):
    pass