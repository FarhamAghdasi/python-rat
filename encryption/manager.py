# ------------ encryption/manager.py ------------
import base64
import hashlib
import os  # Added import
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from config import Config
import logging  # Added for debugging

class EncryptionManager:
    def __init__(self, encryption_key):
        self.key = encryption_key
        self._validate_key()

    def _validate_key(self):
        if len(self.key) != 32:
            raise ValueError("Encryption key must be 32 bytes")

    def encrypt(self, plaintext):
        try:
            logging.info("Starting encryption")
            iv = os.urandom(Config.IV_LENGTH)
            cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            
            padder = padding.PKCS7(128).padder()
            padded_data = padder.update(plaintext.encode()) + padder.finalize()
            
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()
            result = f"{base64.b64encode(ciphertext).decode()}::{base64.b64encode(iv).decode()}"
            logging.info("Encryption successful")
            return result
        except Exception as e:
            logging.error(f"Encryption failed: {str(e)}")
            raise EncryptionError(f"Encryption failed: {str(e)}")

    def decrypt(self, encrypted_data):
        try:
            logging.info("Starting decryption")
            ciphertext_b64, iv_b64 = encrypted_data.split('::')
            ciphertext = base64.b64decode(ciphertext_b64)
            iv = base64.b64decode(iv_b64)
            
            cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            
            decrypted = decryptor.update(ciphertext) + decryptor.finalize()
            
            unpadder = padding.PKCS7(128).unpadder()
            result = (unpadder.update(decrypted) + unpadder.finalize()).decode()
            logging.info("Decryption successful")
            return result
        except Exception as e:
            logging.error(f"Decryption failed: {str(e)}")
            raise EncryptionError(f"Decryption failed: {str(e)}")

class EncryptionError(Exception):
    pass