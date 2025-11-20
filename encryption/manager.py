# ------------ encryption/manager.py ------------
import base64
import hashlib
import os
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from rat_config import Config
import logging

class EncryptionManager:
    def __init__(self, encryption_key):
        # Derive a proper 32-byte key if needed
        if isinstance(encryption_key, str):
            self.key = self._derive_key(encryption_key)
        else:
            self.key = encryption_key
        self._validate_key()

    def _derive_key(self, password: str) -> bytes:
        """Derive a proper 32-byte key from password using PBKDF2"""
        try:
            # Use a fixed salt for consistency, in production use random salt
            salt = b'rat_encryption_salt_2024'
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )
            return kdf.derive(password.encode())
        except Exception as e:
            logging.error(f"Key derivation error: {str(e)}")
            # Fallback to simple hashing
            return hashlib.sha256(password.encode()).digest()

    def _validate_key(self):
        """Validate encryption key length"""
        if len(self.key) != 32:
            raise ValueError(f"Encryption key must be 32 bytes, got {len(self.key)} bytes")

    def encrypt(self, plaintext):
        """
        Encrypt plaintext using AES-256-CBC with PKCS7 padding
        Returns: base64(ciphertext)::base64(iv)
        """
        try:
            if Config.DEBUG_MODE:
                logging.debug("Starting encryption")
            
            # Generate random IV
            iv = os.urandom(Config.IV_LENGTH)
            
            # Create cipher
            cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            
            # Apply PKCS7 padding
            padder = padding.PKCS7(128).padder()
            
            # Ensure plaintext is bytes
            if isinstance(plaintext, str):
                plaintext_bytes = plaintext.encode('utf-8')
            else:
                plaintext_bytes = plaintext
            
            padded_data = padder.update(plaintext_bytes) + padder.finalize()
            
            # Encrypt
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()
            
            # Combine ciphertext and IV
            result = f"{base64.b64encode(ciphertext).decode()}::{base64.b64encode(iv).decode()}"
            
            if Config.DEBUG_MODE:
                logging.debug("Encryption successful")
            return result
            
        except Exception as e:
            logging.error(f"Encryption failed: {str(e)}")
            raise EncryptionError(f"Encryption failed: {str(e)}")

    def decrypt(self, encrypted_data):
        """
        Decrypt encrypted data
        Expected format: base64(ciphertext)::base64(iv)
        """
        try:
            if Config.DEBUG_MODE:
                logging.debug("Starting decryption")
            
            # Split ciphertext and IV
            if '::' not in encrypted_data:
                raise EncryptionError("Invalid encrypted data format")
                
            ciphertext_b64, iv_b64 = encrypted_data.split('::', 1)
            
            # Decode from base64
            ciphertext = base64.b64decode(ciphertext_b64)
            iv = base64.b64decode(iv_b64)
            
            # Validate IV length
            if len(iv) != Config.IV_LENGTH:
                raise EncryptionError(f"Invalid IV length: {len(iv)}")
            
            # Create cipher
            cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            
            # Decrypt
            decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()
            
            # Remove PKCS7 padding
            unpadder = padding.PKCS7(128).unpadder()
            decrypted = unpadder.update(decrypted_padded) + unpadder.finalize()
            
            # Return as string
            result = decrypted.decode('utf-8')
            
            if Config.DEBUG_MODE:
                logging.debug("Decryption successful")
            return result
            
        except Exception as e:
            logging.error(f"Decryption failed: {str(e)}")
            raise EncryptionError(f"Decryption failed: {str(e)}")

    def encrypt_json(self, data):
        """Encrypt JSON data"""
        import json
        try:
            json_str = json.dumps(data, ensure_ascii=False)
            return self.encrypt(json_str)
        except Exception as e:
            logging.error(f"JSON encryption failed: {str(e)}")
            raise EncryptionError(f"JSON encryption failed: {str(e)}")

    def decrypt_json(self, encrypted_data):
        """Decrypt JSON data"""
        import json
        try:
            decrypted_str = self.decrypt(encrypted_data)
            return json.loads(decrypted_str)
        except Exception as e:
            logging.error(f"JSON decryption failed: {str(e)}")
            raise EncryptionError(f"JSON decryption failed: {str(e)}")

class EncryptionError(Exception):
    """Encryption/decryption related errors"""
    pass