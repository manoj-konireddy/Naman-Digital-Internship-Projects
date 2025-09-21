import base64
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import json

class EncryptionManager:
    def __init__(self, encryption_key=None):
        """Initialize encryption manager with user's encryption key"""
        if encryption_key:
            self.key = base64.b64decode(encryption_key.encode('utf-8'))
        else:
            self.key = None
    
    def set_key(self, encryption_key):
        """Set the encryption key"""
        self.key = base64.b64decode(encryption_key.encode('utf-8'))
    
    def encrypt_message(self, message):
        """Encrypt message using AES-256-GCM"""
        if not self.key:
            raise ValueError("Encryption key not set")
        
        # Generate a random IV (Initialization Vector)
        iv = os.urandom(16)  # 128-bit IV for AES
        
        # Create cipher
        cipher = Cipher(
            algorithms.AES(self.key),
            modes.GCM(iv),
            backend=default_backend()
        )
        
        encryptor = cipher.encryptor()
        
        # Encrypt the message
        message_bytes = message.encode('utf-8')
        ciphertext = encryptor.update(message_bytes) + encryptor.finalize()
        
        # Combine IV, ciphertext, and authentication tag
        encrypted_data = {
            'iv': base64.b64encode(iv).decode('utf-8'),
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
            'tag': base64.b64encode(encryptor.tag).decode('utf-8')
        }
        
        # Return as base64 encoded JSON string
        return base64.b64encode(json.dumps(encrypted_data).encode('utf-8')).decode('utf-8')
    
    def decrypt_message(self, encrypted_message):
        """Decrypt message using AES-256-GCM"""
        if not self.key:
            raise ValueError("Encryption key not set")
        
        try:
            # Decode the base64 JSON string
            encrypted_data = json.loads(base64.b64decode(encrypted_message.encode('utf-8')).decode('utf-8'))
            
            # Extract components
            iv = base64.b64decode(encrypted_data['iv'].encode('utf-8'))
            ciphertext = base64.b64decode(encrypted_data['ciphertext'].encode('utf-8'))
            tag = base64.b64decode(encrypted_data['tag'].encode('utf-8'))
            
            # Create cipher
            cipher = Cipher(
                algorithms.AES(self.key),
                modes.GCM(iv, tag),
                backend=default_backend()
            )
            
            decryptor = cipher.decryptor()
            
            # Decrypt the message
            decrypted_bytes = decryptor.update(ciphertext) + decryptor.finalize()
            
            return decrypted_bytes.decode('utf-8')
            
        except Exception as e:
            return f"[DECRYPTION ERROR: {str(e)}]"
    
    def generate_key(self):
        """Generate a new 256-bit encryption key"""
        key = os.urandom(32)  # 256 bits
        return base64.b64encode(key).decode('utf-8')
    
    def test_encryption(self):
        """Test encryption/decryption functionality"""
        if not self.key:
            return False, "No encryption key set"
        
        test_message = "Hello, this is a test message for encryption!"
        
        try:
            # Encrypt
            encrypted = self.encrypt_message(test_message)
            # Decrypt
            decrypted = self.decrypt_message(encrypted)
            
            if decrypted == test_message:
                return True, "Encryption test passed"
            else:
                return False, "Encryption test failed: decrypted message doesn't match"
                
        except Exception as e:
            return False, f"Encryption test failed: {str(e)}"
