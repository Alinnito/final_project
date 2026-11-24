import hmac
from typing import Optional
from core.config import SecurityConfig
from cryptography.fernet import Fernet

class CryptoEngine:
    def __init__(self, config: Optional[SecurityConfig] = None):
        self.config = config or SecurityConfig()
        self.fernet = Fernet(self.config.encryption_key)
        self.hmac_secret = self.config.audit_hmac_secret

    def encrypt_field(self, plaintext: str) -> str:
        """Симметричное шифрование строки. Возвращает base64-токен."""
        if plaintext is None:
            return ""
        encrypted_bytes = self.fernet.encrypt(str(plaintext).encode("utf-8"))
        return encrypted_bytes.decode("utf-8")

    def decrypt_field(self, ciphertext: str) -> str:
        """Расшифрование токена. В случае ошибки возвращает исходный текст."""
        if not ciphertext:
            return ""
        try:
            decrypted_bytes = self.fernet.decrypt(ciphertext.encode("utf-8"))
            return decrypted_bytes.decode("utf-8")
        except InvalidToken:
            return "[DECRYPTION_ERROR: INVALID_KEY_OR_DATA]"
