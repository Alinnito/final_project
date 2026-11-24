import hmac
from typing import Optional
from core.config import SecurityConfig
from cryptography.fernet import Fernet


class CryptoEngine:
    def __init__(self, config: Optional[SecurityConfig] = None):
        self.config = config or SecurityConfig()
        self.fernet = Fernet(self.config.encryption_key)
        self.hmac_secret = self.config.audit_hmac_secret


