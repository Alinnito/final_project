"""
Криптографический модуль (Crypto Engine) комплекса защиты баз данных
Реализует:
1. Симметричное шифрование полей (AES-128-CBC + HMAC-SHA256 через Fernet)
2. Динамическое маскирование персональных данных (Dynamic Data Masking)
3. Формирование и проверку имитовставки (HMAC) для защиты целостности записей аудита
"""
import hmac
import hashlib
import re
from typing import Optional, Any
from core.config import SecurityConfig
from cryptography.fernet import Fernet

class CryptoEngine:
    def __init__(self, config: Optional[SecurityConfig] = None):
        self.config = config or SecurityConfig()
        self.fernet = Fernet(self.config.encryption_key)
        self.hmac_secret = self.config.audit_hmac_secret

    def encrypt_field(self, plaintext: str) -> str:
        """Симметричное шифрование строки. Возвращает base64-токен"""
        if plaintext is None:
            return ""
        encrypted_bytes = self.fernet.encrypt(str(plaintext).encode("utf-8"))
        return encrypted_bytes.decode("utf-8")

    def decrypt_field(self, ciphertext: str) -> str:
        """Расшифрование токена. В случае ошибки возвращает исходный текст"""
        if not ciphertext:
            return ""
        try:
            decrypted_bytes = self.fernet.decrypt(ciphertext.encode("utf-8"))
            return decrypted_bytes.decode("utf-8")
        except Exception:
            return "[DECRYPTION_ERROR: INVALID_KEY_OR_DATA]"

    def compute_hmac(self, data_string: str) -> str:
        """Вычисляет HMAC-SHA256 от строки данных с секретным ключом аудита"""
        signature = hmac.new(
            self.hmac_secret,
            data_string.encode("utf-8"),
            hashlib.sha256
        ).hexdigest()
        return signature

    def verify_hmac(self, data_string: str, expected_hmac: str) -> bool:
        """Проверяет целостность записи журнала аудита"""
        actual_hmac = self.compute_hmac(data_string)
        return hmac.compare_digest(actual_hmac, expected_hmac)

    # Алгоритмы динамического маскирования персональных данных

    @staticmethod
    def mask_phone(phone: str) -> str:
        """Маскирование номера телефона: +7 (999) ***-**-12"""
        clean = re.sub(r"[^\d+]", "", phone)
        if len(clean) >= 11:
            return f"{clean[:5]}***-**-{clean[-2:]}"
        return "***-***-**"

    @staticmethod
    def mask_email(email: str) -> str:
        """Маскирование адреса электронной почты: a***e@domain.com"""
        if "@" not in email:
            return "***"
        user, domain = email.split("@", 1)
        if len(user) <= 2:
            masked_user = user[0] + "***"
        else:
            masked_user = f"{user[0]}***{user[-1]}"
        return f"{masked_user}@{domain}"

    @staticmethod
    def mask_passport(passport: str) -> str:
        """Маскирование паспорта РФ (серия и номер): **** ***456"""
        clean = re.sub(r"\s+", "", passport)
        if len(clean) >= 10:
            return f"**** ***{clean[-3:]}"
        return "**** ******"

    @staticmethod
    def mask_card(card_number: str) -> str:
        """Маскирование номера банковской карты: **** **** **** 1234"""
        clean = re.sub(r"\D", "", card_number)
        if len(clean) >= 16:
            return f"**** **** **** {clean[-4:]}"
        return "**** **** **** ****"

    @staticmethod
    def mask_salary(_val: Any) -> str:
        """Маскирование финансовой информации (оклад/стипендия)"""
        return "***,** руб."

    def mask_value_by_type(self, value: str, mask_type: str) -> str:
        """Универсальный метод маскирования по типу атрибута"""
        if value is None:
            return ""
        s_val = str(value)
        if mask_type == "phone":
            return self.mask_phone(s_val)
        elif mask_type == "email":
            return self.mask_email(s_val)
        elif mask_type == "passport":
            return self.mask_passport(s_val)
        elif mask_type == "card":
            return self.mask_card(s_val)
        elif mask_type == "salary":
            return self.mask_salary(s_val)
        elif mask_type in ("inn", "snils"):
            if len(s_val) > 4:
                return f"***-***-{s_val[-4:]}"
            return "***"
        return "********"
