"""
Пакет ядровых модулей комплекса защиты баз данных (DBSecGuard).
"""
from core.config import SecurityConfig, SQLI_SIGNATURES
from core.sqli_detector import SQLiDetector, InspectionResult
from core.crypto_engine import CryptoEngine