"""
Пакет ядровых модулей комплекса защиты баз данных (DBSecGuard).
"""
from core.config import DatabaseConfig, SecurityConfig, SQLI_SIGNATURES
from core.crypto_engine import CryptoEngine
from core.sqli_detector import SQLiDetector, InspectionResult
from core.rbac_manager import RBACManager, Role, Permission, UserSession
from core.audit_logger import AuditLogger, AuditRecord
from core.db_connector import DBConnector