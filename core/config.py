"""
Модуль конфигурации комплекса защиты баз данных (DBSecGuard)
Содержит настройки подключения, параметры криптографической защиты,
правила сигнатурного анализа и пороговые значения системы обнаружения атак
"""
import os
from typing import List, Dict
from dataclasses import dataclass

@dataclass
class DatabaseConfig:
    host: str = os.getenv("DB_HOST", "localhost")
    port: int = int(os.getenv("DB_PORT", "5432"))
    dbname: str = os.getenv("DB_NAME", "TEST")
    user: str = os.getenv("DB_USER", "sa")
    password: str = os.getenv("DB_PASS", "1234")
    use_sqlite_fallback: bool = True
    sqlite_path: str = os.path.join(os.path.dirname(__file__), "..", "db_local_sec.db")

@dataclass
class SecurityConfig:
    # Симметричный ключ Fernet (AES-128 в режиме CBC с аутентификацией HMAC-SHA256)
    encryption_key: bytes = b'vE9qT1zQyW5X8K7mP3nL0bJ6cV4xF2gH9sD8aM1kO4I='
    # Соль для хеширования записей журнала аудита
    audit_hmac_secret: bytes = b'EnterpriseDBSecuritySecret2026_AuditSalt!'
    # Пороговые значения риска (от 0 до 100)
    risk_threshold_low: int = 25
    risk_threshold_medium: int = 50
    risk_threshold_high: int = 75
    # Автоматическая блокировка запроса при риске выше:
    auto_block_threshold: int = 70

SQLI_SIGNATURES: List[Dict] = [
    {
        "id": "SQLI_TAUTOLOGY",
        "name": "Тавтологическое выражение (логическое тождество)",
        "pattern": r"(?i)(\b(or|and)\b\s+[\'\"]?\w+[\'\"]?\s*=\s*[\'\"]?\w+[\'\"]?|1\s*=\s*1|0\s*=\s*0|true\s*=\s*true)",
        "risk": 85,
        "category": "Authentication Bypass / Data Leak"
    },
    {
        "id": "SQLI_UNION",
        "name": "Внедрение через оператор UNION SELECT",
        "pattern": r"(?i)\bunion\s+(all\s+)?select\b",
        "risk": 95,
        "category": "Information Disclosure"
    },
    {
        "id": "SQLI_STACKED",
        "name": "Многократные/составные запросы (Stacked Queries)",
        "pattern": r"(?i);\s*(drop|alter|delete|update|insert|create|truncate)\b",
        "risk": 100,
        "category": "Data Destruction / Unauthorized Modification"
    },
    {
        "id": "SQLI_COMMENTS",
        "name": "Символы обрезки и комментирования SQL",
        "pattern": r"(--|#|/\*.*?\*/)",
        "risk": 60,
        "category": "Syntax Obfuscation"
    },
    {
        "id": "SQLI_TIME_BASED",
        "name": "Слепая инъекция на основе задержки времени (Time-Based)",
        "pattern": r"(?i)\b(pg_sleep|sleep|waitfor\s+delay|benchmark)\s*\(",
        "risk": 90,
        "category": "Blind SQL Injection"
    },
    {
        "id": "SQLI_SYS_FUNCS",
        "name": "Обращение к системным таблицам и метаданным СУБД",
        "pattern": r"(?i)\b(information_schema|pg_catalog|pg_tables|pg_user|pg_shadow)\b",
        "risk": 80,
        "category": "Reconnaissance / Metadata Harvesting"
    },
    {
        "id": "SQLI_PRIV_ESC",
        "name": "Попытка повышения привилегий или вызова шелла",
        "pattern": r"(?i)\b(copy\s+.*\s+from\s+program|xp_cmdshell|pg_read_file)\b",
        "risk": 100,
        "category": "Remote Code Execution / Privilege Escalation"
    }
]