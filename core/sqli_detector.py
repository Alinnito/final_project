import re
from typing import List, Dict, Optional
from dataclasses import dataclass

@dataclass
class InspectionResult:
    is_threat: bool
    risk_score: int
    matched_rules: List[str]
    attack_categories: List[str]
    action: str
    explanation: str
    original_query: str
    sanitized_query: Optional[str] = None

class SQLiDetector:
    def __init__(self):
        self.signatures = SQLI_SIGNATURES

    def inspect_query(self, query: str) -> InspectionResult:
        if not query or not query.strip():
            return InspectionResult(
                is_threat=False,
                risk_score=0,
                matched_rules=[],
                attack_categories=[],
                action="ALLOW",
                explanation="Пустой запрос",
                original_query=""
            )

        matched_rules = []
        categories = []
        rule_risk_max = 0

        # Сигнатурный анализ
        for sig in self.signatures:
            if re.search(sig["pattern"], query):
                matched_rules.append(sig["name"])
                if sig["category"] not in categories:
                    categories.append(sig["category"])
                if sig["risk"] > rule_risk_max:
                    rule_risk_max = sig["risk"]

        return InspectionResult(
            is_threat=True,
            risk_score=rule_risk_max,
            matched_rules=matched_rules,
            attack_categories=categories,
            action="BLOCK",
            explanation="Сигнатурный анализ",
            original_query=query
        )

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



