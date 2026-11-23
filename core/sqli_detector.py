import re
from typing import List, Dict

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
    }
]

query = "select * from tbl where 1=1"
matched_rules = []
categories = []
rule_risk_max = 0

for sig in SQLI_SIGNATURES:
    if re.search(sig["pattern"], query):
        matched_rules.append(sig["name"])
        if sig["category"] not in categories:
            categories.append(sig["category"])
        if sig["risk"] > rule_risk_max:
            rule_risk_max = sig["risk"]

print(categories)
print(rule_risk_max)
