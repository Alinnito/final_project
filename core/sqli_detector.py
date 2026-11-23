import re
import math
from typing import List, Optional
from dataclasses import dataclass
from core.config import SQLI_SIGNATURES

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

    def calculate_entropy(self, text: str) -> float:
        """Вычисляет информационную энтропию Шеннона для детекции обфускации"""
        if not text:
            return 0.0
        # Вероятность каждого уникального значения
        prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
        entropy = -sum([p * math.log2(p) for p in prob if p > 0])
        return entropy


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





