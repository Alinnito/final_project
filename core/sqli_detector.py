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

    def calculate_entropy(self, query: str) -> float:
        """Вычисляет информационную энтропию Шеннона для детекции обфускации"""
        if not query:
            return 0.0
        # Вероятность каждого уникального значения
        prob = [float(query.count(char)) / len(query) for char in dict.fromkeys(list(query))]
        entropy = -sum([p * math.log2(p) for p in prob if p > 0])
        return entropy

    def analyze_heuristics(self, query: str) -> int:
        """Эвристический анализ аномалий в синтаксисе SQL"""
        score = 0
        # Непарное количество кавычек
        single_quotes = query.count("'")
        double_quotes = query.count('"')
        if single_quotes % 2 != 0:
            score += 35
        if double_quotes % 2 != 0:
            score += 25

        # Аномальная плотность символов SQL
        special_chars = sum(1 for char in query if char in "=;#/*%\\@^~")
        if len(query) > 0 and (special_chars / len(query)) > 0/15:
            score += 25

        # Энтропия выше нормы для стандартных SQL-запросов (признак обфускации)
        ent = self.calculate_entropy(query)
        if ent > 4.8 and len(query) > 30:
            score += 20


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





