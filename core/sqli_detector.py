"""
Модуль описания SQL-инъекций и вредоносных запросов (SQLi Detector)
Реализует комбинированный подход:
- Сигнатурный анализ регулярными выражениями (OWASP SQLi Patterns);
- Эвристический анализ токенов и кавычек;
- Вычисление коэффициента риска (Risk Score) от 0 до 100;
- Классификацию инцидента и выработку защитного действия
"""
import re
import math
from typing import List, Optional
from dataclasses import dataclass
from core.config import SQLI_SIGNATURES, SecurityConfig

@dataclass
class InspectionResult:
    is_threat: bool
    risk_score: int
    matched_rules: List[str]
    attack_categories: List[str]
    action: str # ALLOW, WARN, BLOCK
    explanation: str
    original_query: str
    sanitized_query: Optional[str] = None

class SQLiDetector:
    def __init__(self, config: Optional[SecurityConfig] = None):
        self.config = config or SecurityConfig()
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
        if len(query) > 0 and (special_chars / len(query)) > 0.15:
            score += 25

        # Энтропия выше нормы для стандартных SQL-запросов (признак обфускации)
        ent = self.calculate_entropy(query)
        if ent > 4.8 and len(query) > 30:
            score += 20

        return score

    def inspect_query(self, query: str) -> InspectionResult:
        """Комплексная инспекция SQL-запроса на признаки атак"""
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

        # Эвристический анализ
        heuristic_score = self.analyze_heuristics(query)

        # Результирующий риск (композиция максимума сигнатур и эвристики)
        final_risk = min(100, rule_risk_max + (heuristic_score // 2))

        is_threat = final_risk >= self.config.risk_threshold_medium
        if final_risk >= self.config.auto_block_threshold:
            action = "BLOCK"
            explanation = f"Критическая угроза! Запрос заблокирован (Риск: {final_risk}/100)."
        elif final_risk >= self.config.risk_threshold_medium:
            action = "WARN"
            explanation = f"Подозрительная активность зафиксирована в аудите (Риск: {final_risk}/100)."
        else:
            action = "ALLOW"
            explanation = "Запрос признан легитимным и безопасным."

        if matched_rules:
            explanation += f" Сработавшие правила: {', '.join(matched_rules)}."

        return InspectionResult(
            is_threat=is_threat,
            risk_score=final_risk,
            matched_rules=matched_rules,
            attack_categories=categories,
            action=action,
            explanation=explanation,
            original_query=query
        )
