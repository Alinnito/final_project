"""
Модуль защищенного аудита и управления инцидентами ИБ (Audit Logger)
Обеспечивает формирование неизменяемого журнала аудита (Tamper-Resistant Log)
с расчетом HMAC-SHA256 для каждой записи, фильтрацию и экспорт отчетов
"""
import time
from dataclasses import dataclass
from typing import List, Optional
from core.crypto_engine import CryptoEngine

@dataclass
class AuditRecord:
    record_id: int
    timestamp: str
    username: str
    client_ip: str
    query_text: str
    operation: str
    risk_score: int
    is_blocked: bool
    incident_type: Optional[str]
    integrity_hmac: str

class AuditLogger:
    def __init__(self, crypto_engine: Optional[CryptoEngine] = None):
        self.crypto_engine = crypto_engine or CryptoEngine()
        self.records: List[AuditRecord] = []
        self._counter = 1

    def log_event(self, username: str, client_ip: str, query: str,
                  risk_score: int, is_blocked: bool, incident_type: Optional[str] = None) -> AuditRecord:
        """Регистрирует событие доступа к БД и подписывает его HMAC-хешем"""
        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        op = "SELECT"
        q_upper = query.strip().upper()
        for candidate in ["SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "ALTER", "CREATE", "TRUNCATE"]:
            if q_upper.startswith(candidate):
                op = candidate
                break

        # Строка для вычисления HMAC
        data_to_sign = f"{self._counter}|{ts}|{username}|{client_ip}|{query}|{op}|{risk_score}|{is_blocked}"
        hmac_sig = self.crypto_engine.compute_hmac(data_to_sign)

        record = AuditRecord(
            record_id=self._counter,
            timestamp=ts,
            username=username,
            client_ip=client_ip,
            query_text=query,
            operation=op,
            risk_score=risk_score,
            is_blocked=is_blocked,
            incident_type=incident_type,
            integrity_hmac=hmac_sig
        )
        self.records.append(record)
        self._counter += 1
        return record

    def verify_all_records(self) -> List[int]:
        """Проверяет целостность всех записей в журнале аудита. Возвращает список поврежденных ID"""
        corrupted_ids = []
        for r in self.records:
            data_to_verify = f"{r.record_id}|{r.timestamp}|{r.username}|{r.client_ip}|{r.query_text}|{r.operation}|{r.risk_score}|{r.is_blocked}"
            if not self.crypto_engine.verify_hmac(data_to_verify, r.integrity_hmac):
                corrupted_ids.append(r.record_id)
        return corrupted_ids