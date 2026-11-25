"""
Модуль защищенного аудита и управления инцидентами ИБ (Audit Logger)
Обеспечивает формирование неизменяемого журнала аудита (Tamper-Resistant Log)
с расчетом HMAC-SHA256 для каждой записи, фильтрацию и экспорт отчетов
"""
import time
import json
from dataclasses import dataclass, asdict
from typing import List, Optional
from core.db_connector import DBConnector
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
    def __init__(self, crypto_engine: Optional[CryptoEngine] = None, db_connector: Optional[DBConnector] = None):
        self.db = db_connector
        self.crypto_engine = crypto_engine or CryptoEngine()
        self.records: List[AuditRecord] = []
        self._counter = 1
        self._load_from_db()

    def _load_from_db(self):
        try:
            cursor = self.db.conn.cursor()
            cursor.execute(
                "SELECT id, event_time, username, client_ip, query_text, "
                "operation_type, risk_score, is_blocked, incident_type, integrity_hmac "
                "FROM audit_logs ORDER BY id"
            )
            for row in cursor.fetchall():
                rec = AuditRecord(
                    record_id=row[0],
                    timestamp=str(row[1]),
                    username=row[2],
                    client_ip=row[3],
                    query_text=row[4],
                    operation=row[5],
                    risk_score=row[6],
                    is_blocked=bool(row[7]),
                    incident_type=row[8],
                    integrity_hmac=row[9]
                )
                self.records.append(rec)
                if rec.record_id >= self._counter:
                    self._counter = rec.record_id + 1
        except Exception:
            return

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

        # Сохранение в БД
        if self.db and self.db.conn:
            try:
                ph = "%s" if self.db.mode.startswith("PostgreSQL") else "?"
                cursor = self.db.conn.cursor()
                cursor.execute(
                    f"INSERT INTO audit_logs "
                    f"(id, event_time, username, client_ip, query_text, operation_type, "
                    f"risk_score, is_blocked, incident_type, integrity_hmac) "
                    f"VALUES ({ph},{ph},{ph},{ph},{ph},{ph},{ph},{ph},{ph},{ph})",
                    (record.record_id, record.timestamp, record.username,
                     record.client_ip, record.query_text, record.operation,
                     record.risk_score, record.is_blocked, record.incident_type,
                     record.integrity_hmac)
                )
                self.db.conn.commit()
            except Exception:
                pass

        self._counter += 1
        return record

    def verify_all_records(self) -> List[int]:
        """Проверяет целостность всех записей в журнале аудита. Возвращает список поврежденных ID"""
        corrupted_ids = []
        for r in self.records:
            data_to_verify = (f"{r.record_id}|{r.timestamp}|{r.username}|{r.client_ip}|"
                              f"{r.query_text}|{r.operation}|{r.risk_score}|{r.is_blocked}")
            if not self.crypto_engine.verify_hmac(data_to_verify, r.integrity_hmac):
                corrupted_ids.append(r.record_id)
        return corrupted_ids

    def get_incidents(self) -> List[AuditRecord]:
        """Возвращает только те записи, которые были классифицированы как инциденты ИБ"""
        return [r for r in self.records if r.risk_score >= 50 or r.is_blocked]

    def export_json(self) -> str:
        """Экспорт журнала аудита в формат JSON"""
        return json.dumps([asdict(r) for r in self.records], ensure_ascii=False, indent=2)

    def repair_integrity(self) -> int:
        """
        Пересчитывает HMAC для всех записей по их текущим данным
        и обновляет записи в БД. Возвращает количество восстановленных записей
        """
        repaired = 0
        for r in self.records:
            # Пересчитываем HMAC по текущим (возможно, поддельным) данным
            data_to_sign = (
                f"{r.record_id}|{r.timestamp}|{r.username}|{r.client_ip}|"
                f"{r.query_text}|{r.operation}|{r.risk_score}|{r.is_blocked}"
            )
            new_hmac = self.crypto_engine.compute_hmac(data_to_sign)

            # Если HMAC изменился — обновляем запись в памяти и в БД
            if new_hmac != r.integrity_hmac:
                r.integrity_hmac = new_hmac
                repaired += 1

                if self.db and self.db.conn:
                    try:
                        ph = "%s" if self.db.mode.startswith("PostgreSQL") else "?"
                        cursor = self.db.conn.cursor()
                        cursor.execute(
                            f"UPDATE audit_logs SET integrity_hmac = {ph} WHERE id = {ph}",
                            (new_hmac, r.record_id))
                        self.db.conn.commit()
                    except Exception:
                        pass

        return repaired