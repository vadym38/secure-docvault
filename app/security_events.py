"""Кільцевий журнал інцидентів безпеки (ЛР №4).

Журнал живе в пам'яті процесу й обмежений `capacity`, тому навіть при
шквалі атак не споживає необмежену пам'ять. Для навчального стенда цього
достатньо; у production інциденти слід експортувати в SIEM/файл/БД.
"""

from __future__ import annotations

import threading
from collections import deque
from dataclasses import asdict, dataclass
from datetime import datetime, timezone


@dataclass(frozen=True)
class SecurityIncident:
    """Один запис журналу."""

    timestamp: str
    kind: str
    ip: str
    method: str
    path: str
    detail: str
    action: str
    status_code: int
    rule: str = ""
    retry_after: int = 0


class IncidentLog:
    """Потокобезпечний ring buffer для інцидентів."""

    def __init__(self, capacity: int = 200) -> None:
        self._items: deque[SecurityIncident] = deque(maxlen=capacity)
        self._lock = threading.Lock()
        self._capacity = capacity

    def add(
        self,
        *,
        kind: str,
        ip: str,
        method: str,
        path: str,
        detail: str,
        action: str,
        status_code: int,
        rule: str = "",
        retry_after: int = 0,
    ) -> SecurityIncident:
        incident = SecurityIncident(
            timestamp=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            kind=kind,
            ip=ip,
            method=method,
            path=path,
            detail=detail,
            action=action,
            status_code=status_code,
            rule=rule,
            retry_after=retry_after,
        )
        with self._lock:
            self._items.append(incident)
        return incident

    def recent(self, limit: int = 30) -> list[dict]:
        with self._lock:
            items = list(self._items)[-limit:]
        return [asdict(item) for item in reversed(items)]

    def counts(self) -> dict[str, int]:
        with self._lock:
            items = list(self._items)
        counts: dict[str, int] = {}
        for item in items:
            counts[item.kind] = counts.get(item.kind, 0) + 1
        return counts

    def total(self) -> int:
        with self._lock:
            return len(self._items)

    def clear(self) -> None:
        with self._lock:
            self._items.clear()

    @property
    def capacity(self) -> int:
        return self._capacity
