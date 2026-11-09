"""Ковзне вікно (Sliding Window Log) для обмеження частоти запитів (ЛР №4).

Ключові рішення:

* **Sliding Window Log**, а не Fixed Window: вікно не «скидається» на межі
  хвилини, тому немає сплеску 2×limit на стику двох вікон.
* **deque на кожен ключ** зберігає лише мітки часу в межах вікна. Для ліміту
  60/хв це максимум 60 чисел на IP — пам'ять обмежена зверху.
* **Періодичне прибирання** порожніх і застарілих ключів захищає від
  Memory Exhaustion DoS, коли клієнт надсилає запити з багатьох IP.
* **Потокобезпечність**: один `threading.Lock` на весь стан; Flask dev-сервер
  і WSGI-сервери можуть обробляти запити паралельно.
* Стан живе в `app.extensions`, а не в глобальній змінній, тому тести та
  окремі екземпляри застосунку не впливають один на одного.
"""

from __future__ import annotations

import math
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass


@dataclass(frozen=True)
class RateDecision:
    """Результат перевірки одного запиту."""

    allowed: bool
    limit: int
    window_seconds: int
    remaining: int
    retry_after: int
    rule: str
    key: str


@dataclass(frozen=True)
class RateLimitRule:
    """Правило для конкретної групи маршрутів."""

    name: str
    title: str
    limit: int
    window_seconds: int
    scope: str


class SlidingWindowRateLimiter:
    """Потокобезпечний лічильник ковзного вікна."""

    def __init__(
        self,
        *,
        max_keys: int = 10_000,
        key_ttl_seconds: int = 600,
    ) -> None:
        self._events: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()
        self._max_keys = max_keys
        self._key_ttl_seconds = key_ttl_seconds
        self._last_prune = 0.0
        self._total_allowed = 0
        self._total_limited = 0

    def check(
        self,
        client_ip: str,
        rule: RateLimitRule,
        *,
        now: float | None = None,
    ) -> RateDecision:
        """Перевіряє ліміт і, якщо можна, додає поточний запит у вікно."""

        current = time.monotonic() if now is None else now
        key = f"{client_ip}:{rule.name}"

        with self._lock:
            self._maybe_prune_locked(current)

            bucket = self._events[key]
            cutoff = current - rule.window_seconds
            while bucket and bucket[0] <= cutoff:
                bucket.popleft()

            if len(bucket) >= rule.limit:
                # Найстаріший запит визначить, коли звільниться місце.
                oldest = bucket[0]
                retry_after = max(
                    1,
                    math.ceil(rule.window_seconds - (current - oldest)),
                )
                self._total_limited += 1
                return RateDecision(
                    allowed=False,
                    limit=rule.limit,
                    window_seconds=rule.window_seconds,
                    remaining=0,
                    retry_after=retry_after,
                    rule=rule.name,
                    key=key,
                )

            bucket.append(current)
            if len(self._events) > self._max_keys:
                self._hard_cap_locked()
            self._total_allowed += 1
            return RateDecision(
                allowed=True,
                limit=rule.limit,
                window_seconds=rule.window_seconds,
                remaining=max(0, rule.limit - len(bucket)),
                retry_after=0,
                rule=rule.name,
                key=key,
            )

    def _maybe_prune_locked(self, now: float) -> None:
        """Прибирає застарілі ключі, щоб словник не ріс безмежно."""

        if (
            len(self._events) <= self._max_keys
            and now - self._last_prune < 30
        ):
            return

        stale_before = now - self._key_ttl_seconds
        doomed = [
            key
            for key, bucket in self._events.items()
            if not bucket or bucket[-1] <= stale_before
        ]
        for key in doomed:
            del self._events[key]

        # Жорсткий запобіжник: якщо ключів усе одно забагато, видаляємо
        # найстаріші за останньою міткою часу.
        self._hard_cap_locked()

        self._last_prune = now

    def _hard_cap_locked(self) -> None:
        """Тримає словник ключів у межах `max_keys`."""

        if len(self._events) <= self._max_keys:
            return
        ordered = sorted(
            self._events.items(),
            key=lambda item: item[1][-1] if item[1] else 0.0,
        )
        for key, _bucket in ordered[: len(self._events) - self._max_keys]:
            del self._events[key]

    def reset(self) -> None:
        """Повністю очищає стан (лабораторна кнопка Reset)."""

        with self._lock:
            self._events.clear()
            self._last_prune = 0.0
            self._total_allowed = 0
            self._total_limited = 0

    def stats(self) -> dict:
        """Службова статистика для сторінки /waf-lab."""

        with self._lock:
            active = sum(1 for bucket in self._events.values() if bucket)
            events = sum(len(bucket) for bucket in self._events.values())
            return {
                "tracked_keys": len(self._events),
                "active_keys": active,
                "events_in_window": events,
                "total_allowed": self._total_allowed,
                "total_limited": self._total_limited,
                "max_keys": self._max_keys,
            }


# Стандартні правила ЛР №4. Значення можна перевизначити через Config.
DEFAULT_RULES: tuple[RateLimitRule, ...] = (
    RateLimitRule(
        name="auth_login",
        title="Вхід / автентифікація",
        limit=5,
        window_seconds=60,
        scope="POST /api/v1/auth/login, POST /login",
    ),
    RateLimitRule(
        name="api_general",
        title="Загальні API-маршрути",
        limit=60,
        window_seconds=60,
        scope="/api/v1/*",
    ),
    RateLimitRule(
        name="web_general",
        title="HTML-сторінки порталу",
        limit=120,
        window_seconds=60,
        scope="решта маршрутів",
    ),
)
