"""Сигнатурний мікро-WAF та Greylist для ЛР №4.

Модуль не претендує на заміну ModSecurity/CRS: це навчальний, але
реалістичний сигнатурний фільтр. Він інспектує **шлях**, **query string**
і **тіло** запиту після одноразового URL-декодування, тому обходить
найпростіші спроби приховати payload через `%2e%2e%2f` або `%27`.

Ключові обмеження сигнатурного підходу (див. README):
* він ловить відомі шаблони, але не нові/обфусковані атаки;
* можливі False Positives на легітимному тексті;
* тому WAF — додатковий шар, а не заміна параметризованих запитів,
  Jinja2-autoescape та санітизації.
"""

from __future__ import annotations

import re
import threading
import time
import unicodedata
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import unquote_plus


@dataclass(frozen=True)
class AttackSignature:
    """Одна сигнатура атаки."""

    rule_id: str
    title: str
    severity: str
    pattern: re.Pattern[str]
    example: str


@dataclass(frozen=True)
class WafVerdict:
    """Результат інспекції запиту."""

    blocked: bool
    rule_id: str = ""
    title: str = ""
    severity: str = ""
    location: str = ""
    snippet: str = ""


# Порядок важливий: спочатку більш специфічні правила, потім загальні.
WAF_SIGNATURES: tuple[AttackSignature, ...] = (
    AttackSignature(
        rule_id="waf-1001",
        title="Path Traversal",
        severity="critical",
        pattern=re.compile(r"\.\.[\\/]"),
        example="../../etc/passwd",
    ),
    AttackSignature(
        rule_id="waf-1002",
        title="SQL Injection: UNION SELECT",
        severity="critical",
        pattern=re.compile(r"\bunion\s+(?:all\s+)?select\b", re.IGNORECASE),
        example="' UNION SELECT password FROM users--",
    ),
    AttackSignature(
        rule_id="waf-1003",
        title="SQL Injection: tautology",
        severity="high",
        pattern=re.compile(
            r"\b(?:or|and)\b\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+['\"]?",
            re.IGNORECASE,
        ),
        example="' OR '1'='1",
    ),
    AttackSignature(
        rule_id="waf-1004",
        title="SQL Injection: destructive statement",
        severity="critical",
        pattern=re.compile(
            r"\b(?:drop\s+table|insert\s+into|delete\s+from|truncate\s+table)\b",
            re.IGNORECASE,
        ),
        example="'; DROP TABLE users; --",
    ),
    AttackSignature(
        rule_id="waf-1005",
        title="SQL Injection: xp_cmdshell / exec xp_",
        severity="critical",
        pattern=re.compile(r"\b(?:exec\s+xp_|xp_cmdshell\b)", re.IGNORECASE),
        example="EXEC xp_cmdshell 'whoami'",
    ),
    AttackSignature(
        rule_id="waf-2001",
        title="Command Injection: shell separator",
        severity="critical",
        pattern=re.compile(
            r"(?:;|\||&&|\$\(|`)\s*(?:/bin/)?(?:sh|bash|cmd|powershell)\b",
            re.IGNORECASE,
        ),
        example="; /bin/sh -c id",
    ),
    AttackSignature(
        rule_id="waf-2002",
        title="Command Injection: cmd.exe",
        severity="critical",
        pattern=re.compile(r"\bcmd\.exe\b", re.IGNORECASE),
        example="&& cmd.exe /c whoami",
    ),
    AttackSignature(
        rule_id="waf-2003",
        title="Command Injection: system()/exec()",
        severity="high",
        pattern=re.compile(r"\b(?:os\.)?system\(|\bexec\("),
        example="system('id')",
    ),
    AttackSignature(
        rule_id="waf-2004",
        title="Command Injection: cmd parameter",
        severity="high",
        pattern=re.compile(r"(?:^|[?&;])\s*cmd\s*=", re.IGNORECASE),
        example="?cmd=whoami",
    ),
    AttackSignature(
        rule_id="waf-3001",
        title="XSS: script tag",
        severity="high",
        pattern=re.compile(r"<\s*script\b", re.IGNORECASE),
        example="<script>alert(1)</script>",
    ),
    AttackSignature(
        rule_id="waf-3002",
        title="XSS: javascript: URI",
        severity="high",
        pattern=re.compile(r"javascript\s*:", re.IGNORECASE),
        example="javascript:alert(document.cookie)",
    ),
    AttackSignature(
        rule_id="waf-3003",
        title="XSS: inline event handler",
        severity="high",
        pattern=re.compile(
            r"\bon(?:error|load|click|mouseover|focus)\s*=",
            re.IGNORECASE,
        ),
        example='<img src=x onerror=alert(1)>',
    ),
    AttackSignature(
        rule_id="waf-3004",
        title="XSS: dangerous container",
        severity="medium",
        pattern=re.compile(r"<\s*(?:svg|iframe|object|embed)\b", re.IGNORECASE),
        example="<svg onload=alert(1)>",
    ),
)

# Обмежуємо розмір фрагмента, який потрапляє в журнал.
MAX_SNIPPET = 120


def _decode(value: str) -> str:
    """Подвійне URL-декодування + NFKC-нормалізація."""

    first = unquote_plus(value)
    second = unquote_plus(first)
    return unicodedata.normalize("NFKC", second)


def _snippet(value: str, match: re.Match[str]) -> str:
    start = max(0, match.start() - 20)
    end = min(len(value), match.end() + 40)
    return value[start:end].replace("\n", " ")[:MAX_SNIPPET]


def inspect_payload(text: str | None) -> WafVerdict:
    """Перевіряє один текстовий фрагмент на всі сигнатури."""

    if not text:
        return WafVerdict(blocked=False)

    decoded = _decode(str(text))
    if not decoded:
        return WafVerdict(blocked=False)

    for signature in WAF_SIGNATURES:
        match = signature.pattern.search(decoded)
        if match:
            return WafVerdict(
                blocked=True,
                rule_id=signature.rule_id,
                title=signature.title,
                severity=signature.severity,
                snippet=_snippet(decoded, match),
            )

    return WafVerdict(blocked=False)


def inspect_request(
    path: str,
    query_string: str = "",
    body_text: str = "",
) -> WafVerdict:
    """Послідовно інспектує path → query → body."""

    for location, value in (
        ("path", path),
        ("query", query_string),
        ("body", body_text),
    ):
        verdict = inspect_payload(value)
        if verdict.blocked:
            return WafVerdict(
                blocked=True,
                rule_id=verdict.rule_id,
                title=verdict.title,
                severity=verdict.severity,
                location=location,
                snippet=verdict.snippet,
            )
    return WafVerdict(blocked=False)


def signature_table() -> tuple[dict[str, str], ...]:
    """Дані для таблиці сигнатур на сторінці /waf-lab."""

    return tuple(
        {
            "rule_id": signature.rule_id,
            "title": signature.title,
            "severity": signature.severity,
            "pattern": signature.pattern.pattern,
            "example": signature.example,
        }
        for signature in WAF_SIGNATURES
    )


@dataclass
class GreylistEntry:
    """Один запис Greylist."""

    ip: str
    blocked_at: str
    expires_at: float
    duration_seconds: int
    reason: str
    rule_id: str = ""


class Greylist:
    """Тимчасовий список заблокованих IP (Greylist)."""

    def __init__(self) -> None:
        self._entries: dict[str, GreylistEntry] = {}
        self._lock = threading.Lock()

    def block(
        self,
        ip: str,
        *,
        seconds: int,
        reason: str,
        rule_id: str = "",
    ) -> GreylistEntry:
        now = time.monotonic()
        entry = GreylistEntry(
            ip=ip,
            blocked_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            expires_at=now + seconds,
            duration_seconds=seconds,
            reason=reason,
            rule_id=rule_id,
        )
        with self._lock:
            self._entries[ip] = entry
        return entry

    def remaining(self, ip: str, *, now: float | None = None) -> int:
        current = time.monotonic() if now is None else now
        with self._lock:
            entry = self._entries.get(ip)
            if entry is None:
                return 0
            left = int(entry.expires_at - current)
            if left <= 0:
                del self._entries[ip]
                return 0
            return max(1, left)

    def is_blocked(self, ip: str) -> tuple[bool, int]:
        remaining = self.remaining(ip)
        return (remaining > 0, remaining)

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()

    def active(self) -> list[dict]:
        now = time.monotonic()
        with self._lock:
            expired = [
                ip for ip, entry in self._entries.items() if entry.expires_at <= now
            ]
            for ip in expired:
                del self._entries[ip]

            return [
                {
                    "ip": entry.ip,
                    "blocked_at": entry.blocked_at,
                    "duration_seconds": entry.duration_seconds,
                    "remaining_seconds": max(1, int(entry.expires_at - now)),
                    "reason": entry.reason,
                    "rule_id": entry.rule_id,
                }
                for entry in sorted(
                    self._entries.values(),
                    key=lambda item: item.expires_at,
                )
            ]
