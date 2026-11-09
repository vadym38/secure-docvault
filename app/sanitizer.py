"""Санітизація та контекстне екранування користувацького вводу (ЛР №3).

Модуль закриває два класи XSS-ризиків:

* **Stored XSS** — усе, що потрапляє до бази (описи, коментарі, імена
  файлів), проходить через Bleach і зберігається вже без HTML-тегів;
* **Reflected XSS** — шаблони Jinja2 працюють у режимі autoescape, а
  додатково є ``escape_text`` для явного екранування у не-HTML контекстах.

Bleach не є «срібною кулею»: він не знає контексту використання. Тому
модуль навмисно розділяє політики для вільного тексту та для імені файлу.
"""

from __future__ import annotations

import html
import re
import unicodedata
from dataclasses import dataclass, field

import bleach

# Керуючі символи, які не мають сенсу в тексті й можуть ламати логи/CSV.
CONTROL_CHARS_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

# Теги, вміст яких треба прибирати разом із тегом. Для решти тегів Bleach
# залишить лише текстовий вміст, що безпечно після autoescape.
DANGEROUS_BLOCK_RE = re.compile(
    r"(?is)<\s*(script|style|iframe|object|embed|svg|math|template)\b[^>]*>"
    r".*?<\s*/\s*\1\s*>"
)

TAG_RE = re.compile(r"(?is)<\s*/?\s*([a-z][a-z0-9:-]*)\b")
EVENT_HANDLER_RE = re.compile(r"(?i)\bon[a-z]+\s*=")
JS_PROTOCOL_RE = re.compile(r"(?i)javascript\s*:")
DATA_HTML_RE = re.compile(r"(?i)data\s*:\s*text/html")

FILENAME_ALLOWED_RE = re.compile(r"[^\w.\- ]", re.UNICODE)
SPACE_RE = re.compile(r"[ \t\f\v]+")
NEWLINE_RE = re.compile(r"\n{3,}")

# Зарезервовані імена Windows: їх не можна використовувати як ім'я файлу.
WINDOWS_RESERVED = {
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}

DEFAULT_MAX_TEXT = 2000
DEFAULT_MAX_FILENAME = 120


@dataclass(frozen=True)
class SanitizationReport:
    """Результат аналізу одного вводу для навчального протоколу."""

    original_length: int
    cleaned_length: int
    removed_tags: tuple[str, ...] = field(default_factory=tuple)
    removed_handlers: tuple[str, ...] = field(default_factory=tuple)
    blocked_protocols: tuple[str, ...] = field(default_factory=tuple)
    changed: bool = False

    @property
    def blocked_vectors(self) -> tuple[str, ...]:
        vectors: list[str] = []
        vectors.extend(f"<{tag}>" for tag in self.removed_tags)
        vectors.extend(self.removed_handlers)
        vectors.extend(self.blocked_protocols)
        return tuple(dict.fromkeys(vectors))

    @property
    def is_clean(self) -> bool:
        return not self.changed


def _normalize(text: str) -> str:
    """Нормалізує Unicode та прибирає керуючі символи."""

    normalized = unicodedata.normalize("NFC", text)
    return CONTROL_CHARS_RE.sub("", normalized)


def _plain_text(value: str) -> str:
    """Перетворює HTML-фрагмент у безпечний простий текст."""

    cleaned = bleach.clean(
        value,
        tags=[],
        attributes={},
        protocols=[],
        strip=True,
        strip_comments=True,
    )
    # bleach повертає HTML-сутності (&lt;). Для подальшого Jinja-autoescape
    # потрібен саме сирий текст, інакше на екрані з'явиться "&lt;".
    return html.unescape(cleaned)


def sanitize_text(
    text: str | None,
    *,
    max_length: int = DEFAULT_MAX_TEXT,
    strip_blocks: bool = False,
) -> str:
    """Повертає безпечний простий текст без HTML-тегів.

    ``strip_blocks=True`` додатково видаляє вміст небезпечних контейнерів
    (script/style/iframe/svg), що корисно для імен файлів і коротких полів.
    """

    if text is None:
        return ""
    if not isinstance(text, str):
        text = str(text)

    value = _normalize(text)
    if strip_blocks:
        value = DANGEROUS_BLOCK_RE.sub(" ", value)

    value = _plain_text(value)
    value = SPACE_RE.sub(" ", value)
    value = NEWLINE_RE.sub("\n\n", value)
    value = value.strip()

    if len(value) > max_length:
        value = value[: max_length - 1].rstrip() + "…"
    return value


def sanitize_comment(text: str | None, *, max_length: int = DEFAULT_MAX_TEXT) -> str:
    """Коментар користувача: зберігає переноси рядків, але не HTML."""

    return sanitize_text(text, max_length=max_length, strip_blocks=False)


def sanitize_description(text: str | None, *, max_length: int = DEFAULT_MAX_TEXT) -> str:
    """Опис документа — та сама політика, що й для коментаря."""

    return sanitize_comment(text, max_length=max_length)


def sanitize_filename(
    filename: str | None,
    *,
    max_length: int = DEFAULT_MAX_FILENAME,
) -> str:
    """Безпечне ім'я файлу без шляхів, тегів і керуючих символів."""

    value = sanitize_text(filename, max_length=max_length, strip_blocks=True)
    value = value.replace("\\", "/")
    value = value.rsplit("/", 1)[-1]
    value = FILENAME_ALLOWED_RE.sub("_", value)
    value = re.sub(r"_{2,}", "_", value)
    value = value.strip(" .")

    if not value or value in {".", ".."}:
        value = "document"

    stem = value.split(".", 1)[0].upper()
    if stem in WINDOWS_RESERVED:
        value = f"_{value}"

    return value[:max_length]


def escape_text(text: str | None) -> str:
    """Явне HTML-екранування для нешаблонних контекстів."""

    return html.escape(text or "", quote=True)


def inspect_sanitization(text: str | None) -> SanitizationReport:
    """Аналізує вхід і показує, які вектори було нейтралізовано."""

    if not text:
        return SanitizationReport(0, 0)

    raw = _normalize(str(text))
    tags = tuple(
        dict.fromkeys(
            match.group(1).lower()
            for match in TAG_RE.finditer(raw)
            if match.group(1).lower() not in {"b", "i", "u", "em", "strong", "p", "br"}
        )
    )
    handlers = tuple(
        dict.fromkeys(
            match.group(0).rstrip("=").strip().lower()
            for match in EVENT_HANDLER_RE.finditer(raw)
        )
    )
    protocols: list[str] = []
    if JS_PROTOCOL_RE.search(raw):
        protocols.append("javascript:")
    if DATA_HTML_RE.search(raw):
        protocols.append("data:text/html")

    cleaned = sanitize_comment(raw)
    return SanitizationReport(
        original_length=len(raw),
        cleaned_length=len(cleaned),
        removed_tags=tags,
        removed_handlers=handlers,
        blocked_protocols=tuple(protocols),
        changed=cleaned != raw.strip(),
    )
