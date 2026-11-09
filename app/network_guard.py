"""Вхідний middleware WAF + Rate Limiting (ЛР №4).

Порядок обробки запиту:

1. Визначення IP (з урахуванням trusted proxy, якщо увімкнено).
2. Greylist: чи IP уже заблоковано після сигнатури атаки.
3. WAF: path → query → body на набір сигнатур.
4. Rate Limiter: окремі правила для login / API / HTML.
5. Передача запиту у Flask-маршрут.

Middleware реєструється як `before_request`, тому працює перед усіма
маршрутами, включно з API та сторінками помилок.
"""

from __future__ import annotations

from flask import Flask, Response, jsonify, render_template, request

from .rate_limiter import RateLimitRule, SlidingWindowRateLimiter
from .security_events import IncidentLog
from .waf_filter import Greylist, inspect_request


# Лабораторні сторінки, які навмисно приймають XSS/SQLi-payload для
# демонстрації інших механізмів захисту. Їх не можна блокувати WAF, інакше
# Лабораторні роботи №1 і №3 втратять сенс. Санітизація та параметризовані
# запити на цих сторінках залишаються другими рівнями захисту.
WAF_EXEMPT_PREFIXES: tuple[str, ...] = (
    "/static/",
    "/favicon.ico",
    "/client-lab",
    "/security-lab",
    "/waf-lab",
)

# Консоль WAF залишаємо доступною навіть після Greylist, щоб можна було
# переглянути журнал і зробити лабораторний Reset. Це усвідомлене рішення
# для навчального стенда; у production таку консоль не публікують.
GREYLIST_EXEMPT_PREFIXES: tuple[str, ...] = (
    "/static/",
    "/favicon.ico",
    "/waf-lab",
)

RATE_LIMIT_EXEMPT_PREFIXES: tuple[str, ...] = (
    "/static/",
    "/favicon.ico",
    "/waf-lab",
)


class NetworkGuard:
    """Спільний стан WAF, Rate Limiter, Greylist і журналу інцидентів."""

    def __init__(self, app: Flask) -> None:
        self.app = app
        self.limiter = SlidingWindowRateLimiter(
            max_keys=int(app.config.get("RATE_LIMIT_MAX_KEYS", 10_000)),
            key_ttl_seconds=int(app.config.get("RATE_LIMIT_KEY_TTL_SECONDS", 600)),
        )
        self.greylist = Greylist()
        self.incidents = IncidentLog(
            capacity=int(app.config.get("SECURITY_LOG_CAPACITY", 200))
        )
        self.rules: dict[str, RateLimitRule] = {
            "auth_login": RateLimitRule(
                name="auth_login",
                title="Вхід / автентифікація",
                limit=int(app.config.get("RATE_LIMIT_LOGIN_LIMIT", 5)),
                window_seconds=int(app.config.get("RATE_LIMIT_LOGIN_WINDOW", 60)),
                scope="POST /api/v1/auth/login, POST /login",
            ),
            "api_general": RateLimitRule(
                name="api_general",
                title="Загальні API-маршрути",
                limit=int(app.config.get("RATE_LIMIT_API_LIMIT", 60)),
                window_seconds=int(app.config.get("RATE_LIMIT_API_WINDOW", 60)),
                scope="/api/v1/*",
            ),
            "web_general": RateLimitRule(
                name="web_general",
                title="HTML-сторінки порталу",
                limit=int(app.config.get("RATE_LIMIT_WEB_LIMIT", 120)),
                window_seconds=int(app.config.get("RATE_LIMIT_WEB_WINDOW", 60)),
                scope="решта маршрутів",
            ),
        }

    # ------------------------------------------------------------------
    # Налаштування та стан
    # ------------------------------------------------------------------

    @property
    def waf_enabled(self) -> bool:
        return bool(self.app.config.get("WAF_ENABLED", True))

    @property
    def rate_limit_enabled(self) -> bool:
        return bool(self.app.config.get("RATE_LIMIT_ENABLED", True))

    @property
    def greylist_seconds(self) -> int:
        return int(self.app.config.get("WAF_GREYLIST_SECONDS", 300))

    def reset(self) -> None:
        """Скидає лічильники, Greylist і журнал (лабораторний Reset)."""

        self.limiter.reset()
        self.greylist.clear()
        self.incidents.clear()

    def stats(self) -> dict:
        return {
            "rate_limiter": self.limiter.stats(),
            "incidents": self.incidents.counts(),
            "incidents_total": self.incidents.total(),
            "greylist": self.greylist.active(),
            "greylist_seconds": self.greylist_seconds,
            "waf_enabled": self.waf_enabled,
            "rate_limit_enabled": self.rate_limit_enabled,
        }

    def rule_table(self) -> list[dict]:
        return [
            {
                "name": rule.name,
                "title": rule.title,
                "limit": rule.limit,
                "window_seconds": rule.window_seconds,
                "scope": rule.scope,
            }
            for rule in self.rules.values()
        ]

    # ------------------------------------------------------------------
    # IP та класифікація
    # ------------------------------------------------------------------

    def client_ip(self) -> str:
        if self.app.config.get("TRUST_PROXY_HEADERS", False):
            forwarded = request.headers.get("X-Forwarded-For", "")
            if forwarded:
                return forwarded.split(",", 1)[0].strip()
        return request.remote_addr or "unknown"

    def _is_waf_exempt(self, path: str) -> bool:
        if request.endpoint == "static":
            return True
        return any(path.startswith(prefix) for prefix in WAF_EXEMPT_PREFIXES)

    def _is_greylist_exempt(self, path: str) -> bool:
        if request.endpoint == "static":
            return True
        return any(path.startswith(prefix) for prefix in GREYLIST_EXEMPT_PREFIXES)

    def _is_rate_limit_exempt(self, path: str) -> bool:
        if request.endpoint == "static":
            return True
        return any(
            path.startswith(prefix) for prefix in RATE_LIMIT_EXEMPT_PREFIXES
        )

    def _pick_rule(self, path: str, method: str) -> RateLimitRule:
        if method == "POST" and path in ("/api/v1/auth/login", "/login"):
            return self.rules["auth_login"]
        if path.startswith("/api/"):
            return self.rules["api_general"]
        return self.rules["web_general"]

    # ------------------------------------------------------------------
    # Основна обробка
    # ------------------------------------------------------------------

    def before_request(self) -> Response | None:
        if not self.waf_enabled and not self.rate_limit_enabled:
            return None

        path = request.path
        method = request.method
        ip = self.client_ip()

        # 1. Greylist — перевіряємо до WAF і лімітів.
        if self.waf_enabled and not self._is_greylist_exempt(path):
            blocked, remaining = self.greylist.is_blocked(ip)
            if blocked:
                self._log(
                    kind="greylist",
                    ip=ip,
                    method=method,
                    path=path,
                    detail=f"IP уже в Greylist, залишилось {remaining} с",
                    action="HTTP 403 (Greylist)",
                    status_code=403,
                    rule="greylist",
                    retry_after=remaining,
                )
                return self._blocked_response(
                    status_code=403,
                    code="ip_greylisted",
                    title="IP у Greylist",
                    message=(
                        "Цю IP-адресу тимчасово заблоковано після сигнатури "
                        "атаки. Дочекайтеся завершення інтервалу або "
                        "скористайтеся лабораторним Reset."
                    ),
                    rule="greylist",
                    retry_after=remaining,
                    waf_action="greylist",
                )

        # 2. WAF — path, query, body.
        if self.waf_enabled and not self._is_waf_exempt(path):
            body_text = self._read_body_for_inspection()
            verdict = inspect_request(
                path=path,
                query_string=request.query_string.decode("utf-8", "replace"),
                body_text=body_text,
            )

            if verdict.blocked:
                entry = self.greylist.block(
                    ip,
                    seconds=self.greylist_seconds,
                    reason=verdict.title,
                    rule_id=verdict.rule_id,
                )
                self._log(
                    kind="waf_block",
                    ip=ip,
                    method=method,
                    path=path,
                    detail=(
                        f"{verdict.title} ({verdict.rule_id}); "
                        f"location={verdict.location}; "
                        f"snippet={verdict.snippet!r}"
                    ),
                    action=(
                        f"HTTP 403 + Greylist {entry.duration_seconds} с"
                    ),
                    status_code=403,
                    rule=verdict.rule_id,
                )
                return self._blocked_response(
                    status_code=403,
                    code="waf_blocked",
                    title="WAF заблокував запит",
                    message=(
                        f"Виявлено сигнатуру: {verdict.title} "
                        f"({verdict.rule_id}). IP додано до Greylist на "
                        f"{entry.duration_seconds} с."
                    ),
                    rule=verdict.rule_id,
                    retry_after=entry.duration_seconds,
                    waf_action="blocked",
                    extra={
                        "location": verdict.location,
                        "snippet": verdict.snippet,
                    },
                )

        # 3. Rate Limiter.
        if self.rate_limit_enabled and not self._is_rate_limit_exempt(path):
            rule = self._pick_rule(path, method)
            decision = self.limiter.check(ip, rule)

            if not decision.allowed:
                self._log(
                    kind="rate_limit",
                    ip=ip,
                    method=method,
                    path=path,
                    detail=(
                        f"{rule.title}: {rule.limit} запитів за "
                        f"{rule.window_seconds} с"
                    ),
                    action=(
                        f"HTTP 429, Retry-After {decision.retry_after} с"
                    ),
                    status_code=429,
                    rule=rule.name,
                    retry_after=decision.retry_after,
                )
                return self._rate_limited_response(decision, rule)

            # Успішна відповідь отримає інформативні заголовки.
            request.environ["docvault.rate_decision"] = decision

        return None

    # ------------------------------------------------------------------
    # Відповіді
    # ------------------------------------------------------------------

    def _rate_limited_response(self, decision, rule: RateLimitRule) -> Response:
        response = self._blocked_response(
            status_code=429,
            code="rate_limited",
            title="Забагато запитів",
            message=(
                f"Перевищено ліміт {rule.limit} запитів за "
                f"{rule.window_seconds} с. Спробуйте через "
                f"{decision.retry_after} с."
            ),
            rule=rule.name,
            retry_after=decision.retry_after,
            waf_action="rate_limited",
        )
        response.headers["Retry-After"] = str(decision.retry_after)
        response.headers["X-RateLimit-Limit"] = str(rule.limit)
        response.headers["X-RateLimit-Remaining"] = "0"
        response.headers["X-RateLimit-Window"] = str(rule.window_seconds)
        response.headers["X-RateLimit-Rule"] = rule.name
        return response

    def _blocked_response(
        self,
        *,
        status_code: int,
        code: str,
        title: str,
        message: str,
        rule: str,
        retry_after: int = 0,
        waf_action: str = "blocked",
        extra: dict | None = None,
    ) -> Response:
        base_headers = {
            "Retry-After": str(retry_after) if retry_after else "",
            "X-WAF-Action": waf_action,
            "X-WAF-Rule": rule,
        }
        base_headers = {key: value for key, value in base_headers.items() if value}

        if request.path.startswith("/api/"):
            payload: dict = {
                "error": {
                    "code": code,
                    "message": message,
                    "rule": rule,
                }
            }
            if retry_after:
                payload["error"]["retry_after"] = retry_after
            if extra:
                payload["error"].update(extra)
            response = jsonify(payload)
            response.status_code = status_code
            for key, value in base_headers.items():
                response.headers[key] = value
            return response

        response = render_template(
            "network_block.html",
            code=status_code,
            title=title,
            message=message,
            rule=rule,
            retry_after=retry_after,
            xss=(extra or {}).get("snippet", ""),
        )
        flask_response = self.app.make_response(response)
        flask_response.status_code = status_code
        for key, value in base_headers.items():
            flask_response.headers[key] = value
        return flask_response

    # ------------------------------------------------------------------
    # Допоміжні
    # ------------------------------------------------------------------

    def _read_body_for_inspection(self) -> str:
        """Читає тіло з кешуванням, не ламаючи подальший розбір форми/JSON."""

        if request.method not in ("POST", "PUT", "PATCH", "DELETE"):
            return ""
        if request.mimetype and request.mimetype.startswith("multipart/"):
            # Файли в Lab 5 інспектуватимуться окремо; сирі multipart-байти
            # містять бінарні дані й дають багато хибних спрацювань.
            return ""

        max_bytes = int(self.app.config.get("WAF_MAX_BODY_INSPECT", 65_536))
        try:
            raw = request.get_data(cache=True)
        except Exception:  # pragma: no cover - захист від екзотичних WSGI-серверів
            return ""
        if not raw:
            return ""
        return raw[:max_bytes].decode("utf-8", "replace")

    def _log(
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
    ) -> None:
        self.incidents.add(
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
        self.app.logger.warning(
            "[%s] ip=%s %s %s | rule=%s | %s | %s",
            kind.upper(),
            ip,
            method,
            path,
            rule or "—",
            detail,
            action,
        )


def install_network_middleware(app: Flask) -> NetworkGuard:
    """Створює NetworkGuard та реєструє before_request."""

    guard = NetworkGuard(app)
    app.extensions["network_guard"] = guard
    app.before_request(guard.before_request)

    @app.after_request
    def add_rate_limit_headers(response):
        decision = request.environ.get("docvault.rate_decision")
        if decision is not None:
            response.headers.setdefault("X-RateLimit-Limit", str(decision.limit))
            response.headers.setdefault(
                "X-RateLimit-Remaining", str(decision.remaining)
            )
            response.headers.setdefault(
                "X-RateLimit-Window", str(decision.window_seconds)
            )
            response.headers.setdefault("X-RateLimit-Rule", decision.rule)
        return response

    return guard
