"""Стрес-тест WAF / Rate Limiting для Secure DocVault (ЛР №4).

Скрипт використовує лише стандартну бібліотеку Python (`urllib`), тому
не потребує `requests`/`aiohttp`. Він:

1. надсилає серію POST-запитів на `/api/v1/auth/login` з хибним паролем;
2. фіксує перехід `401 → 429` і заголовок `Retry-After`;
3. надсилає Path Traversal payload і перевіряє `403` + Greylist.

Запуск:
    python scripts/stress_test_lab4.py
    python scripts/stress_test_lab4.py --base-url http://127.0.0.1:5000 --requests 10
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request


def _configure_stdout() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")


def request(
    url: str,
    *,
    method: str = "GET",
    payload: dict | None = None,
    timeout: float = 5.0,
) -> tuple[int, dict[str, str], str]:
    """Виконує HTTP-запит і повертає (status, headers, body)."""

    data = None
    headers = {"Accept": "application/json", "User-Agent": "DocVault-Lab4-Stress/1.0"}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"

    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            body = response.read().decode("utf-8", "replace")
            return response.status, dict(response.headers), body
    except urllib.error.HTTPError as error:
        body = error.read().decode("utf-8", "replace")
        return error.code, dict(error.headers), body
    except urllib.error.URLError as error:
        return 0, {}, f"network error: {error.reason}"


def _short(value: str, size: int = 100) -> str:
    value = " ".join(value.split())
    return value if len(value) <= size else value[: size - 1] + "…"


def _format_body(body: str, size: int = 110) -> str:
    """Показує змістовний error.code/message замість \\uXXXX-екранування."""

    try:
        data = json.loads(body)
    except (ValueError, TypeError):
        return _short(body, size)

    error = data.get("error") if isinstance(data, dict) else None
    if isinstance(error, dict):
        code = error.get("code", "error")
        message = error.get("message", "")
        rule = error.get("rule")
        suffix = f" [rule={rule}]" if rule else ""
        return _short(f"{code}: {message}{suffix}", size)
    return _short(body, size)


def main() -> int:
    _configure_stdout()

    parser = argparse.ArgumentParser(description="Lab 4 WAF / Rate Limiting stress test")
    parser.add_argument(
        "--base-url",
        default="http://127.0.0.1:5000",
        help="Base URL запущеного Secure DocVault",
    )
    parser.add_argument(
        "--requests",
        type=int,
        default=10,
        help="Кількість спроб входу (за замовчуванням 10)",
    )
    args = parser.parse_args()
    base_url = args.base_url.rstrip("/")

    print("=" * 78)
    print("Secure DocVault · ЛР №4 · WAF / Rate Limiting stress test")
    print(f"Target: {base_url}")
    print("=" * 78)

    login_url = f"{base_url}/api/v1/auth/login"
    statuses: list[int] = []
    limited = 0

    print(f"\n[1] Rate Limiter: {args.requests} POST-запитів на {login_url}")
    for index in range(1, args.requests + 1):
        status, headers, body = request(
            login_url,
            method="POST",
            payload={
                "username": "bruteforce-probe",
                "password": "wrong-password",
            },
        )
        retry_after = headers.get("Retry-After", "-")
        rule = headers.get("X-RateLimit-Rule", "-")
        statuses.append(status)
        if status == 429:
            limited += 1
        print(
            f"  #{index:02d} | HTTP {status} | "
            f"Retry-After: {retry_after} | rule: {rule} | "
            f"{_format_body(body)}"
        )

    print("\n[2] WAF: Path Traversal")
    traversal_url = f"{base_url}/api/v1/user/profile?file=../../etc/passwd"
    status, headers, body = request(traversal_url)
    print(
        f"  GET {traversal_url}\n"
        f"  HTTP {status} | X-WAF-Rule: {headers.get('X-WAF-Rule', '-')} | "
        f"Retry-After: {headers.get('Retry-After', '-')}\n"
        f"  {_format_body(body, 160)}"
    )

    print("\n[3] Greylist: повторний запит до /api/v1/health")
    health_url = f"{base_url}/api/v1/health"
    health_status, health_headers, health_body = request(health_url)
    print(
        f"  HTTP {health_status} | X-WAF-Action: "
        f"{health_headers.get('X-WAF-Action', '-')} | "
        f"Retry-After: {health_headers.get('Retry-After', '-')}\n"
        f"  {_format_body(health_body, 160)}"
    )

    print("\n" + "=" * 78)
    print("Підсумок")
    print(f"  Усього запитів входу: {len(statuses)}")
    print(f"  401 Unauthorized:     {statuses.count(401)}")
    print(f"  429 Too Many Requests:{statuses.count(429)}")
    print(f"  Path Traversal:       HTTP {status}")
    print(f"  Greylist follow-up:   HTTP {health_status}")

    expected = 401 in statuses and 429 in statuses and status == 403 and health_status == 403
    if expected:
        print("  РЕЗУЛЬТАТ: OK — Rate Limiter, WAF і Greylist спрацювали.")
    else:
        print("  РЕЗУЛЬТАТ: перевірте конфігурацію WAF/лімітів або запущений сервер.")
    print("=" * 78)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
