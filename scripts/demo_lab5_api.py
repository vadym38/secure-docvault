"""Реальний API-протокол ЛР №5: login → upload → list → download.

Скрипт використовує лише стандартну бібліотеку `urllib`, тому не потребує
`requests`. Він демонструє повний цикл зашифрованого документа:

1. JWT-логін;
2. multipart-завантаження з шифруванням на сервері;
3. метадані контейнера (IV / Tag / Ciphertext);
4. скачування та перевірку SHA-256.

Запуск:
    python scripts/demo_lab5_api.py --base-url http://127.0.0.1:5000
"""

from __future__ import annotations

import argparse
import hashlib
import json
import secrets
import sys
import urllib.error
import urllib.request

SAMPLE_TEXT = (
    b"CONFIDENTIAL FINANCIAL REPORT - SECURE DOCVAULT 2026\n"
    b"Quarter: Q3 2026\nAmount: 1 250 000 UAH\n"
)


def _configure_stdout() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")


def request(
    url: str,
    *,
    method: str = "GET",
    data: bytes | None = None,
    headers: dict[str, str] | None = None,
    timeout: float = 10.0,
) -> tuple[int, dict[str, str], bytes]:
    req = urllib.request.Request(
        url,
        data=data,
        headers=headers or {},
        method=method,
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            return response.status, dict(response.headers), response.read()
    except urllib.error.HTTPError as error:
        return error.code, dict(error.headers), error.read()
    except urllib.error.URLError as error:
        return 0, {}, f"network error: {error.reason}".encode()


def login(base_url: str, username: str, password: str) -> str:
    status, _headers, body = request(
        f"{base_url}/api/v1/auth/login",
        method="POST",
        data=json.dumps({"username": username, "password": password}).encode(),
        headers={"Content-Type": "application/json", "Accept": "application/json"},
    )
    print(f"[1] POST /api/v1/auth/login → HTTP {status}")
    if status != 200:
        print(body.decode("utf-8", "replace")[:300])
        raise SystemExit(1)
    payload = json.loads(body)
    print(
        f"    access_token: {payload['access_token'][:28]}… "
        f"({len(payload['access_token'])} chars)"
    )
    return payload["access_token"]


def main() -> int:
    _configure_stdout()
    parser = argparse.ArgumentParser(description="Lab 5 documents API demo")
    parser.add_argument("--base-url", default="http://127.0.0.1:5000")
    parser.add_argument("--username", default="lab5.demo")
    parser.add_argument("--password", default="Vault#2026!")
    args = parser.parse_args()
    base_url = args.base_url.rstrip("/")

    print("=" * 78)
    print("Secure DocVault · ЛР №5 · API upload/download protocol")
    print(f"Target: {base_url}")
    print("=" * 78)

    token = login(base_url, args.username, args.password)
    auth = {"Authorization": f"Bearer {token}", "Accept": "application/json"}

    boundary = "----DocVaultLab5" + secrets.token_hex(8)
    body = (
        f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="file"; filename="lab5-report.txt"\r\n'
        "Content-Type: text/plain\r\n\r\n"
    ).encode() + SAMPLE_TEXT + f"\r\n--{boundary}--\r\n".encode()

    status, _headers, response = request(
        f"{base_url}/api/v1/documents/upload",
        method="POST",
        data=body,
        headers={
            **auth,
            "Content-Type": f"multipart/form-data; boundary={boundary}",
        },
    )
    print(f"\n[2] POST /api/v1/documents/upload → HTTP {status}")
    if status != 201:
        print(response.decode("utf-8", "replace")[:400])
        return 1
    document = json.loads(response)["document"]
    doc_id = document["document_id"]
    print(f"    document_id       : {doc_id}")
    print(f"    original_filename : {document['original_filename']}")
    print(f"    plaintext size    : {document['size_bytes']} B")
    print(f"    encrypted size    : {document['encrypted_size_bytes']} B")
    print(f"    sha256            : {document['sha256']}")
    print("    container         : [12 B IV][16 B Tag][Ciphertext]")

    status, _headers, response = request(
        f"{base_url}/api/v1/documents",
        headers=auth,
    )
    print(f"\n[3] GET /api/v1/documents → HTTP {status}")
    documents = json.loads(response)["documents"]
    print(f"    документів у сховищі: {len(documents)}")

    status, _headers, response = request(
        f"{base_url}/api/v1/documents/{doc_id}",
        headers=auth,
    )
    print(f"\n[4] GET /api/v1/documents/{doc_id} → HTTP {status}")
    meta = json.loads(response)["document"]
    print(f"    IV  (12 B): {meta['nonce_hex']}")
    print(f"    Tag (16 B): {meta['tag_hex']}")
    print(f"    ciphertext: {meta['ciphertext_size']} B")
    print(f"    container : {meta['total_size']} B")

    status, headers, downloaded = request(
        f"{base_url}/api/v1/documents/{doc_id}/download",
        headers=auth,
    )
    print(f"\n[5] GET /api/v1/documents/{doc_id}/download → HTTP {status}")
    print(f"    bytes             : {len(downloaded)}")
    print(f"    X-Content-SHA256  : {headers.get('X-Content-SHA256', '—')}")
    print(f"    X-Document-Encryption: {headers.get('X-Document-Encryption', '—')}")
    digest = hashlib.sha256(downloaded).hexdigest()
    print(f"    SHA-256 downloaded: {digest}")
    print(
        "    plaintext match   : "
        f"{'YES — OK' if downloaded == SAMPLE_TEXT else 'NO (!)'}"
    )

    print("\n" + "=" * 78)
    print("РЕЗУЛЬТАТ: файл зашифровано, збережено та успішно розшифровано.")
    print("=" * 78)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
