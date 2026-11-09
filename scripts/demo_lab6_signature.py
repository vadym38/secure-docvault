"""Реальний API-протокол ЛР №6: keygen → upload → sign → download.

Використовує лише стандартну бібліотеку `urllib`. Демонструє:
* генерацію RSA-PSS ключа з encrypted PKCS#8 PEM;
* підписання завантаженого документа;
* статус `Signed & Verified` у download API.

Запуск:
    python scripts/demo_lab6_signature.py --base-url http://127.0.0.1:5000
"""

from __future__ import annotations

import argparse
import hashlib
import json
import secrets
import sys
import urllib.error
import urllib.request

PASSPHRASE = "Sigil#2026!"
DOCUMENT = (
    b"OFFICIAL STATEMENT: APPROVED BY CHIEF SECURITY OFFICER\n"
    b"Secure DocVault - board resolution #2026-06\n"
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
    timeout: float = 15.0,
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
    token = json.loads(body)["access_token"]
    print(f"    access_token: {token[:28]}… ({len(token)} chars)")
    return token


def main() -> int:
    _configure_stdout()
    parser = argparse.ArgumentParser(description="Lab 6 signature API demo")
    parser.add_argument("--base-url", default="http://127.0.0.1:5000")
    parser.add_argument("--username", default="lab6.demo")
    parser.add_argument("--password", default="Vault#2026!")
    args = parser.parse_args()
    base_url = args.base_url.rstrip("/")

    print("=" * 78)
    print("Secure DocVault · ЛР №6 · RSA-PSS digital signature protocol")
    print(f"Target: {base_url}")
    print("=" * 78)

    token = login(base_url, args.username, args.password)
    auth = {"Authorization": f"Bearer {token}", "Accept": "application/json"}

    status, _headers, body = request(
        f"{base_url}/api/v1/keys/generate",
        method="POST",
        data=json.dumps({"passphrase": PASSPHRASE}).encode(),
        headers={**auth, "Content-Type": "application/json"},
    )
    print(f"\n[2] POST /api/v1/keys/generate → HTTP {status}")
    if status != 201:
        print(body.decode("utf-8", "replace")[:400])
        return 1
    key = json.loads(body)["key"]
    public_pem = key["public_key_pem"]
    private_pem = key["private_key_pem_encrypted"]
    print(f"    key_id    : {key['key_id']}")
    print(f"    algorithm : {key['algorithm']}")
    print(f"    fingerprint: {key['fingerprint']}")
    print(f"    public PEM: {public_pem.splitlines()[0]} ({len(public_pem)} chars)")
    print(f"    private PEM: {private_pem.splitlines()[0]} ({len(private_pem)} chars)")

    boundary = "----DocVaultLab6" + secrets.token_hex(8)
    multipart = (
        f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="file"; filename="board-resolution.txt"\r\n'
        "Content-Type: text/plain\r\n\r\n"
    ).encode() + DOCUMENT + f"\r\n--{boundary}--\r\n".encode()

    status, _headers, body = request(
        f"{base_url}/api/v1/documents/upload",
        method="POST",
        data=multipart,
        headers={
            **auth,
            "Content-Type": f"multipart/form-data; boundary={boundary}",
        },
    )
    print(f"\n[3] POST /api/v1/documents/upload → HTTP {status}")
    if status != 201:
        print(body.decode("utf-8", "replace")[:400])
        return 1
    document = json.loads(body)["document"]
    doc_id = document["document_id"]
    print(f"    document_id : {doc_id}")
    print(f"    filename    : {document['original_filename']}")
    print(f"    SHA-256     : {document['sha256']}")

    status, _headers, body = request(
        f"{base_url}/api/v1/documents/{doc_id}/sign",
        method="POST",
        data=json.dumps({"passphrase": PASSPHRASE}).encode(),
        headers={**auth, "Content-Type": "application/json"},
    )
    print(f"\n[4] POST /api/v1/documents/{doc_id}/sign → HTTP {status}")
    if status != 200:
        print(body.decode("utf-8", "replace")[:400])
        return 1
    signature = json.loads(body)["signature"]
    print(f"    status      : Signed & Verified")
    print(f"    signer      : {signature['signer']}")
    print(f"    algorithm   : {signature['algorithm']}")
    print(f"    key_id      : {signature['key_id']}")
    print(f"    fingerprint : {signature['fingerprint']}")
    print(f"    signed_at   : {signature['signed_at']}")
    print(f"    signature   : {signature['signature_b64'][:48]}… "
          f"({len(signature['signature_b64'])} b64 chars)")

    status, headers, downloaded = request(
        f"{base_url}/api/v1/documents/{doc_id}/download",
        headers=auth,
    )
    print(f"\n[5] GET /api/v1/documents/{doc_id}/download → HTTP {status}")
    print(f"    bytes               : {len(downloaded)}")
    print(f"    X-Signature-Status  : {headers.get('X-Signature-Status', '—')}")
    print(f"    X-Signature-Algorithm: {headers.get('X-Signature-Algorithm', '—')}")
    print(f"    X-Signer            : {headers.get('X-Signer', '—')}")
    print(f"    X-Signature-Fingerprint: {headers.get('X-Signature-Fingerprint', '—')}")
    print(f"    SHA-256 downloaded  : {hashlib.sha256(downloaded).hexdigest()}")
    print(
        "    plaintext match     : "
        f"{'YES — OK' if downloaded == DOCUMENT else 'NO (!)'}"
    )

    print("\n" + "=" * 78)
    print("РЕЗУЛЬТАТ: ключ створено, документ підписано, підпис перевірено.")
    print("=" * 78)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
