"""HTML-знімок таблиці document_signatures (ЛР №6).

Запуск:
    python scripts/signature_db_snapshot.py --db instance/docvault.db
"""

from __future__ import annotations

import argparse
import html
import sqlite3
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUTPUT = ROOT / "docs" / "signature_db_snapshot.html"

SQL = """
SELECT s.document_id,
       d.original_filename,
       u.username AS signer,
       s.key_id,
       s.algorithm,
       s.document_sha256,
       s.signature_b64,
       s.signed_at,
       s.verified_at,
       s.status,
       k.fingerprint AS key_fingerprint
FROM document_signatures AS s
JOIN documents AS d ON d.id = s.document_id
LEFT JOIN users AS u ON u.id = s.signer_id
LEFT JOIN user_signing_keys AS k ON k.key_id = s.key_id
ORDER BY s.signed_at DESC
"""


def _short(value: object, size: int = 80) -> str:
    text = str(value or "")
    return text if len(text) <= size else text[: size - 1] + "…"


def generate(db_path: str | Path, output: str | Path = DEFAULT_OUTPUT) -> Path:
    connection = sqlite3.connect(str(db_path))
    connection.row_factory = sqlite3.Row
    try:
        rows = connection.execute(SQL).fetchall()
    finally:
        connection.close()

    body_rows = []
    for row in rows:
        body_rows.append(
            "<tr>"
            f'<td class="mono doc">{html.escape(str(row["document_id"]))}</td>'
            f'<td>{html.escape(str(row["original_filename"]))}</td>'
            f'<td class="mono">{html.escape(str(row["signer"] or "—"))}</td>'
            f'<td class="mono small">{html.escape(str(row["algorithm"]))}</td>'
            f'<td class="mono hash">{html.escape(str(row["document_sha256"]))}</td>'
            f'<td class="mono sig">{html.escape(_short(row["signature_b64"], 84))}'
            f'<span class="len">{len(str(row["signature_b64"]))} b64</span></td>'
            f'<td class="mono small">{html.escape(str(row["signed_at"]))}</td>'
            f'<td class="mono small">{html.escape(str(row["verified_at"] or "—"))}</td>'
            f'<td><span class="status status--{html.escape(str(row["status"]))}">'
            f'{html.escape(str(row["status"]))}</span></td>'
            "</tr>"
        )

    if not body_rows:
        body_rows.append(
            '<tr><td colspan="9" class="empty">Таблиця document_signatures порожня.</td></tr>'
        )

    document = f"""<!doctype html>
<html lang="uk"><head><meta charset="utf-8">
<title>document_signatures · Secure DocVault</title>
<style>
  :root {{
    --bg:#05080b; --panel:#0c141b; --line:rgba(151,193,208,.16);
    --text:#e9f3f3; --muted:#8aa1a9; --muted2:#647a83;
    --violet:#b49cff; --gold:#ffd07a; --mint:#72f2c6; --rose:#ff7c91;
    --mono:"Cascadia Code","JetBrains Mono",Consolas,monospace;
  }}
  *{{box-sizing:border-box}}
  body{{margin:0;padding:38px;background:
    radial-gradient(900px 500px at 82% -10%,rgba(180,156,255,.13),transparent 60%),
    radial-gradient(700px 420px at 2% 10%,rgba(255,208,122,.06),transparent 58%),var(--bg);
    color:var(--text);font-family:"Segoe UI",system-ui,sans-serif}}
  .wrap{{max-width:1380px;margin:0 auto}}
  .eyebrow{{margin:0 0 8px;color:var(--violet);font-family:var(--mono);font-size:11px;letter-spacing:.16em;text-transform:uppercase}}
  h1{{margin:0 0 6px;font-size:31px;letter-spacing:-.035em}}
  .sub{{margin:0 0 18px;color:var(--muted);font-size:12px}}
  .sql{{margin:0 0 16px;padding:13px 15px;border:1px solid var(--line);border-radius:12px;background:#070c10;color:var(--muted);font-family:var(--mono);font-size:10.5px;white-space:pre-wrap}}
  .table{{border:1px solid var(--line);border-radius:14px;overflow:hidden;background:var(--panel)}}
  table{{width:100%;border-collapse:collapse;font-size:10.5px}}
  th,td{{padding:9px 8px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}}
  th{{color:var(--muted);font-family:var(--mono);font-size:9px;letter-spacing:.07em;text-transform:uppercase;background:rgba(255,255,255,.025)}}
  tr:last-child td{{border-bottom:0}}
  td{{color:#c3d4d8;line-height:1.45}}
  .mono{{font-family:var(--mono)}}
  .small{{font-size:9.5px;color:var(--muted2)}}
  .doc{{color:var(--violet)}}
  .hash{{color:var(--mint);overflow-wrap:anywhere;max-width:170px}}
  .sig{{color:var(--gold);overflow-wrap:anywhere;max-width:210px}}
  .len{{display:block;margin-top:4px;color:var(--muted2);font-size:9px}}
  .status{{display:inline-flex;padding:3px 8px;border:1px solid var(--line);border-radius:999px;font-family:var(--mono);font-size:9px;text-transform:uppercase}}
  .status--verified{{color:var(--mint);border-color:rgba(114,242,198,.35);background:rgba(114,242,198,.08)}}
  .status--signed{{color:var(--gold);border-color:rgba(255,208,122,.35);background:rgba(255,208,122,.08)}}
  .status--invalid{{color:var(--rose);border-color:rgba(255,124,145,.35);background:rgba(255,124,145,.08)}}
  .empty{{text-align:center;color:var(--muted2);font-family:var(--mono);padding:26px}}
  .note{{margin:14px 0 0;color:var(--muted2);font-family:var(--mono);font-size:10px}}
</style></head>
<body><div class="wrap">
  <p class="eyebrow">Database snapshot / signature audit</p>
  <h1>document_signatures</h1>
  <p class="sub">Рядки {len(rows)} · SQLite · підпис зберігається як base64 RSA-PSS</p>
  <pre class="sql">SELECT s.document_id, d.original_filename, u.username AS signer,
       s.key_id, s.algorithm, s.document_sha256, s.signature_b64,
       s.signed_at, s.verified_at, s.status, k.fingerprint
FROM document_signatures AS s
JOIN documents AS d ON d.id = s.document_id
LEFT JOIN users AS u ON u.id = s.signer_id
LEFT JOIN user_signing_keys AS k ON k.key_id = s.key_id
ORDER BY s.signed_at DESC;</pre>
  <div class="table"><table>
    <thead><tr><th>Document ID</th><th>Файл</th><th>Signer</th><th>Algorithm</th>
      <th>SHA-256</th><th>Signature b64</th><th>Signed at</th><th>Verified at</th><th>Status</th></tr></thead>
    <tbody>{''.join(body_rows)}</tbody>
  </table></div>
  <p class="note">Приватний ключ у БД відсутній у відкритому вигляді: лише encrypted PKCS#8 PEM у user_signing_keys.</p>
</div></body></html>"""

    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(document, encoding="utf-8")
    return path


def main() -> int:
    parser = argparse.ArgumentParser(description="Lab 6 DB snapshot")
    parser.add_argument("--db", default=str(ROOT / "instance" / "docvault.db"))
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT))
    args = parser.parse_args()
    path = generate(args.db, args.output)
    print(f"Snapshot: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
