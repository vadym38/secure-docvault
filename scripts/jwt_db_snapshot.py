"""Генерує HTML-знімок таблиці refresh_tokens для протоколу ЛР №2.

Приклад:
    python scripts/jwt_db_snapshot.py
    python scripts/jwt_db_snapshot.py --db instance/lab2_demo.db --out docs/jwt_db_snapshot.html
"""

from __future__ import annotations

import argparse
import html
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _status(row: sqlite3.Row) -> tuple[str, str]:
    if not row["revoked_at"]:
        return "ACTIVE", "active"
    reason = row["revoked_reason"] or "revoked"
    if reason == "rotated":
        return "ROTATED", "rotated"
    if reason == "reuse_detected":
        return "REUSE DETECTED", "reuse"
    return reason.upper(), "revoked"


def generate_snapshot(db_path: Path, out_path: Path) -> Path:
    connection = sqlite3.connect(str(db_path))
    connection.row_factory = sqlite3.Row

    rows = connection.execute(
        """
        SELECT rt.id, rt.jti, rt.family_id, rt.user_id, u.username,
               rt.issued_at, rt.expires_at, rt.revoked_at,
               rt.revoked_reason, rt.replaced_by_jti
        FROM refresh_tokens AS rt
        LEFT JOIN users AS u ON u.id = rt.user_id
        ORDER BY rt.id
        """
    ).fetchall()
    connection.close()

    active = sum(1 for row in rows if not row["revoked_at"])
    rotated = sum(1 for row in rows if row["revoked_reason"] == "rotated")
    reuse = sum(1 for row in rows if row["revoked_reason"] == "reuse_detected")

    body_rows = []
    for row in rows:
        status, css = _status(row)
        body_rows.append(
            f"""
            <tr>
              <td class="mono">{row['id']}</td>
              <td>{html.escape(row['username'] or '—')}</td>
              <td class="mono small">{html.escape(row['jti'][:22])}…</td>
              <td class="mono small">{html.escape(row['family_id'][:16])}…</td>
              <td class="mono small">{html.escape(row['issued_at'])}</td>
              <td class="mono small">{html.escape(row['expires_at'])}</td>
              <td class="mono small">{html.escape(row['revoked_at'] or '—')}</td>
              <td><span class="pill {css}">{html.escape(status)}</span></td>
              <td class="mono small">{html.escape((row['replaced_by_jti'] or '—')[:22])}</td>
            </tr>
            """
        )

    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    document = f"""<!doctype html>
<html lang="uk">
<head>
<meta charset="utf-8">
<title>refresh_tokens · Secure DocVault</title>
<style>
  :root {{
    --bg:#05080b; --panel:#0c141b; --line:rgba(151,193,208,.16);
    --text:#e9f3f3; --soft:#c3d4d8; --muted:#8aa1a9; --mint:#72f2c6;
    --rose:#ff7c91; --amber:#ffb86b; --blue:#7ab8ff;
    --mono:"Cascadia Code","JetBrains Mono",Consolas,monospace;
    --font:"Segoe UI Variable Text","Segoe UI",system-ui,sans-serif;
  }}
  * {{ box-sizing:border-box; }}
  body {{
    margin:0; padding:40px 46px; color:var(--text); font-family:var(--font);
    background:
      radial-gradient(circle at 8% 0%, rgba(47,214,160,.12), transparent 32rem),
      radial-gradient(circle at 95% 90%, rgba(122,184,255,.08), transparent 32rem),
      linear-gradient(145deg,#04070a,#070d12 52%,#04070a);
  }}
  h1 {{ margin:0; font-size:34px; letter-spacing:-.04em; }}
  .sub {{ margin:8px 0 18px; color:var(--muted); font-size:13px; }}
  .meta {{ display:flex; flex-wrap:wrap; gap:8px; margin-bottom:18px; }}
  .badge {{
    padding:5px 9px; border:1px solid var(--line); border-radius:999px;
    color:var(--muted); font-family:var(--mono); font-size:10px;
  }}
  .badge--ok {{ color:var(--mint); border-color:rgba(114,242,198,.3); }}
  .badge--warn {{ color:var(--amber); border-color:rgba(255,184,107,.3); }}
  .badge--bad {{ color:var(--rose); border-color:rgba(255,124,145,.3); }}
  table {{
    width:100%; border-collapse:collapse; overflow:hidden;
    border:1px solid var(--line); border-radius:14px; background:var(--panel);
  }}
  th {{
    padding:10px 11px; text-align:left; color:var(--muted);
    font-family:var(--mono); font-size:9px; letter-spacing:.08em;
    text-transform:uppercase; border-bottom:1px solid var(--line);
    background:rgba(255,255,255,.02);
  }}
  td {{ padding:11px; border-bottom:1px solid var(--line); color:var(--soft); font-size:11px; }}
  tr:last-child td {{ border-bottom:0; }}
  .mono {{ font-family:var(--mono); }}
  .small {{ font-size:10px; color:var(--muted); }}
  .pill {{
    display:inline-block; padding:3px 7px; border-radius:999px;
    font-family:var(--mono); font-size:8.5px; letter-spacing:.05em;
  }}
  .pill.active {{ color:var(--mint); background:rgba(114,242,198,.1); }}
  .pill.rotated {{ color:var(--blue); background:rgba(122,184,255,.1); }}
  .pill.reuse {{ color:var(--rose); background:rgba(255,124,145,.1); }}
  .pill.revoked {{ color:var(--amber); background:rgba(255,184,107,.1); }}
  .note {{
    margin-top:16px; padding:12px 14px; border:1px solid var(--line);
    border-left:3px solid var(--mint); border-radius:10px;
    color:var(--muted); font-size:11px; line-height:1.55;
  }}
</style>
</head>
<body>
  <h1>refresh_tokens · журнал ротації</h1>
  <p class="sub">Кожен Refresh-токен — окремий jti. Після обміну старий запис отримує revoked_at, а повторне використання відкликає всю family_id.</p>
  <div class="meta">
    <span class="badge badge--ok">active: {active}</span>
    <span class="badge badge--warn">rotated: {rotated}</span>
    <span class="badge badge--bad">reuse detected: {reuse}</span>
    <span class="badge">records: {len(rows)}</span>
    <span class="badge">generated: {generated}</span>
    <span class="badge">DB: {html.escape(str(db_path))}</span>
  </div>
  <table>
    <thead>
      <tr>
        <th>ID</th><th>USER</th><th>JTI</th><th>FAMILY</th><th>ISSUED</th>
        <th>EXPIRES</th><th>REVOKED</th><th>STATUS</th><th>REPLACED BY</th>
      </tr>
    </thead>
    <tbody>
      {''.join(body_rows)}
    </tbody>
  </table>
  <p class="note">
    <strong>Як читати:</strong> рядок <span class="mono">ROTATED</span> — токен одноразово обміняно на новий;
    <span class="mono">REUSE DETECTED</span> — повторна спроба використати вже ротований токен;
    <span class="mono">ACTIVE</span> — токен ще можна обміняти. Саме revoked_at/replaced_by_jti
    реалізують blacklist та Refresh Token Rotation.
  </p>
</body>
</html>"""

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(document, encoding="utf-8")
    return out_path


def main() -> int:
    parser = argparse.ArgumentParser(description="HTML-знімок refresh_tokens")
    parser.add_argument("--db", default=str(ROOT / "instance" / "docvault.db"))
    parser.add_argument("--out", default=str(ROOT / "docs" / "jwt_db_snapshot.html"))
    args = parser.parse_args()

    out = generate_snapshot(Path(args.db), Path(args.out))
    print(f"[+] Знімок refresh_tokens: {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
