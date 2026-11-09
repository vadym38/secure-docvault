"""Генерує локальний HTML-знімок таблиці users для звіту.

Приклад:
    python scripts/db_snapshot.py
    python scripts/db_snapshot.py --db instance/docvault.db --out docs/db_snapshot.html

Скрипт призначений лише для навчального звіту. Не публікуйте реальні хеші
паролів у відкритому доступі.
"""

from __future__ import annotations

import argparse
import html
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

COLUMNS = (
    "id",
    "username",
    "email",
    "password_hash",
    "salt",
    "role",
    "created_at",
    "is_active",
)


def _cell(value) -> str:
    if value is None:
        return '<span class="null">NULL</span>'
    if isinstance(value, int):
        return str(value)
    return f"<code>{html.escape(str(value))}</code>"


def generate_snapshot(db_path: Path, output_path: Path) -> Path:
    """Читає users та записує автономний HTML-файл зі стилями."""

    db_path = Path(db_path)
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(str(db_path))
    connection.row_factory = sqlite3.Row

    try:
        schema = connection.execute("PRAGMA table_info(users)").fetchall()
        rows = connection.execute(
            f"SELECT {', '.join(COLUMNS)} FROM users ORDER BY id"
        ).fetchall()
        indexes = connection.execute("PRAGMA index_list(users)").fetchall()
    finally:
        connection.close()

    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    schema_rows = "".join(
        f"""
        <tr>
          <td><code>{html.escape(str(column['name']))}</code></td>
          <td><code>{html.escape(str(column['type']))}</code></td>
          <td>{'NOT NULL' if column['notnull'] else 'NULL'}</td>
          <td>{'PK' if column['pk'] else '—'}</td>
          <td>{html.escape(str(column['dflt_value'])) if column['dflt_value'] is not None else '—'}</td>
        </tr>
        """
        for column in schema
    )

    data_rows = ""
    for row in rows:
        cells = "".join(f"<td>{_cell(row[column])}</td>" for column in COLUMNS)
        data_rows += f"<tr>{cells}</tr>"

    if not data_rows:
        data_rows = f'<tr><td colspan="{len(COLUMNS)}" class="empty">Таблиця порожня</td></tr>'

    index_rows = "".join(
        f"<li><code>{html.escape(str(index['name']))}</code>"
        f" — {'UNIQUE' if index['unique'] else 'INDEX'}</li>"
        for index in indexes
    )

    document = f"""<!doctype html>
<html lang="uk">
<head>
  <meta charset="utf-8">
  <title>Secure DocVault · users snapshot</title>
  <style>
    :root {{
      --bg: #05080b;
      --panel: #0c141b;
      --line: rgba(151, 193, 208, 0.18);
      --text: #e9f3f3;
      --muted: #8aa1a9;
      --mint: #72f2c6;
      --amber: #ffb86b;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      padding: 34px;
      color: var(--text);
      background:
        radial-gradient(circle at 10% 0%, rgba(47, 214, 160, 0.12), transparent 28rem),
        linear-gradient(145deg, #04070a, #070d12 55%, #04070a);
      font-family: "Segoe UI", system-ui, sans-serif;
      font-size: 14px;
    }}
    h1 {{ margin: 0 0 4px; font-size: 28px; letter-spacing: -0.03em; }}
    h2 {{ margin: 26px 0 10px; font-size: 17px; }}
    p {{ margin: 0; color: var(--muted); }}
    code {{ font-family: "Cascadia Code", Consolas, monospace; }}
    .meta {{ display: flex; flex-wrap: wrap; gap: 10px 22px; margin: 14px 0 24px; color: var(--muted); font-size: 12px; }}
    .badge {{ display: inline-block; padding: 3px 8px; border: 1px solid rgba(114,242,198,.3); border-radius: 999px; color: var(--mint); font-family: "Cascadia Code", Consolas, monospace; font-size: 11px; }}
    .panel {{ overflow: auto; border: 1px solid var(--line); border-radius: 14px; background: var(--panel); }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{ padding: 9px 11px; border-bottom: 1px solid var(--line); text-align: left; vertical-align: top; white-space: nowrap; }}
    th {{ position: sticky; top: 0; color: var(--muted); background: #0a1218; font-family: "Cascadia Code", Consolas, monospace; font-size: 10px; letter-spacing: .08em; text-transform: uppercase; }}
    tr:last-child td {{ border-bottom: 0; }}
    td code {{ color: var(--mint); font-size: 11px; }}
    td:nth-child(4) code, td:nth-child(5) code {{ color: var(--amber); }}
    .null {{ color: var(--muted); }}
    .empty {{ color: var(--muted); text-align: center; padding: 28px; }}
    ul {{ margin: 8px 0 0; padding-left: 20px; color: var(--muted); }}
    .note {{ margin-top: 20px; padding: 12px 14px; border-left: 3px solid var(--amber); border-radius: 8px; background: rgba(255,184,107,.06); color: var(--muted); font-size: 12px; }}
  </style>
</head>
<body>
  <h1>Secure DocVault · таблиця <code>users</code></h1>
  <p>Локальний знімок бази даних для протоколу тестування ЛР №1.</p>
  <div class="meta">
    <span class="badge">bcrypt cost 12</span>
    <span>DB: <code>{html.escape(str(db_path))}</code></span>
    <span>Згенеровано: {generated_at}</span>
    <span>Записів: <strong>{len(rows)}</strong></span>
  </div>

  <h2>Схема</h2>
  <div class="panel">
    <table>
      <thead>
        <tr><th>Поле</th><th>Тип</th><th>Обов'язкове</th><th>Ключ</th><th>За замовчуванням</th></tr>
      </thead>
      <tbody>{schema_rows}</tbody>
    </table>
  </div>

  <h2>Дані</h2>
  <div class="panel">
    <table>
      <thead>
        <tr>{''.join(f'<th>{column}</th>' for column in COLUMNS)}</tr>
      </thead>
      <tbody>{data_rows}</tbody>
    </table>
  </div>

  <h2>Індекси</h2>
  <ul>{index_rows}</ul>

  <p class="note">
    Паролі не показані у відкритому вигляді: у колонках <code>password_hash</code>
    та <code>salt</code> зберігаються результати bcrypt. Сіль унікальна для
    кожного запису; вона також вбудована у сам bcrypt-хеш.
  </p>
</body>
</html>
"""

    output_path.write_text(document, encoding="utf-8")
    return output_path


def main() -> int:
    parser = argparse.ArgumentParser(description="HTML-знімок таблиці users")
    parser.add_argument("--db", default=str(ROOT / "instance" / "docvault.db"))
    parser.add_argument("--out", default=str(ROOT / "docs" / "db_snapshot.html"))
    args = parser.parse_args()

    output = generate_snapshot(Path(args.db), Path(args.out))
    print(f"[+] Знімок збережено: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
