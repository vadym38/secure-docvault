# Скриншоти ЛР №6 — Secure DocVault

Усі файли згенеровані скриптом `scripts/capture_screenshots_lab6.py` з
реального Flask-сервера, RSA-PSS-підпису, БД `document_signatures` та
Selenium UI.

| Заголовок для звіту | Файл |
|---|---|
| Оглядова сторінка Signature Lab | `00-signature-lab-overview.png` |
| Експортовані ключі: public X.509 PEM + encrypted PKCS#8 PEM | `01-keypair-pem.png` |
| Підписаний документ: статус Signed & Verified | `02-document-signed.png` |
| API: keygen → upload → sign → download, `X-Signature-Status` | `03-api-signed-download.png` |
| Тест фальсифікації: зміна 1 байта → verify = False / 409 | `04-tamper-signature.png` |
| Таблиця `document_signatures` у БД | `05-signature-db.png` |
| Список документів зі статусами підпису | `06-vault-signed-documents.png` |
| Архітектурна схема RSA-PSS / SHA-256 | `07-signature-architecture.png` |

`_capture_summary.json` містить реальний вивід API- та tamper-скриптів.
`docs/signature_db_snapshot.html` — HTML-знімок таблиці підписів.
