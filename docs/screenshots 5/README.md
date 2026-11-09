# Скриншоти ЛР №5 — Secure DocVault

Усі файли згенеровані скриптом `scripts/capture_screenshots_lab5.py` з
реального Flask-сервера, реального API-протоколу, AES-256-GCM контейнера
та Selenium UI.

| Заголовок для звіту | Файл |
|---|---|
| Оглядова сторінка Cipher Vault `/vault` | `00-vault-overview.png` |
| API: login → upload → metadata → download, SHA-256 match | `01-api-upload-download.png` |
| Hexdump зашифрованого `.enc`-контейнера, plaintext marker: ABSENT | `02-stored-container-hexdump.png` |
| Тест цілісності: змінено 1 байт → `InvalidTag` → `409` | `03-integrity-invalidtag.png` |
| UI-завантаження та detail з IV/Tag/Ciphertext і hexdump | `04-vault-upload-detail.png` |
| Список зашифрованих документів | `05-vault-documents.png` |
| Архітектурна схема AES-GCM / AEAD | `06-file-encryption-architecture.png` |

`_capture_summary.json` містить реальний вивід API-, hexdump- та
integrity-скриптів.
