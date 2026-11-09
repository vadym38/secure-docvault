"""Генерує готовий DOCX-звіт з лабораторної роботи №1.

Запуск:
    python scripts/build_report_docx.py

Результат:
    docs/Звіт_ЛР1_Secure_DocVault.docx
"""

from __future__ import annotations

from pathlib import Path

from docx import Document
from docx.enum.section import WD_SECTION
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Cm, Pt, RGBColor

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
SHOTS = DOCS / "screenshots"
OUTPUT = DOCS / "Звіт_ЛР1_Secure_DocVault.docx"

BODY_FONT = "Times New Roman"
CODE_FONT = "Consolas"
DARK = RGBColor(0x1F, 0x2A, 0x33)
MUTED = RGBColor(0x55, 0x66, 0x70)


def _set_cell_shading(cell, color: str) -> None:
    tc_pr = cell._tc.get_or_add_tcPr()
    shading = OxmlElement("w:shd")
    shading.set(qn("w:fill"), color)
    tc_pr.append(shading)


def _set_repeat_table_header(row) -> None:
    tr_pr = row._tr.get_or_add_trPr()
    tbl_header = OxmlElement("w:tblHeader")
    tbl_header.set(qn("w:val"), "true")
    tr_pr.append(tbl_header)


def _add_page_number(paragraph) -> None:
    run = paragraph.add_run()
    begin = OxmlElement("w:fldChar")
    begin.set(qn("w:fldCharType"), "begin")
    instr = OxmlElement("w:instrText")
    instr.set(qn("xml:space"), "preserve")
    instr.text = "PAGE"
    end = OxmlElement("w:fldChar")
    end.set(qn("w:fldCharType"), "end")
    run._r.append(begin)
    run._r.append(instr)
    run._r.append(end)


def _style_document(doc: Document) -> None:
    styles = doc.styles

    normal = styles["Normal"]
    normal.font.name = BODY_FONT
    normal.font.size = Pt(12)
    normal.font.color.rgb = DARK
    normal.paragraph_format.line_spacing = 1.15
    normal.paragraph_format.space_after = Pt(6)
    normal.element.rPr.rFonts.set(qn("w:eastAsia"), BODY_FONT)

    for name, size, color in (
        ("Heading 1", 16, DARK),
        ("Heading 2", 14, DARK),
        ("Heading 3", 12, DARK),
    ):
        style = styles[name]
        style.font.name = BODY_FONT
        style.font.size = Pt(size)
        style.font.bold = True
        style.font.color.rgb = color
        style.paragraph_format.space_before = Pt(12)
        style.paragraph_format.space_after = Pt(6)

    code = styles.add_style("CodeBlock", 1)
    code.font.name = CODE_FONT
    code.font.size = Pt(8)
    code.font.color.rgb = RGBColor(0x20, 0x30, 0x38)
    code.paragraph_format.space_after = Pt(0)
    code.paragraph_format.line_spacing = 1.0
    code.element.rPr.rFonts.set(qn("w:eastAsia"), CODE_FONT)

    caption = styles.add_style("ShotCaption", 1)
    caption.font.name = BODY_FONT
    caption.font.size = Pt(10)
    caption.font.italic = True
    caption.font.color.rgb = MUTED
    caption.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.CENTER
    caption.paragraph_format.space_after = Pt(10)


def _add_header_footer(section) -> None:
    header = section.header
    header_paragraph = header.paragraphs[0]
    header_paragraph.text = "Secure DocVault · лабораторна робота №1"
    header_paragraph.alignment = WD_ALIGN_PARAGRAPH.RIGHT
    for run in header_paragraph.runs:
        run.font.name = BODY_FONT
        run.font.size = Pt(9)
        run.font.color.rgb = MUTED

    footer = section.footer
    footer_paragraph = footer.paragraphs[0]
    footer_paragraph.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = footer_paragraph.add_run("Сторінка ")
    run.font.name = BODY_FONT
    run.font.size = Pt(9)
    run.font.color.rgb = MUTED
    _add_page_number(footer_paragraph)


def _title_page(doc: Document) -> None:
    for _ in range(2):
        doc.add_paragraph()

    lines = [
        ("ДРОГОБИЦЬКИЙ ДЕРЖАВНИЙ ПЕДАГОГІЧНИЙ УНІВЕРСИТЕТ", 14, True),
        ("ІМЕНІ ІВАНА ФРАНКА", 14, True),
        ("", 12, False),
        ("Факультет фізики, математики, економіки", 11, False),
        ("та інноваційних технологій", 11, False),
        ("Кафедра фізики та інформаційних систем", 11, False),
        ("", 12, False),
        ("Освітньо-професійна програма «Комп'ютерні науки»", 11, False),
        ("Рівень вищої освіти: перший (бакалаврський)", 11, False),
        ("", 12, False),
        ("Дисципліна: «Технології захисту інформаційних ресурсів»", 11, False),
    ]

    for text, size, bold in lines:
        paragraph = doc.add_paragraph()
        paragraph.alignment = WD_ALIGN_PARAGRAPH.CENTER
        paragraph.paragraph_format.space_after = Pt(2)
        run = paragraph.add_run(text)
        run.font.name = BODY_FONT
        run.font.size = Pt(size)
        run.bold = bold

    for _ in range(4):
        doc.add_paragraph()

    title = doc.add_paragraph()
    title.alignment = WD_ALIGN_PARAGRAPH.CENTER
    title.paragraph_format.space_after = Pt(4)
    run = title.add_run("ЗВІТ")
    run.font.name = BODY_FONT
    run.font.size = Pt(26)
    run.bold = True

    subtitle = doc.add_paragraph()
    subtitle.alignment = WD_ALIGN_PARAGRAPH.CENTER
    subtitle.paragraph_format.space_after = Pt(14)
    run = subtitle.add_run("з лабораторної роботи №1")
    run.font.name = BODY_FONT
    run.font.size = Pt(14)

    topic = doc.add_paragraph()
    topic.alignment = WD_ALIGN_PARAGRAPH.CENTER
    topic.paragraph_format.space_after = Pt(4)
    run = topic.add_run("«Фундамент безпеки:")
    run.font.name = BODY_FONT
    run.font.size = Pt(18)
    run.bold = True

    topic2 = doc.add_paragraph()
    topic2.alignment = WD_ALIGN_PARAGRAPH.CENTER
    topic2.paragraph_format.space_after = Pt(4)
    run = topic2.add_run("Автентифікація та захист бази даних»")
    run.font.name = BODY_FONT
    run.font.size = Pt(18)
    run.bold = True

    project = doc.add_paragraph()
    project.alignment = WD_ALIGN_PARAGRAPH.CENTER
    project.paragraph_format.space_after = Pt(26)
    run = project.add_run("Наскрізний навчальний проєкт «Secure DocVault» · Етап 1")
    run.font.name = BODY_FONT
    run.font.size = Pt(11)
    run.italic = True
    run.font.color.rgb = MUTED

    for _ in range(2):
        doc.add_paragraph()

    for label in (
        "Виконав: ______________________________",
        "Група: ______________________________",
        "Викладач: ______________________________",
    ):
        paragraph = doc.add_paragraph()
        paragraph.alignment = WD_ALIGN_PARAGRAPH.LEFT
        paragraph.paragraph_format.left_indent = Cm(8)
        paragraph.paragraph_format.space_after = Pt(10)
        run = paragraph.add_run(label)
        run.font.name = BODY_FONT
        run.font.size = Pt(12)

    for _ in range(5):
        doc.add_paragraph()

    city = doc.add_paragraph()
    city.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = city.add_run("Дрогобич — 2026")
    run.font.name = BODY_FONT
    run.font.size = Pt(12)
    run.font.color.rgb = MUTED

    doc.add_page_break()


def _add_schema_table(doc: Document) -> None:
    rows = [
        ("id", "INTEGER", "PRIMARY KEY AUTOINCREMENT", "унікальний ідентифікатор"),
        ("username", "TEXT", "NOT NULL, UNIQUE, COLLATE NOCASE", "ім'я для входу"),
        ("email", "TEXT", "NOT NULL, UNIQUE, COLLATE NOCASE", "контактна адреса"),
        ("password_hash", "TEXT", "NOT NULL", "повний bcrypt-хеш $2b$12$..."),
        ("salt", "TEXT", "NOT NULL", "унікальна сіль (вбудована в хеш)"),
        ("role", "TEXT", "DEFAULT 'user', CHECK", "роль доступу"),
        ("created_at", "TEXT", "DEFAULT UTC", "час створення"),
        ("is_active", "INTEGER", "DEFAULT 1, CHECK", "ознака активності"),
    ]

    table = doc.add_table(rows=1, cols=4)
    table.style = "Table Grid"
    table.alignment = WD_TABLE_ALIGNMENT.CENTER

    header = table.rows[0].cells
    for cell, text in zip(header, ("Поле", "Тип", "Обмеження", "Призначення")):
        cell.text = ""
        paragraph = cell.paragraphs[0]
        run = paragraph.add_run(text)
        run.bold = True
        run.font.name = BODY_FONT
        run.font.size = Pt(9)
        _set_cell_shading(cell, "DDEBE7")
    _set_repeat_table_header(table.rows[0])

    for field, type_, constraint, purpose in rows:
        cells = table.add_row().cells
        for cell, text in zip(cells, (field, type_, constraint, purpose)):
            cell.text = ""
            paragraph = cell.paragraphs[0]
            run = paragraph.add_run(text)
            run.font.name = CODE_FONT if field in {"password_hash", "salt"} else BODY_FONT
            run.font.size = Pt(8.5)


def _add_code(doc: Document, path: Path, title: str) -> None:
    doc.add_heading(title, level=2)

    text = path.read_text(encoding="utf-8")

    table = doc.add_table(rows=1, cols=1)
    table.style = "Table Grid"
    cell = table.rows[0].cells[0]
    _set_cell_shading(cell, "F4F7F6")

    paragraph = cell.paragraphs[0]
    paragraph.style = doc.styles["CodeBlock"]

    first = True
    for line in text.splitlines():
        if not first:
            paragraph.add_run().add_break()
        run = paragraph.add_run(line if line else " ")
        run.font.name = CODE_FONT
        run.font.size = Pt(7.5)
        first = False

    doc.add_paragraph()


def _add_picture(doc: Document, filename: str, caption: str) -> None:
    path = SHOTS / filename
    if not path.exists():
        return
    paragraph = doc.add_paragraph()
    paragraph.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = paragraph.add_run()
    run.add_picture(str(path), width=Cm(16.2))
    cap = doc.add_paragraph(caption, style="ShotCaption")


def _add_bullets(doc: Document, items: list[str]) -> None:
    for item in items:
        paragraph = doc.add_paragraph(style="List Bullet")
        paragraph.paragraph_format.space_after = Pt(3)
        run = paragraph.add_run(item)
        run.font.name = BODY_FONT
        run.font.size = Pt(11)


def build() -> Path:
    doc = Document()
    _style_document(doc)

    section = doc.sections[0]
    section.page_width = Cm(21)
    section.page_height = Cm(29.7)
    section.top_margin = Cm(2)
    section.bottom_margin = Cm(2)
    section.left_margin = Cm(2.5)
    section.right_margin = Cm(1.5)
    _add_header_footer(section)

    _title_page(doc)

    # 1. Мета -------------------------------------------------------------
    doc.add_heading("1. Мета та постановка задачі", level=1)
    doc.add_paragraph(
        "Мета роботи: створити первинне безпечне ядро бекенду корпоративного "
        "порталу Secure DocVault — підсистему безпечної реєстрації та входу "
        "користувачів із підключенням реляційної бази даних, криптографічним "
        "хешуванням паролів із застосуванням солі та апаратним захистом від "
        "SQL-ін'єкцій через параметризовані запити."
    )
    doc.add_paragraph(
        "Етап 1 закладає фундамент системи управління ідентифікацією та доступом "
        "(IAM). На цьому рівні формуються довірені облікові записи, безпечне "
        "зберігання паролів і базовий модуль перевірки автентичності, який у "
        "ЛР №2 буде використаний для випуску JWT-токенів."
    )
    doc.add_paragraph(
        "У методичному прикладі використано десктопний PyQt-клієнт. У цій роботі "
        "реалізовано веб-інтерфейс на Flask + Jinja2 з авторським темним дизайном "
        "«Obsidian Vault». Це дає змогу продемонструвати ті самі механізми безпеки "
        "в браузері та перевірити їх E2E-тестами через Selenium."
    )

    doc.add_heading("2. Архітектура та схема даних", level=1)
    doc.add_heading("2.1. Таблиця users", level=2)
    _add_schema_table(doc)
    doc.add_paragraph()
    doc.add_paragraph(
        "Усі SQL-запити виконуються через Prepared Statements: SQL-код містить "
        "плейсхолдери ?, а значення передаються окремим кортежем параметрів."
    )
    doc.add_heading("2.2. Діаграма процесу реєстрації та входу", level=2)
    _add_picture(doc, "08-auth-flow.png", "Рис. 1. Потік реєстрації та входу Secure DocVault")

    # 3. Код --------------------------------------------------------------
    doc.add_page_break()
    doc.add_heading("3. Лістинг програмного коду", level=1)
    doc.add_paragraph(
        "Нижче наведено повні файли криптографічного модуля та модуля роботи з "
        "базою даних. Маршрути, CSRF та сесії реалізовано в app/auth.py; повний "
        "код доступний у репозиторії."
    )
    _add_code(doc, ROOT / "app" / "auth_security.py", "3.1. app/auth_security.py")
    _add_code(doc, ROOT / "app" / "database.py", "3.2. app/database.py")

    # 4. Протокол ---------------------------------------------------------
    doc.add_page_break()
    doc.add_heading("4. Протокол тестування", level=1)

    doc.add_heading("4.1. Вміст таблиці users у БД", level=2)
    doc.add_paragraph(
        "Паролі не зберігаються у відкритому вигляді: у полі password_hash — "
        "bcrypt-рядок $2b$12$..., у полі salt — унікальна сіль. Усі три солі різні."
    )
    _add_picture(doc, "07-users-table.png", "Рис. 2. Таблиця users із bcrypt-хешами та унікальними солями")

    doc.add_heading("4.2. Успішна реєстрація з валідацією складності пароля", level=2)
    doc.add_paragraph(
        "Форма заповнена паролем Vault#2026!. Індикатор показує «Надійний», усі "
        "п'ять правил підсвічені зеленим. Серверна валідація дублює клієнтську."
    )
    _add_picture(doc, "01-register-validation.png", "Рис. 3. Реєстрація з надійним паролем")
    _add_picture(doc, "02-register-success.png", "Рис. 4. Успішна реєстрація")

    doc.add_heading("4.3. Успішний вхід", level=2)
    doc.add_paragraph(
        "Після введення правильного пароля відкривається закритий кабінет із "
        "ідентифікатором, роллю, часом створення та частково замаскованим хешем."
    )
    _add_picture(doc, "04-dashboard.png", "Рис. 5. Успішний вхід і кабінет користувача")

    doc.add_heading("4.4. Помилка входу з хибним паролем", level=2)
    doc.add_paragraph(
        "Введено Wrong#2026! замість Vault#2026!. Сервер повертає єдине нейтральне "
        "повідомлення «Невірне ім'я користувача або пароль.», не розкриваючи "
        "причину відмови."
    )
    _add_picture(doc, "03-login-error.png", "Рис. 6. Помилка входу з хибним паролем")

    doc.add_heading("4.5. Моделювання SQL-ін'єкції у формі входу", level=2)
    doc.add_paragraph(
        "У поле «Ім'я користувача» введено класичний payload ' OR '1'='1. "
        "Результат: доступ не надано, повернуто 401 і нейтральне повідомлення."
    )
    _add_picture(doc, "05-sqli-login.png", "Рис. 7. SQLi-payload у формі входу та відмова")

    doc.add_heading("4.6. SQLi-лабораторія", level=2)
    doc.add_paragraph(
        "Стенд /security-lab виконує той самий параметризований SELECT, що й вхід, "
        "але не створює сесію та не повертає персональних даних. Результат: "
        "rows returned: 0, injection blocked: true."
    )
    _add_picture(doc, "06-security-lab.png", "Рис. 8. Параметризований запит блокує payload")

    doc.add_heading("4.7. Автоматичні тести", level=2)
    _add_bullets(
        doc,
        [
            "25 тестів unittest: політика пароля, bcrypt, унікальність солей, схема БД, SQLi-payload.",
            "9 E2E-тестів Selenium: реєстрація, слабкий пароль, вхід, хибний пароль, SQLi, CSRF, dashboard, показ пароля.",
            "Загалом 34 автоматичні перевірки — усі успішні.",
        ],
    )
    code = doc.add_paragraph()
    code.style = doc.styles["CodeBlock"]
    code.add_run(
        "python -m unittest tests.test_security tests.test_database -v\n"
        "Ran 25 tests ... OK\n\n"
        "python -m unittest tests.test_web_e2e -v\n"
        "Ran 9 tests ... OK"
    )

    # 5. Git --------------------------------------------------------------
    doc.add_heading("5. Git-коміт", level=1)
    doc.add_paragraph(
        "Репозиторій ініціалізовано локально. Перший стабільний коміт позначено "
        "тегом v0.1-auth-db. Для здачі викладачеві потрібно додати remote та "
        "виконати git push --tags."
    )
    _add_bullets(
        doc,
        [
            "git log --oneline --decorate",
            "git tag  →  v0.1-auth-db",
            "Посилання на репозиторій: ______________________________",
        ],
    )

    # 6. Висновки ---------------------------------------------------------
    doc.add_heading("6. Висновки", level=1)
    _add_bullets(
        doc,
        [
            "bcrypt із work factor 12 виконує 2^12 ітерацій, тому brute-force та rainbow-table атаки стають економічно недоцільними; work factor можна підвищувати з часом.",
            "Унікальна сіль руйнує повторне використання rainbow table: однакові паролі двох користувачів дають різні хеші. Сіль не є секретом.",
            "Prepared Statements розділяють код і дані: СУБД компілює запит із плейсхолдерами до передачі значень, тому payload ' OR '1'='1 залишається літералом.",
            "CSRF-токени, session.clear() після входу, HttpOnly/SameSite cookie, єдине повідомлення про помилку та dummy bcrypt-перевірка зменшують ризик CSRF, session fixation, user enumeration і timing-атак.",
            "Створено робочий веб-застосунок, який проходить 34 автоматичні перевірки та демонструє блокування SQLi.",
        ],
    )

    # 7. Контрольні питання ----------------------------------------------
    doc.add_page_break()
    doc.add_heading("7. Відповіді на контрольні питання", level=1)

    questions = [
        (
            "1. Чому MD5, SHA-1, SHA-256 вразливі для паролів? Що таке rainbow table?",
            "Це швидкі хеш-функції загального призначення. Вони проєктувалися для "
            "перевірки цілісності даних, а не для зберігання секретів. Сучасні GPU "
            "обчислюють мільярди SHA-256-хешів за секунду, тому перебір паролів стає "
            "швидким. Rainbow table — заздалегідь обчислена таблиця відповідностей "
            "«хеш → пароль». Якщо хеші не солені, атакуючий може миттєво знайти пароль "
            "за таблицею. Сіль робить кожен хеш унікальним і руйнує можливість "
            "повторного використання таблиці.",
        ),
        (
            "2. Призначення солі. Чому вона унікальна і чи потрібно її засекречувати?",
            "Сіль — випадкове значення, яке додається до пароля перед хешуванням. "
            "Вона гарантує, що однакові паролі дають різні хеші, і що rainbow table "
            "не можна застосувати повторно. Сіль має бути унікальною для кожного "
            "користувача (бажано — для кожного запису пароля). Сіль не потрібно "
            "зберігати в секреті: вона зберігається поряд із хешем, але її "
            "унікальність і достатня ентропія роблять атаку невигідною. Секретом є "
            "сам пароль, а не сіль.",
        ),
        (
            "3. Принцип work factor у bcrypt/Argon2. Чому важливо збільшувати складність?",
            "Work factor визначає кількість обчислювальної роботи для одного "
            "хешування. У bcrypt rounds=12 означає 2^12 ітерацій; у Argon2 "
            "налаштовуються memory cost, time cost і parallelism. Збільшення work "
            "factor збільшує час для захисника, але експоненційно збільшує вартість "
            "масового перебору для атакуючого. З часом обладнання дешевшає, тому "
            "параметри треба періодично підвищувати; старі хеші можна перехешувати "
            "під час наступного входу користувача.",
        ),
        (
            "4. Чому Prepared Statements гарантують захист від SQLi, а фільтрація лапок — ні?",
            "Prepared Statement розділяє код запиту і дані. СУБД спочатку компілює "
            "запит із плейсхолдерами ?, а потім підставляє значення як параметри. "
            "Тому значення ніколи не інтерпретується як SQL-синтаксис. Фільтрація "
            "лапок — це чорний список: вона залежить від контексту, кодування, "
            "драйвера та може бути обійдена через альтернативні представлення, "
            "коментарі, UNION, числові контексти тощо. Параметризація — структурний "
            "захист на рівні протоколу СУБД, а не евристика.",
        ),
        (
            "5. Що таке timing attack і як checkpw захищає від витоку?",
            "Timing attack — атака за часом виконання. Якщо перевірка пароля порівнює "
            "символи по одному і зупиняється на першій розбіжності, час відповіді "
            "залежить від кількості правильних перших символів. Атакуючий може "
            "підбирати пароль посимвольно. bcrypt.checkpw виконує порівняння у "
            "постійному часі (constant-time) і не зупиняється на першій розбіжності, "
            "тому час не розкриває правильний префікс. Додатково dummy-хеш для "
            "неіснуючого користувача вирівнює час між «користувач є» та «користувача "
            "немає».",
        ),
    ]

    for question, answer in questions:
        doc.add_heading(question, level=2)
        doc.add_paragraph(answer)

    doc.add_heading("Додаток. Відтворення результатів", level=1)
    _add_bullets(
        doc,
        [
            "python -m venv venv",
            "pip install -r requirements-dev.txt",
            "copy .env.example .env  (Windows) або cp .env.example .env (Linux/macOS)",
            "python run.py",
            "python -m unittest tests.test_security tests.test_database -v",
            "python -m unittest tests.test_web_e2e -v",
            "python scripts/capture_screenshots.py",
        ],
    )
    doc.add_paragraph("Демо-пароль: Vault#2026! (створюється scripts/seed_demo.py).")

    doc.save(OUTPUT)
    return OUTPUT


if __name__ == "__main__":
    result = build()
    print(f"[+] DOCX-звіт збережено: {result}")
