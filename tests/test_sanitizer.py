"""Юніт-тести санітизації користувацького вводу (ЛР №3).

Запуск:
    python -m unittest tests.test_sanitizer -v
"""

from __future__ import annotations

import unittest

from app.sanitizer import (
    escape_text,
    inspect_sanitization,
    sanitize_comment,
    sanitize_description,
    sanitize_filename,
    sanitize_text,
)


class SanitizeTextTests(unittest.TestCase):
    def test_script_tag_is_removed(self):
        cleaned = sanitize_text("<script>alert('XSS')</script>")
        self.assertNotIn("<script", cleaned.lower())
        self.assertNotIn("</script", cleaned.lower())

    def test_img_onerror_is_removed(self):
        cleaned = sanitize_text('<img src=x onerror=alert(1)>')
        self.assertNotIn("<img", cleaned.lower())
        self.assertNotIn("onerror", cleaned.lower())

    def test_svg_onload_is_removed(self):
        cleaned = sanitize_text('<svg onload=alert(1)>')
        self.assertNotIn("<svg", cleaned.lower())
        self.assertNotIn("onload", cleaned.lower())

    def test_javascript_protocol_cannot_survive_as_markup(self):
        cleaned = sanitize_text('<a href="javascript:alert(1)">link</a>')
        self.assertNotIn("<a", cleaned.lower())
        self.assertNotIn("href=", cleaned.lower())

    def test_plain_ukrainian_text_is_preserved(self):
        text = "Договір оренди приміщення №14"
        self.assertEqual(sanitize_text(text), text)

    def test_html_entities_are_returned_as_plain_text(self):
        # Bleach екранує < > &, модуль повертає сирий текст: Jinja2
        # повторно екранує його під час виводу.
        self.assertEqual(sanitize_text("2 < 3 & 4 > 1"), "2 < 3 & 4 > 1")
        self.assertEqual(escape_text("2 < 3"), "2 &lt; 3")

    def test_control_characters_are_removed(self):
        cleaned = sanitize_text("report\x00\x07.pdf")
        self.assertEqual(cleaned, "report.pdf")

    def test_text_is_truncated_to_limit(self):
        cleaned = sanitize_text("a" * 50, max_length=10)
        self.assertEqual(len(cleaned), 10)
        self.assertTrue(cleaned.endswith("…"))

    def test_none_returns_empty_string(self):
        self.assertEqual(sanitize_text(None), "")

    def test_comment_keeps_newlines(self):
        cleaned = sanitize_comment("Перший рядок\nДругий рядок")
        self.assertIn("\n", cleaned)

    def test_description_delegates_to_comment_policy(self):
        payload = "<b>Опис</b><script>alert(1)</script>"
        cleaned = sanitize_description(payload)
        self.assertNotIn("<script", cleaned.lower())
        self.assertNotIn("<b>", cleaned.lower())
        self.assertIn("Опис", cleaned)


class SanitizeFilenameTests(unittest.TestCase):
    def test_path_traversal_is_stripped(self):
        self.assertEqual(sanitize_filename("../../etc/passwd"), "passwd")

    def test_backslash_path_is_stripped(self):
        self.assertEqual(sanitize_filename(r"C:\temp\secret.pdf"), "secret.pdf")

    def test_html_payload_in_filename_is_removed(self):
        cleaned = sanitize_filename("contract<img src=x onerror=alert(1)>.pdf")
        self.assertEqual(cleaned, "contract.pdf")

    def test_dangerous_characters_are_replaced(self):
        cleaned = sanitize_filename("звіт:2026?.pdf")
        self.assertNotIn(":", cleaned)
        self.assertNotIn("?", cleaned)

    def test_windows_reserved_name_is_prefixed(self):
        self.assertEqual(sanitize_filename("CON.txt"), "_CON.txt")

    def test_empty_name_falls_back_to_document(self):
        self.assertEqual(sanitize_filename("   "), "document")
        self.assertEqual(sanitize_filename(".."), "document")

    def test_ukrainian_filename_is_preserved(self):
        self.assertEqual(sanitize_filename("звіт-2026.pdf"), "звіт-2026.pdf")

    def test_double_extension_is_preserved_safely(self):
        self.assertEqual(sanitize_filename("archive.tar.gz"), "archive.tar.gz")


class SanitizationReportTests(unittest.TestCase):
    def test_report_lists_removed_tags_and_handlers(self):
        report = inspect_sanitization(
            "<script>alert(1)</script><img src=x onerror=alert(2)>"
        )
        self.assertIn("<script>", report.blocked_vectors)
        self.assertIn("<img>", report.blocked_vectors)
        self.assertIn("onerror", report.blocked_vectors)
        self.assertTrue(report.changed)

    def test_report_detects_javascript_protocol(self):
        report = inspect_sanitization('<a href="javascript:alert(1)">x</a>')
        self.assertIn("javascript:", report.blocked_vectors)

    def test_clean_text_is_reported_unchanged(self):
        report = inspect_sanitization("Звичайний опис документа")
        self.assertTrue(report.is_clean)
        self.assertEqual(report.blocked_vectors, ())


if __name__ == "__main__":
    unittest.main()
