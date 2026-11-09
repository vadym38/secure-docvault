"""Юніт-тести сигнатурного WAF та Greylist (ЛР №4).

Запуск:
    python -m unittest tests.test_waf_filter -v
"""

from __future__ import annotations

import unittest

from app.waf_filter import (
    Greylist,
    inspect_payload,
    inspect_request,
    signature_table,
)


class PathTraversalTests(unittest.TestCase):
    def test_forward_slash_traversal(self):
        verdict = inspect_payload("../../etc/passwd")
        self.assertTrue(verdict.blocked)
        self.assertEqual(verdict.rule_id, "waf-1001")

    def test_backslash_traversal(self):
        verdict = inspect_payload(r"..\..\windows\win.ini")
        self.assertTrue(verdict.blocked)

    def test_url_encoded_traversal(self):
        verdict = inspect_payload("%2e%2e%2f%2e%2e%2fetc%2fpasswd")
        self.assertTrue(verdict.blocked)

    def test_double_encoded_traversal(self):
        verdict = inspect_payload("%252e%252e%252fetc%252fpasswd")
        self.assertTrue(verdict.blocked)


class SqlInjectionTests(unittest.TestCase):
    def test_union_select(self):
        self.assertTrue(inspect_payload("x' UNION SELECT password FROM users--").blocked)

    def test_tautology(self):
        verdict = inspect_payload("' OR '1'='1")
        self.assertTrue(verdict.blocked)
        self.assertEqual(verdict.rule_id, "waf-1003")

    def test_drop_table(self):
        self.assertTrue(inspect_payload("'; DROP TABLE users; --").blocked)

    def test_xp_cmdshell(self):
        self.assertTrue(inspect_payload("EXEC xp_cmdshell 'whoami'").blocked)

    def test_case_insensitive(self):
        self.assertTrue(inspect_payload("union select 1,2,3").blocked)


class CommandInjectionTests(unittest.TestCase):
    def test_shell_separator(self):
        verdict = inspect_payload("; /bin/sh -c id")
        self.assertTrue(verdict.blocked)
        self.assertEqual(verdict.rule_id, "waf-2001")

    def test_cmd_exe(self):
        self.assertTrue(inspect_payload("&& cmd.exe /c whoami").blocked)

    def test_system_call(self):
        self.assertTrue(inspect_payload("system('id')").blocked)

    def test_os_system_call(self):
        self.assertTrue(inspect_payload("os.system('cat /etc/passwd')").blocked)

    def test_cmd_parameter(self):
        self.assertTrue(inspect_payload("?cmd=whoami").blocked)

    def test_pipe_bash(self):
        self.assertTrue(inspect_payload("| bash -i").blocked)


class XssSignatureTests(unittest.TestCase):
    def test_script_tag(self):
        verdict = inspect_payload("<script>alert(1)</script>")
        self.assertTrue(verdict.blocked)
        self.assertEqual(verdict.rule_id, "waf-3001")

    def test_javascript_uri(self):
        self.assertTrue(inspect_payload("javascript:alert(1)").blocked)

    def test_event_handler(self):
        self.assertTrue(inspect_payload('<img src=x onerror=alert(1)>').blocked)

    def test_svg_container(self):
        self.assertTrue(inspect_payload("<svg onload=alert(1)>").blocked)


class FalsePositiveTests(unittest.TestCase):
    def test_plain_ukrainian_text_is_clean(self):
        self.assertFalse(
            inspect_payload("Договір оренди приміщення №14").blocked
        )

    def test_email_is_clean(self):
        self.assertFalse(inspect_payload("student@example.com").blocked)

    def test_operating_system_with_space_is_clean(self):
        # `system (` із пробілом — не виклик функції.
        self.assertFalse(inspect_payload("operating system (Linux)").blocked)

    def test_normal_sql_word_is_clean(self):
        self.assertFalse(inspect_payload("Опис документа для select").blocked)

    def test_empty_payload_is_clean(self):
        self.assertFalse(inspect_payload("").blocked)
        self.assertFalse(inspect_payload(None).blocked)


class RequestInspectionTests(unittest.TestCase):
    def test_path_is_inspected(self):
        verdict = inspect_request("/files/../../etc/passwd")
        self.assertTrue(verdict.blocked)
        self.assertEqual(verdict.location, "path")

    def test_query_is_inspected(self):
        verdict = inspect_request("/api/v1/user/profile", "file=../../etc/passwd")
        self.assertTrue(verdict.blocked)
        self.assertEqual(verdict.location, "query")

    def test_body_is_inspected(self):
        verdict = inspect_request(
            "/api/v1/auth/login",
            "",
            '{"username": "x", "password": "x\' OR \'1\'=\'1"}',
        )
        self.assertTrue(verdict.blocked)
        self.assertEqual(verdict.location, "body")

    def test_clean_request(self):
        verdict = inspect_request("/api/v1/health", "verbose=1", "")
        self.assertFalse(verdict.blocked)


class GreylistTests(unittest.TestCase):
    def test_block_and_check(self):
        greylist = Greylist()
        greylist.block("10.0.0.1", seconds=60, reason="test")
        blocked, remaining = greylist.is_blocked("10.0.0.1")
        self.assertTrue(blocked)
        self.assertGreater(remaining, 0)

    def test_unknown_ip_is_not_blocked(self):
        greylist = Greylist()
        self.assertEqual(greylist.is_blocked("10.0.0.2"), (False, 0))

    def test_clear(self):
        greylist = Greylist()
        greylist.block("10.0.0.1", seconds=60, reason="test")
        greylist.clear()
        self.assertFalse(greylist.is_blocked("10.0.0.1")[0])
        self.assertEqual(greylist.active(), [])

    def test_active_lists_entry(self):
        greylist = Greylist()
        greylist.block("10.0.0.1", seconds=60, reason="Path Traversal", rule_id="waf-1001")
        entries = greylist.active()
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["ip"], "10.0.0.1")
        self.assertEqual(entries[0]["rule_id"], "waf-1001")

    def test_signature_table_has_ids(self):
        table = signature_table()
        self.assertGreaterEqual(len(table), 10)
        self.assertEqual(table[0]["rule_id"], "waf-1001")


if __name__ == "__main__":
    unittest.main()
