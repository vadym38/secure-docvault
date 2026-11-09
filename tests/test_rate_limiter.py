"""Юніт-тести Sliding Window Rate Limiter (ЛР №4).

Запуск:
    python -m unittest tests.test_rate_limiter -v
"""

from __future__ import annotations

import unittest

from app.rate_limiter import RateLimitRule, SlidingWindowRateLimiter


def rule(limit: int = 3, window: int = 10, name: str = "test") -> RateLimitRule:
    return RateLimitRule(
        name=name,
        title="Test rule",
        limit=limit,
        window_seconds=window,
        scope="/test",
    )


class SlidingWindowTests(unittest.TestCase):
    def setUp(self):
        self.limiter = SlidingWindowRateLimiter()

    def test_allows_requests_until_limit(self):
        for index in range(3):
            decision = self.limiter.check("10.0.0.1", rule(), now=100.0 + index)
            self.assertTrue(decision.allowed)
            self.assertEqual(decision.remaining, 2 - index)

    def test_blocks_request_over_limit(self):
        for index in range(3):
            self.limiter.check("10.0.0.1", rule(), now=100.0 + index)

        decision = self.limiter.check("10.0.0.1", rule(), now=103.0)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.remaining, 0)
        self.assertGreaterEqual(decision.retry_after, 1)

    def test_retry_after_decreases_as_window_moves(self):
        for index in range(3):
            self.limiter.check("10.0.0.1", rule(window=10), now=100.0 + index)

        early = self.limiter.check("10.0.0.1", rule(window=10), now=103.0)
        late = self.limiter.check("10.0.0.1", rule(window=10), now=107.0)
        self.assertFalse(early.allowed)
        self.assertFalse(late.allowed)
        self.assertGreater(early.retry_after, late.retry_after)

    def test_window_slides_and_allows_again(self):
        for index in range(3):
            self.limiter.check("10.0.0.1", rule(window=10), now=100.0 + index)
        self.assertFalse(
            self.limiter.check("10.0.0.1", rule(window=10), now=109.5).allowed
        )
        self.assertTrue(
            self.limiter.check("10.0.0.1", rule(window=10), now=111.0).allowed
        )

    def test_different_ips_are_isolated(self):
        for index in range(3):
            self.limiter.check("10.0.0.1", rule(), now=100.0 + index)

        self.assertFalse(
            self.limiter.check("10.0.0.1", rule(), now=103.0).allowed
        )
        self.assertTrue(
            self.limiter.check("10.0.0.2", rule(), now=103.0).allowed
        )

    def test_different_rules_are_isolated(self):
        login = rule(limit=2, name="auth_login")
        api = rule(limit=10, name="api_general")
        self.limiter.check("10.0.0.1", login, now=100.0)
        self.limiter.check("10.0.0.1", login, now=101.0)
        self.assertFalse(self.limiter.check("10.0.0.1", login, now=102.0).allowed)
        self.assertTrue(self.limiter.check("10.0.0.1", api, now=102.0).allowed)

    def test_memory_is_bounded_by_limit(self):
        for index in range(3):
            self.limiter.check("10.0.0.1", rule(), now=100.0 + index)
        # Наступні відхилені запити не додаються у deque.
        for index in range(20):
            self.limiter.check("10.0.0.1", rule(), now=103.0 + index * 0.1)
        stats = self.limiter.stats()
        self.assertEqual(stats["events_in_window"], 3)

    def test_reset_clears_state(self):
        self.limiter.check("10.0.0.1", rule(), now=100.0)
        self.limiter.reset()
        stats = self.limiter.stats()
        self.assertEqual(stats["tracked_keys"], 0)
        self.assertEqual(stats["total_allowed"], 0)
        self.assertEqual(stats["total_limited"], 0)

    def test_stale_keys_are_pruned_when_max_keys_exceeded(self):
        limiter = SlidingWindowRateLimiter(max_keys=2, key_ttl_seconds=10)
        limiter.check("10.0.0.1", rule(), now=100.0)
        limiter.check("10.0.0.2", rule(), now=101.0)
        limiter.check("10.0.0.3", rule(), now=102.0)
        self.assertLessEqual(limiter.stats()["tracked_keys"], 2)


if __name__ == "__main__":
    unittest.main()
