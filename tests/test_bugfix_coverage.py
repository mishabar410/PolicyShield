"""Tests for PII date-of-birth validation and idempotency cache eviction."""

from __future__ import annotations

from policyshield.shield.pii import _date_check


class TestDateCheck:
    """Tests for _date_check false-positive prevention."""

    def test_valid_dob_dd_mm_yyyy(self):
        assert _date_check("15/06/1990") is True

    def test_valid_dob_mm_dd_yyyy(self):
        assert _date_check("06-15-1990") is True

    def test_valid_dob_yyyy_mm_dd(self):
        assert _date_check("1990.06.15") is True

    def test_invalid_month_both_gt_12(self):
        # 25/13/2000 — both non-year parts > 12, neither can be month
        assert _date_check("25/13/2000") is False

    def test_invalid_day_gt_31(self):
        assert _date_check("32/06/2000") is False

    def test_invalid_year_too_old(self):
        assert _date_check("15/06/1800") is False

    def test_invalid_year_too_future(self):
        assert _date_check("15/06/2200") is False

    def test_version_number_rejected(self):
        """Version-like strings shouldn't match as DoB."""
        # 01.02.2024 is valid-looking, should still pass (ambiguous month/day)
        assert _date_check("01.02.2024") is True

    def test_invalid_format_too_few_parts(self):
        assert _date_check("15-06") is False

    def test_invalid_format_non_numeric(self):
        assert _date_check("ab/cd/efgh") is False

    def test_ambiguous_short_date_accepted(self):
        # All parts ≤ 31, no 4-digit year → ambiguous, accepted
        assert _date_check("12/06/25") is True


class TestIdempotencyCacheEviction:
    """Tests for periodic stale entry eviction in IdempotencyCache."""

    def test_stale_entries_evicted_after_n_inserts(self):
        from policyshield.server.idempotency import IdempotencyCache

        cache = IdempotencyCache(max_size=1000, ttl=0.001)  # very short TTL
        cache._EVICT_EVERY_N = 5  # evict every 5 inserts for testing

        # Insert some entries
        for i in range(3):
            cache.set(f"key-{i}", {"result": i})

        import time

        time.sleep(0.01)  # Let entries expire

        # Insert 5 more to trigger eviction
        for i in range(3, 8):
            cache.set(f"key-{i}", {"result": i})

        # Old entries should be evicted
        assert cache.get("key-0") is None
        assert cache.get("key-1") is None
        assert cache.get("key-2") is None

    def test_fresh_entries_not_evicted(self):
        from policyshield.server.idempotency import IdempotencyCache

        cache = IdempotencyCache(max_size=1000, ttl=300.0)
        cache._EVICT_EVERY_N = 3

        for i in range(4):
            cache.set(f"key-{i}", {"result": i})

        # All entries should still be accessible
        for i in range(4):
            assert cache.get(f"key-{i}") == {"result": i}
