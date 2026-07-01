"""
Tests for Cache Augmented Generation (CAG) — hint_cache module and
the /cache-stats endpoint.

Run with:  pytest tests/ -v
"""

import os
import sys
import tempfile

import pytest

# ── Import path setup ──────────────────────────────────────────────────
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# Point the cache DB to a temporary file so tests don't pollute the real cache
_tmp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
_tmp_db.close()
os.environ["CAG_DB_PATH"] = _tmp_db.name

from cache import hint_cache  # noqa: E402
from main import app  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

client = TestClient(app)

# Bypass rate limiting
import itertools as _itertools

_ip_counter_cag = _itertools.count(1)
_original_post_cag = client.post


def _post_with_unique_ip_cag(*args, **kwargs):
    headers = kwargs.get("headers", {})
    if "X-Forwarded-For" not in headers:
        headers["X-Forwarded-For"] = f"10.99.99.{next(_ip_counter_cag)}"
        kwargs["headers"] = headers
    return _original_post_cag(*args, **kwargs)


client.post = _post_with_unique_ip_cag


# ═══════════════════════════════════════════════════════════════════════
# Test: generate_key
# ═══════════════════════════════════════════════════════════════════════


class TestGenerateKey:
    """Test the deterministic cache-key generation."""

    def test_basic_key(self):
        key = hint_cache.generate_key(
            "format_string",
            {"nx": True, "pie": True, "canary": False},
            ["printf", "gets", "scanf"],
        )
        assert key == "format_string_NX1_PIE1_Canary0_gets_printf_scanf"

    def test_key_normalises_case(self):
        key = hint_cache.generate_key(
            "FORMAT_STRING",
            {"nx": True, "pie": False, "canary": True},
            ["Printf", "GETS"],
        )
        assert key == "format_string_NX1_PIE0_Canary1_gets_printf"

    def test_key_deduplicates_functions(self):
        key = hint_cache.generate_key(
            "ret2win",
            {"nx": True, "pie": False, "canary": False},
            ["gets", "gets", "gets"],
        )
        assert key == "ret2win_NX1_PIE0_Canary0_gets"

    def test_key_takes_top_3_only(self):
        key = hint_cache.generate_key(
            "ret2libc",
            {"nx": True, "pie": False, "canary": False},
            ["alpha", "beta", "gamma", "delta"],
        )
        # sorted: alpha, beta, delta, gamma → top 3 = alpha, beta, delta
        assert key == "ret2libc_NX1_PIE0_Canary0_alpha_beta_delta"

    def test_key_no_dangerous_functions(self):
        key = hint_cache.generate_key(
            "shellcode",
            {"nx": False, "pie": False, "canary": False},
            [],
        )
        assert key == "shellcode_NX0_PIE0_Canary0"

    def test_key_empty_category(self):
        key = hint_cache.generate_key(
            "",
            {"nx": True, "pie": True, "canary": True},
            ["printf"],
        )
        assert key == "unknown_NX1_PIE1_Canary1_printf"

    def test_key_is_deterministic(self):
        """Same inputs must always produce the same key."""
        args = ("heap_exploitation", {"nx": True, "pie": False, "canary": False}, ["malloc", "free"])
        assert hint_cache.generate_key(*args) == hint_cache.generate_key(*args)


# ═══════════════════════════════════════════════════════════════════════
# Test: get / set / clear
# ═══════════════════════════════════════════════════════════════════════


class TestCacheGetSet:
    """Test cache storage and retrieval."""

    def setup_method(self):
        hint_cache.clear()

    def test_miss_returns_none(self):
        assert hint_cache.get("nonexistent_key") is None

    def test_set_then_get(self):
        hint_cache.set("test_key", "some hints", "kill chain text", "ret2win")
        result = hint_cache.get("test_key")
        assert result is not None
        assert result["hints"] == "some hints"
        assert result["kill_chain"] == "kill chain text"
        assert result["category"] == "ret2win"

    def test_hit_count_increments(self):
        hint_cache.set("counter_key", "hints", "", "test")
        # First get → hit_count becomes 1
        hint_cache.get("counter_key")
        # Second get → hit_count becomes 2
        hint_cache.get("counter_key")

        stats = hint_cache.get_stats()
        assert stats["total_hits"] >= 2

    def test_replace_existing_key(self):
        hint_cache.set("replace_key", "old hints", "", "cat1")
        hint_cache.set("replace_key", "new hints", "new kc", "cat2")
        result = hint_cache.get("replace_key")
        assert result["hints"] == "new hints"
        assert result["kill_chain"] == "new kc"
        assert result["category"] == "cat2"

    def test_clear_removes_all(self):
        hint_cache.set("a", "1", "", "")
        hint_cache.set("b", "2", "", "")
        hint_cache.clear()
        assert hint_cache.get("a") is None
        assert hint_cache.get("b") is None


# ═══════════════════════════════════════════════════════════════════════
# Test: get_stats
# ═══════════════════════════════════════════════════════════════════════


class TestCacheStats:
    """Test cache statistics computation."""

    def setup_method(self):
        hint_cache.clear()

    def test_empty_cache_stats(self):
        stats = hint_cache.get_stats()
        assert stats["total_cached"] == 0
        assert stats["total_hits"] == 0
        assert stats["hit_rate"] == 0.0
        assert stats["most_common_categories"] == []

    def test_stats_after_inserts(self):
        hint_cache.set("k1", "h1", "", "ret2win")
        hint_cache.set("k2", "h2", "", "format_string")
        hint_cache.set("k3", "h3", "", "ret2win")

        stats = hint_cache.get_stats()
        assert stats["total_cached"] == 3
        assert stats["total_hits"] == 0

    def test_stats_after_hits(self):
        hint_cache.set("k1", "h1", "", "ret2win")
        hint_cache.get("k1")  # hit +1
        hint_cache.get("k1")  # hit +2

        stats = hint_cache.get_stats()
        assert stats["total_cached"] == 1
        assert stats["total_hits"] == 2
        # hit_rate = hits / (hits + cached) = 2 / (2 + 1) = 66.7%
        assert stats["hit_rate"] == pytest.approx(66.7, abs=0.1)

    def test_most_common_categories(self):
        hint_cache.set("k1", "h1", "", "ret2win")
        hint_cache.set("k2", "h2", "", "ret2win")
        hint_cache.set("k3", "h3", "", "format_string")

        stats = hint_cache.get_stats()
        assert "ret2win" in stats["most_common_categories"]

    def test_stats_returns_expected_keys(self):
        stats = hint_cache.get_stats()
        assert "total_cached" in stats
        assert "total_hits" in stats
        assert "hit_rate" in stats
        assert "most_common_categories" in stats


# ═══════════════════════════════════════════════════════════════════════
# Test: /cache-stats endpoint
# ═══════════════════════════════════════════════════════════════════════


class TestCacheStatsEndpoint:
    """Test the /cache-stats API endpoint."""

    def setup_method(self):
        hint_cache.clear()

    def test_endpoint_returns_200(self):
        response = client.get("/cache-stats")
        assert response.status_code == 200
        data = response.json()
        assert "total_cached" in data
        assert "total_hits" in data
        assert "hit_rate" in data
        assert "most_common_categories" in data

    def test_endpoint_reflects_cache_state(self):
        hint_cache.set("endpoint_test", "hints", "", "rop_chain")
        hint_cache.get("endpoint_test")  # generate a hit

        response = client.get("/cache-stats")
        data = response.json()
        assert data["total_cached"] >= 1
        assert data["total_hits"] >= 1



class TestChatCaching:
    """Test /chat caching, skipping, and response source flags."""

    def setup_method(self):
        hint_cache.clear()

    def test_chat_cache_hit(self):
        key = hint_cache.generate_key("ret2win", {"nx": True, "pie": False, "canary": False}, ["gets"])
        hint_cache.set(key, "This is ret2win — no protections. Your offset is {offset} bytes. Find the win function: nm -a ./{filename} | grep -i win. Then run your template: python3 exploit_{filename_clean}.py.", "kill chain", "ret2win")

        payload = {
            "messages": [{"role": "user", "content": "How do I do this?"}],
            "binary_context": {
                "filename": "vuln.elf",
                "predicted_offset": 64,
                "ctf_category": "ret2win",
                "protections": {
                    "nx": True,
                    "pie": False,
                    "canary": False
                },
                "functions": ["gets"]
            }
        }
        import main
        original_testing = main._is_testing
        main._is_testing = lambda: False
        try:
            response = client.post("/chat", json=payload)
            assert response.status_code == 200
            data = response.json()
            assert data["response_source"] == "cache"
            assert "vuln.elf" in data["response"]
            assert "64" in data["response"]
            assert "vuln" in data["response"]
        finally:
            main._is_testing = original_testing

    def test_chat_cache_skip(self):
        key = hint_cache.generate_key("ret2win", {"nx": True, "pie": False, "canary": False}, ["gets"])
        hint_cache.set(key, "cached hints", "kill chain", "ret2win")

        payload = {
            "messages": [{"role": "user", "content": "I tried but it failed"}],
            "binary_context": {
                "filename": "vuln.elf",
                "predicted_offset": 64,
                "ctf_category": "ret2win",
                "protections": {
                    "nx": True,
                    "pie": False,
                    "canary": False
                },
                "functions": ["gets"]
            }
        }
        import main
        original_testing = main._is_testing
        main._is_testing = lambda: False
        import unittest.mock as mock
        with mock.patch("main._try_groq", return_value="Fresh AI hints"):
            try:
                response = client.post("/chat", json=payload)
                assert response.status_code == 200
                data = response.json()
                assert data["response_source"] == "ai"
                assert data["response"] == "Fresh AI hints"
            finally:
                main._is_testing = original_testing


# ═══════════════════════════════════════════════════════════════════════
# Cleanup
# ═══════════════════════════════════════════════════════════════════════


def teardown_module():
    """Clean up the temporary database file."""
    hint_cache.reset_connection()
    try:
        os.unlink(_tmp_db.name)
    except OSError:
        pass
