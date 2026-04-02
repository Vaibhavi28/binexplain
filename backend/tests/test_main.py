"""
Tests for BinExplain backend API and core functions.

Run with:  pytest tests/ -v
"""
import io
import pytest
from fastapi.testclient import TestClient

# ── Import the app and core functions ──────────────────────────────────
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from main import (
    app,
    detect_flags,
    detect_patterns,
    calculate_risk_score,
)

client = TestClient(app)

# ── Minimal ELF header for testing (64-bit x86_64 stub) ───────────────
MINIMAL_ELF = (
    b"\x7fELF"
    + b"\x02"
    + b"\x01"
    + b"\x01"
    + b"\x00" * 9
    + b"\x02\x00"
    + b"\x3e\x00"
    + b"\x01\x00\x00\x00"
    + b"\x00" * 200
)


# ═══════════════════════════════════════════════════════════════════════
# API Endpoint Tests
# ═══════════════════════════════════════════════════════════════════════

class TestHealthEndpoint:
    """Test the /health endpoint."""

    def test_health_returns_200(self):
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"


class TestAnalyzeValidation:
    """Test /analyze input validation."""

    def test_rejects_file_over_5mb(self):
        """Files larger than 5MB should be rejected."""
        large_content = b"\x00" * (5 * 1024 * 1024 + 1)  # 5MB + 1 byte
        response = client.post(
            "/analyze",
            files={"file": ("large.elf", large_content)},
        )
        # Server returns 413 (Request Entity Too Large) for oversized files
        assert response.status_code == 413

    def test_rejects_wrong_file_extension(self):
        """Non-binary file extensions should be rejected."""
        response = client.post(
            "/analyze",
            files={"file": ("document.pdf", b"fake pdf content")},
        )
        assert response.status_code == 400
        detail = response.json()["detail"].lower()
        assert "extension" in detail or "not allowed" in detail or "unsupported" in detail

    def test_rejects_empty_file(self):
        """Empty files should be rejected."""
        response = client.post(
            "/analyze",
            files={"file": ("empty.elf", b"")},
        )
        assert response.status_code == 400
        assert "empty" in response.json()["detail"].lower()

    def test_accepts_valid_elf(self):
        """A valid ELF-ish file with the right extension should be accepted."""
        response = client.post(
            "/analyze",
            files={"file": ("test.elf", MINIMAL_ELF)},
        )
        # Should succeed (200) or at least not be a validation error (400)
        assert response.status_code == 200
        data = response.json()
        assert "filename" in data
        assert data["filename"] == "test.elf"

    def test_accepts_extensionless_file(self):
        """Extensionless files should be accepted (auto-detect by magic bytes)."""
        response = client.post(
            "/analyze",
            files={"file": ("mybinary", MINIMAL_ELF)},
        )
        assert response.status_code == 200


# ═══════════════════════════════════════════════════════════════════════
# Core Function Tests
# ═══════════════════════════════════════════════════════════════════════

class TestDetectFlags:
    """Test the detect_flags() function."""

    def test_finds_standard_flag_format(self):
        strings = ["some random text", "flag{this_is_a_test_flag}", "more text"]
        result = detect_flags(strings)
        assert len(result) >= 1
        assert "flag{this_is_a_test_flag}" in result

    def test_finds_picoctf_format(self):
        strings = ["picoCTF{example_flag_123}"]
        result = detect_flags(strings)
        assert len(result) >= 1
        assert "picoCTF{example_flag_123}" in result

    def test_finds_htb_format(self):
        strings = ["normal text", "HTB{hack_the_box_flag}", "end"]
        result = detect_flags(strings)
        assert any("HTB{" in f for f in result)

    def test_finds_generic_format(self):
        """Should match generic WORD{...} patterns."""
        strings = ["DUCTF{some_flag}"]
        result = detect_flags(strings)
        assert len(result) >= 1

    def test_no_flags_returns_empty(self):
        strings = ["printf", "hello world", "no flags here"]
        result = detect_flags(strings)
        assert result == []

    def test_deduplicates_flags(self):
        strings = ["flag{dup}", "flag{dup}", "flag{dup}"]
        result = detect_flags(strings)
        assert result.count("flag{dup}") == 1


class TestDetectPatterns:
    """Test the detect_patterns() function."""

    def test_detects_dangerous_functions(self):
        strings = ["gets", "strcpy", "system"]
        result = detect_patterns(strings)
        assert "dangerous_functions" in result
        assert len(result["dangerous_functions"]) >= 1

    def test_detects_flag_reads(self):
        strings = ["flag.txt", "open_flag"]
        result = detect_patterns(strings)
        assert "flag_reads" in result

    def test_detects_memory_functions(self):
        strings = ["malloc", "free"]
        result = detect_patterns(strings)
        assert "memory_functions" in result

    def test_detects_stack_protection(self):
        strings = ["__stack_chk_fail"]
        result = detect_patterns(strings)
        assert "stack_protection" in result

    def test_detects_glibc_versions(self):
        strings = ["GLIBC_2.34"]
        result = detect_patterns(strings)
        assert "glibc_versions" in result

    def test_empty_strings_returns_empty(self):
        result = detect_patterns([])
        assert result == {}

    def test_no_patterns_returns_empty(self):
        strings = ["hello", "world", "nothing_interesting_123"]
        result = detect_patterns(strings)
        # Should be empty because none of the pattern categories match
        assert "dangerous_functions" not in result


class TestCalculateRiskScore:
    """Test the calculate_risk_score() function."""

    def test_clean_with_no_patterns(self):
        result = calculate_risk_score({}, [])
        # Baseline score may include a default value
        assert result["score"] >= 0
        assert result["level"] in ("Clean", "Warning")
        assert isinstance(result["reasons"], list)

    def test_warning_with_dangerous_functions(self):
        patterns = {"dangerous_functions": ["gets"]}
        result = calculate_risk_score(patterns, [])
        assert result["score"] > 0
        assert result["level"] in ("Warning", "Critical")

    def test_higher_score_with_flags(self):
        patterns = {"dangerous_functions": ["gets", "strcpy"]}
        flags = ["flag{test}"]
        result = calculate_risk_score(patterns, flags)
        assert result["score"] > 0
        assert len(result["reasons"]) >= 1

    def test_critical_with_many_patterns(self):
        patterns = {
            "dangerous_functions": ["gets", "strcpy", "system"],
            "flag_reads": ["flag.txt"],
            "memory_functions": ["malloc", "free"],
        }
        flags = ["flag{critical_test}"]
        result = calculate_risk_score(patterns, flags)
        assert result["score"] >= 50
        assert result["level"] in ("Warning", "Critical")

    def test_returns_expected_keys(self):
        result = calculate_risk_score({}, [])
        assert "score" in result
        assert "level" in result
        assert "reasons" in result
        assert isinstance(result["score"], int)
        assert isinstance(result["level"], str)
        assert isinstance(result["reasons"], list)
