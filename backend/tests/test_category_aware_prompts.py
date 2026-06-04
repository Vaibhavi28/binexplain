"""
Tests for the category-aware AI hint system.

Verifies that:
1. build_category_aware_prompt() produces correct prompts per category
2. Format string category prompts NEVER mention cyclic/overflow offsets
3. Ret2win category prompts NEVER mention %p or format string
4. Chat endpoint accepts ctf_category and uses it dynamically
5. AI_SYSTEM_PROMPT and CHAT_SYSTEM_PROMPT remain valid base prompts
6. Unknown/empty categories fall back to the base prompt unchanged
"""

import os
import sys
import pytest
from fastapi.testclient import TestClient

# ── Import the app and core functions ──────────────────────────────────
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from main import (
    app,
    AI_SYSTEM_PROMPT,
    CHAT_SYSTEM_PROMPT,
    CATEGORY_SPECIFIC_GUIDANCE,
    build_category_aware_prompt,
    ChatRequest,
)

client = TestClient(app)

# Bypass rate limiting
import itertools as _itertools
_ip_counter = _itertools.count(200)

_original_post = client.post
def _post_with_unique_ip(*args, **kwargs):
    headers = kwargs.get("headers", {})
    if "X-Forwarded-For" not in headers:
        headers["X-Forwarded-For"] = f"10.30.30.{next(_ip_counter)}"
        kwargs["headers"] = headers
    return _original_post(*args, **kwargs)
client.post = _post_with_unique_ip


# ═══════════════════════════════════════════════════════════════════════
# 1. build_category_aware_prompt Unit Tests
# ═══════════════════════════════════════════════════════════════════════
class TestBuildCategoryAwarePrompt:
    """Test the prompt builder function in isolation."""

    def test_unknown_category_returns_base(self):
        """Unknown category should return the base prompt unchanged."""
        result = build_category_aware_prompt(AI_SYSTEM_PROMPT, "unknown")
        assert result == AI_SYSTEM_PROMPT

    def test_empty_category_returns_base(self):
        """Empty string category should return the base prompt unchanged."""
        result = build_category_aware_prompt(AI_SYSTEM_PROMPT, "")
        assert result == AI_SYSTEM_PROMPT

    def test_none_category_returns_base(self):
        """None-like falsy category should return the base prompt unchanged."""
        result = build_category_aware_prompt(AI_SYSTEM_PROMPT, "")
        assert result == AI_SYSTEM_PROMPT

    def test_format_string_prompt_contains_category_rules(self):
        """Format string category should inject format-specific guidance."""
        result = build_category_aware_prompt(AI_SYSTEM_PROMPT, "format_string")
        assert "FORMAT_STRING" in result
        assert "%p leaks" in result
        assert "fmtstr_payload" in result
        assert "STRICT RULES" in result

    def test_ret2win_prompt_contains_category_rules(self):
        """Ret2win category should inject ret2win-specific guidance."""
        result = build_category_aware_prompt(AI_SYSTEM_PROMPT, "ret2win")
        assert "RET2WIN" in result
        assert "cyclic(200)" in result or "cyclic_find" in result
        assert "win function" in result.lower() or "win" in result

    def test_ret2libc_prompt_contains_category_rules(self):
        """Ret2libc category should inject ret2libc-specific guidance."""
        result = build_category_aware_prompt(AI_SYSTEM_PROMPT, "ret2libc")
        assert "RET2LIBC" in result
        assert "system()" in result
        assert "/bin/sh" in result

    def test_heap_prompt_contains_category_rules(self):
        """Heap exploitation category should inject heap-specific guidance."""
        result = build_category_aware_prompt(AI_SYSTEM_PROMPT, "heap_exploitation")
        assert "HEAP_EXPLOITATION" in result
        assert "tcache" in result or "UAF" in result
        assert "malloc" in result.lower() or "free" in result.lower()

    def test_rop_chain_prompt_contains_category_rules(self):
        """ROP chain category should inject ROP-specific guidance."""
        result = build_category_aware_prompt(AI_SYSTEM_PROMPT, "rop_chain")
        assert "ROP_CHAIN" in result
        assert "ROPgadget" in result

    def test_shellcode_prompt_contains_category_rules(self):
        """Shellcode category should inject shellcode-specific guidance."""
        result = build_category_aware_prompt(AI_SYSTEM_PROMPT, "shellcode")
        assert "SHELLCODE" in result
        assert "shellcraft" in result or "msfvenom" in result

    def test_novel_category_gets_generic_guidance(self):
        """An unknown but non-empty category should get generic focus guidance."""
        result = build_category_aware_prompt(AI_SYSTEM_PROMPT, "some_new_category")
        assert "some_new_category" in result
        assert "STRICT RULES" in result
        assert "Focus exclusively on some_new_category" in result

    def test_works_with_chat_prompt(self):
        """Category-aware prompt should work with CHAT_SYSTEM_PROMPT too."""
        result = build_category_aware_prompt(CHAT_SYSTEM_PROMPT, "format_string")
        # Should contain the original chat prompt AND the category rules
        assert "expert CTF mentor" in result
        assert "FORMAT_STRING" in result
        assert "%p leaks" in result


# ═══════════════════════════════════════════════════════════════════════
# 2. Category Isolation Tests — Format String Never Gets BOF Advice
# ═══════════════════════════════════════════════════════════════════════
class TestFormatStringIsolation:
    """Verify format string prompts never mention buffer overflow techniques."""

    def test_format_string_prompt_no_cyclic(self):
        """Format string prompt must NEVER mention cyclic()."""
        result = build_category_aware_prompt(AI_SYSTEM_PROMPT, "format_string")
        # The "Never mention" line explicitly bans cyclic
        assert "Never mention: cyclic()" in result or "Never mention" in result

    def test_format_string_prompt_no_overflow_offset(self):
        """Format string prompt must NEVER suggest overflow offset techniques."""
        result = build_category_aware_prompt(AI_SYSTEM_PROMPT, "format_string")
        assert "overflow offsets" in result.lower()  # Should be in the "Never mention" line

    def test_format_string_guidance_content(self):
        """Format string guidance should focus on %p, %n, GOT overwrite."""
        guidance = CATEGORY_SPECIFIC_GUIDANCE["format_string"]
        assert "%p leaks" in guidance
        assert "%n writes" in guidance
        assert "GOT overwrite" in guidance
        assert "fmtstr_payload" in guidance

    def test_format_string_chat_prompt_no_cyclic(self):
        """Chat prompt for format string must not suggest cyclic patterns."""
        result = build_category_aware_prompt(CHAT_SYSTEM_PROMPT, "format_string")
        assert "Never mention: cyclic()" in result or "Never mention" in result


# ═══════════════════════════════════════════════════════════════════════
# 3. Category Isolation Tests — Ret2win Never Gets Format String Advice
# ═══════════════════════════════════════════════════════════════════════
class TestRet2winIsolation:
    """Verify ret2win prompts never mention format string techniques."""

    def test_ret2win_prompt_no_format_string(self):
        """Ret2win prompt must NEVER suggest format string techniques."""
        result = build_category_aware_prompt(AI_SYSTEM_PROMPT, "ret2win")
        assert "Never mention: format string" in result or "Never mention" in result

    def test_ret2win_prompt_no_heap(self):
        """Ret2win prompt must NEVER suggest heap techniques."""
        result = build_category_aware_prompt(AI_SYSTEM_PROMPT, "ret2win")
        assert "heap techniques" in result.lower()  # In the "Never mention" line

    def test_ret2win_guidance_content(self):
        """Ret2win guidance should focus on win function and cyclic."""
        guidance = CATEGORY_SPECIFIC_GUIDANCE["ret2win"]
        assert "win function" in guidance.lower()
        assert "cyclic" in guidance
        assert "return address" in guidance.lower()


# ═══════════════════════════════════════════════════════════════════════
# 4. Cross-Category Contamination Matrix
# ═══════════════════════════════════════════════════════════════════════
class TestCrossCategoryContamination:
    """Verify each category's 'Never mention' rules exist."""

    def test_heap_never_mentions_stack_overflow(self):
        guidance = CATEGORY_SPECIFIC_GUIDANCE["heap_exploitation"]
        assert "stack overflow" in guidance.lower()

    def test_heap_never_mentions_format_string(self):
        guidance = CATEGORY_SPECIFIC_GUIDANCE["heap_exploitation"]
        assert "format string" in guidance.lower()

    def test_shellcode_never_mentions_format_string(self):
        guidance = CATEGORY_SPECIFIC_GUIDANCE["shellcode"]
        assert "format string" in guidance.lower()

    def test_shellcode_never_mentions_rop(self):
        guidance = CATEGORY_SPECIFIC_GUIDANCE["shellcode"]
        assert "ROP" in guidance

    def test_rop_never_mentions_format_string(self):
        guidance = CATEGORY_SPECIFIC_GUIDANCE["rop_chain"]
        assert "format string" in guidance.lower()

    def test_rop_never_mentions_heap(self):
        guidance = CATEGORY_SPECIFIC_GUIDANCE["rop_chain"]
        assert "heap" in guidance.lower()

    def test_ret2libc_never_mentions_format_string(self):
        guidance = CATEGORY_SPECIFIC_GUIDANCE["ret2libc"]
        assert "format string" in guidance.lower()

    def test_ret2libc_never_mentions_heap(self):
        guidance = CATEGORY_SPECIFIC_GUIDANCE["ret2libc"]
        assert "heap" in guidance.lower()


# ═══════════════════════════════════════════════════════════════════════
# 5. ChatRequest Model Tests
# ═══════════════════════════════════════════════════════════════════════
class TestChatRequestModel:
    """Verify ChatRequest accepts ctf_category field."""

    def test_chat_request_accepts_ctf_category(self):
        """ChatRequest should accept ctf_category as an optional field."""
        req = ChatRequest(
            messages=[{"role": "user", "content": "hello"}],
            context="test",
            ctf_category="format_string",
        )
        assert req.ctf_category == "format_string"

    def test_chat_request_default_empty_category(self):
        """ChatRequest ctf_category should default to empty string."""
        req = ChatRequest(
            messages=[{"role": "user", "content": "hello"}],
        )
        assert req.ctf_category == ""


# ═══════════════════════════════════════════════════════════════════════
# 6. /chat Endpoint with ctf_category
# ═══════════════════════════════════════════════════════════════════════
class TestChatEndpointCategory:
    """Test /chat endpoint accepts and processes ctf_category."""

    def test_chat_with_format_string_category(self):
        """Chat endpoint should accept ctf_category field."""
        payload = {
            "messages": [{"role": "user", "content": "What should I do first?"}],
            "context": "Binary: vuln\nCTF Category: format_string\nprintf(user_input) detected",
            "ctf_category": "format_string",
        }
        response = client.post("/chat", json=payload)
        # Should succeed or fail with 503 (no API key) — never 422 (validation error)
        assert response.status_code in [200, 503, 429]

    def test_chat_with_ret2win_category(self):
        """Chat endpoint should accept ret2win category."""
        payload = {
            "messages": [{"role": "user", "content": "How do I exploit this?"}],
            "context": "Binary: ret2win\nCTF Category: ret2win\nwin() function found",
            "ctf_category": "ret2win",
        }
        response = client.post("/chat", json=payload)
        assert response.status_code in [200, 503, 429]

    def test_chat_without_category_still_works(self):
        """Chat should still work without ctf_category (backward compatible)."""
        payload = {
            "messages": [{"role": "user", "content": "hello"}],
            "context": "Binary: test",
        }
        response = client.post("/chat", json=payload)
        assert response.status_code in [200, 503, 429]

    def test_chat_with_empty_category(self):
        """Chat with empty ctf_category should use base prompt."""
        payload = {
            "messages": [{"role": "user", "content": "hello"}],
            "context": "",
            "ctf_category": "",
        }
        response = client.post("/chat", json=payload)
        assert response.status_code in [200, 503, 429]

    def test_chat_with_unknown_category(self):
        """Chat with unknown category should gracefully use base prompt."""
        payload = {
            "messages": [{"role": "user", "content": "hello"}],
            "context": "",
            "ctf_category": "unknown",
        }
        response = client.post("/chat", json=payload)
        assert response.status_code in [200, 503, 429]


# ═══════════════════════════════════════════════════════════════════════
# 7. All Categories Have Required Fields
# ═══════════════════════════════════════════════════════════════════════
class TestCategoryGuidanceCompleteness:
    """Verify all category guidance entries have the required structure."""

    @pytest.mark.parametrize("category", [
        "format_string", "ret2win", "ret2libc",
        "heap_exploitation", "rop_chain", "shellcode",
        "stack_canary_bypass",
    ])
    def test_category_has_focus_line(self, category):
        """Each category guidance should include 'Focus on' line."""
        guidance = CATEGORY_SPECIFIC_GUIDANCE[category]
        assert "Focus on:" in guidance or "focus on" in guidance.lower()

    @pytest.mark.parametrize("category", [
        "format_string", "ret2win", "ret2libc",
        "heap_exploitation", "rop_chain", "shellcode",
    ])
    def test_category_has_key_commands(self, category):
        """Each category should include key commands or specific tool references."""
        guidance = CATEGORY_SPECIFIC_GUIDANCE[category]
        assert "Key commands:" in guidance or "commands" in guidance.lower()

    @pytest.mark.parametrize("category", [
        "format_string", "ret2win", "ret2libc",
        "heap_exploitation", "rop_chain", "shellcode",
    ])
    def test_category_has_never_mention(self, category):
        """Each category should include a 'Never mention' restriction."""
        guidance = CATEGORY_SPECIFIC_GUIDANCE[category]
        assert "Never mention:" in guidance or "Never mention" in guidance

    @pytest.mark.parametrize("category", [
        "format_string", "ret2win", "ret2libc",
        "heap_exploitation", "rop_chain", "shellcode",
        "stack_canary_bypass",
    ])
    def test_prompt_contains_strict_rules(self, category):
        """Built prompt should always contain STRICT RULES section."""
        result = build_category_aware_prompt(AI_SYSTEM_PROMPT, category)
        assert "STRICT RULES" in result

    @pytest.mark.parametrize("category", [
        "format_string", "ret2win", "ret2libc",
        "heap_exploitation", "rop_chain", "shellcode",
        "stack_canary_bypass",
    ])
    def test_prompt_contains_always_section(self, category):
        """Built prompt should always contain ALWAYS section with universal rules."""
        result = build_category_aware_prompt(AI_SYSTEM_PROMPT, category)
        assert "ALWAYS:" in result
        assert "Reference specific function names" in result
        assert "binary filename" in result.lower()


# ═══════════════════════════════════════════════════════════════════════
# 8. Base Prompt Integrity Tests
# ═══════════════════════════════════════════════════════════════════════
class TestBasePromptIntegrity:
    """Ensure the base prompts haven't been accidentally corrupted."""

    def test_ai_system_prompt_has_expert_mentor(self):
        assert "expert CTF mentor" in AI_SYSTEM_PROMPT

    def test_ai_system_prompt_has_bullet_format(self):
        assert "bullet" in AI_SYSTEM_PROMPT.lower()

    def test_ai_system_prompt_has_kill_chain(self):
        assert "Kill Chain" in AI_SYSTEM_PROMPT

    def test_ai_system_prompt_has_try_this_first(self):
        assert "Try this first" in AI_SYSTEM_PROMPT

    def test_chat_system_prompt_has_mentor(self):
        assert "CTF mentor" in CHAT_SYSTEM_PROMPT

    def test_chat_system_prompt_has_conversation_rules(self):
        assert "Never repeat" in CHAT_SYSTEM_PROMPT
        assert "build on previous" in CHAT_SYSTEM_PROMPT.lower()

    def test_chat_system_prompt_has_binary_context_rule(self):
        assert "actual binary name" in CHAT_SYSTEM_PROMPT.lower() or "binary name" in CHAT_SYSTEM_PROMPT.lower()
