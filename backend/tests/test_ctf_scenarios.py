"""
Comprehensive automated test suite for BinExplain from a CTF player's perspective.
"""
import io
import os
import sys
import tempfile
import pytest
from fastapi.testclient import TestClient

# Set dummy values for all API keys so imports don't crash on CI
os.environ.setdefault("ANTHROPIC_API_KEY", "test-key-not-real")
os.environ.setdefault("OPENAI_API_KEY", "test-key-not-real")
os.environ.setdefault("GROQ_API_KEY", "test-key-not-real")
os.environ.setdefault("GEMINI_API_KEY", "test-key-not-real")
os.environ.setdefault("OPENROUTER_API_KEY", "test-key-not-real")
os.environ.setdefault("VIRUSTOTAL_API_KEY", "test-key-not-real")
os.environ.setdefault("ALLOWED_ORIGINS", "http://localhost:5173")
os.environ.setdefault("SENTRY_DSN", "")
os.environ.setdefault("KB_PERSISTENT", "false")

# ── Import the app and core functions ──────────────────────────────────
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from main import (
    app,
    detect_ctf_category,
    detect_patterns,
    detect_flags,
    generate_pwn_template,
)

client = TestClient(app)

# ── Minimal ELF headers for testing ───────────────────────────────────
# e_ident[4] = 1 for 32-bit, 2 for 64-bit
ELF_32 = b"\x7fELF\x01\x01\x01\x00" + b"\x00" * 8 + b"\x02\x00\x03\x00" + b"\x01\x00\x00\x00" + b"\x00" * 200
ELF_64 = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8 + b"\x02\x00\x3e\x00" + b"\x01\x00\x00\x00" + b"\x00" * 200

def _make_password_zip(password: str, filename: str, content: bytes) -> bytes:
    import pyzipper
    buf = io.BytesIO()
    with pyzipper.AESZipFile(
        buf, "w",
        compression=pyzipper.ZIP_DEFLATED,
        encryption=pyzipper.WZ_AES,
    ) as zf:
        zf.setpassword(password.encode("utf-8"))
        zf.writestr(filename, content)
    return buf.getvalue()


# ═══════════════════════════════════════════════════════════════════════
# 1. File Type Tests
# ═══════════════════════════════════════════════════════════════════════
class TestFileTypeScenarios:
    def test_upload_elf_32bit(self):
        response = client.post("/analyze", files={"file": ("test32.elf", ELF_32)})
        assert response.status_code == 200
        assert response.json()["filename"] == "test32.elf"

    def test_upload_elf_64bit(self):
        response = client.post("/analyze", files={"file": ("test64.elf", ELF_64)})
        assert response.status_code == 200
        assert response.json()["filename"] == "test64.elf"

    def test_upload_extensionless_binary(self):
        response = client.post("/analyze", files={"file": ("mybinary", ELF_64)})
        assert response.status_code == 200
        assert response.json()["detected_type"] in ["ELF", ""]

    def test_upload_zip_multiple_binaries(self):
        import zipfile
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("bin1.elf", ELF_64)
            zf.writestr("bin2.elf", ELF_32)
        
        response = client.post("/analyze", files={"file": ("test.zip", buf.getvalue())})
        assert response.status_code == 200
        data = response.json()
        assert data["archive"] == "test.zip"
        assert len(data["results"]) == 2

    def test_upload_password_protected_zip(self):
        try:
            import pyzipper
        except ImportError:
            pytest.skip("pyzipper not installed")
            
        content = _make_password_zip("secret", "test.elf", ELF_64)
        response = client.post("/analyze", files={"file": ("protected.zip", content)})
        assert response.status_code == 422
        assert response.json()["error_code"] == "password_required"
        
        response = client.post("/analyze", files={"file": ("protected.zip", content)}, data={"password": "secret"})
        assert response.status_code == 200

    def test_upload_wrong_file_type(self):
        response = client.post("/analyze", files={"file": ("image.jpg", b"fake jpeg content")})
        assert response.status_code == 400

    def test_upload_file_over_5mb(self):
        large_content = b"\x00" * (5 * 1024 * 1024 + 1)
        response = client.post("/analyze", files={"file": ("large.elf", large_content)})
        assert response.status_code == 413

    def test_upload_empty_file(self):
        response = client.post("/analyze", files={"file": ("empty.elf", b"")})
        assert response.status_code == 400


# ═══════════════════════════════════════════════════════════════════════
# 2. CTF Category Detection Tests
# ═══════════════════════════════════════════════════════════════════════
class TestCTFCategoryDetection:
    def test_ret2win_detected(self):
        patterns = {"dangerous_functions": ["gets"], "win_conditions": ["you win"]}
        checksec = {"pie": False, "nx": True}
        cat = detect_ctf_category(patterns, checksec, ["win()"], {})
        assert cat["category"] in ["ret2win", "ret2libc"]

    def test_format_string_detected(self):
        patterns = {}
        checksec = {"canary": False}
        fmt = {"vulnerable": True, "details": ["printf(buf)"]}
        cat = detect_ctf_category(patterns, checksec, [], fmt)
        assert cat["category"] == "format_string"

    def test_heap_exploitation_detected(self):
        patterns = {"memory_functions": ["malloc", "free"], "menu_driven": ["1) Add"]}
        checksec = {}
        strings = ["malloc(0x10)", "free(ptr)"]
        cat = detect_ctf_category(patterns, checksec, strings, {})
        assert cat["category"] == "heap_exploitation"

    def test_rop_chain_detected(self):
        patterns = {"dangerous_functions": ["gets"]}
        checksec = {"nx": True, "pie": False}
        rop = ["pop rdi; ret", "pop rsi; ret", "pop rdx; ret", "ret"]
        cat = detect_ctf_category(patterns, checksec, [], {}, rop_gadgets=rop)
        assert cat["category"] == "rop_chain"

    def test_shellcode_detected(self):
        patterns = {"dangerous_functions": ["gets"]}
        checksec = {"nx": False}
        cat = detect_ctf_category(patterns, checksec, [], {})
        assert cat["category"] == "shellcode"


# ═══════════════════════════════════════════════════════════════════════
# 3. Security Protection Tests
# ═══════════════════════════════════════════════════════════════════════
class TestSecurityProtections:
    def test_checksec_keys_present(self):
        response = client.post("/analyze", files={"file": ("test.elf", ELF_64)})
        data = response.json()
        assert "checksec" in data
        assert "canary" in data["checksec"]
        assert "nx" in data["checksec"]
        assert "pie" in data["checksec"]
        assert "relro" in data["checksec"]


# ═══════════════════════════════════════════════════════════════════════
# 4. Pattern Detection Tests
# ═══════════════════════════════════════════════════════════════════════
class TestPatternDetection:
    def test_gets_dangerous_function(self):
        res = detect_patterns(["gets", "main"])
        assert "dangerous_functions" in res
        assert "gets" in res["dangerous_functions"]

    def test_flag_reads(self):
        res = detect_patterns(["./flag.txt", "open"])
        assert "flag_reads" in res

    def test_memory_functions(self):
        res = detect_patterns(["malloc", "free", "puts"])
        assert "memory_functions" in res

    def test_stack_protection(self):
        res = detect_patterns(["__stack_chk_fail"])
        assert "stack_protection" in res

    def test_menu_driven(self):
        res = detect_patterns(["1) Add", "2) Edit", "Choice:"])
        assert "menu_driven" in res


# ═══════════════════════════════════════════════════════════════════════
# 5. Flag Detection Tests
# ═══════════════════════════════════════════════════════════════════════
class TestFlagDetection:
    def test_flag_test123(self):
        assert "flag{test123}" in detect_flags(["flag{test123}"])

    def test_picoctf_hello(self):
        assert "picoCTF{hello}" in detect_flags(["picoCTF{hello}"])

    def test_htb_test(self):
        assert "HTB{test}" in detect_flags(["HTB{test}"])

    def test_no_flags(self):
        assert detect_flags(["just", "some", "strings"]) == []


# ═══════════════════════════════════════════════════════════════════════
# 6. AI Features Tests
# ═══════════════════════════════════════════════════════════════════════
class TestAIFeatures:
    def test_chat_endpoint_context(self):
        payload = {
            "messages": [{"role": "user", "content": "What is this?"}],
            "context": "Binary: test.elf\nCTF Category: ret2win"
        }
        response = client.post("/chat", json=payload)
        assert response.status_code in [200, 503, 429]

    def test_analyze_code_c_gets(self):
        code = "void main() { char buf[64]; gets(buf); }"
        response = client.post("/analyze-code", json={"code": code, "filename": "vuln.c"})
        assert response.status_code in [200, 429]
        if response.status_code == 200:
            data = response.json()
            assert "vulnerabilities" in data
            assert any("buffer_overflow" in str(v.get("type", "")).lower() for v in data.get("vulnerabilities", []))

    def test_analyze_code_python_eval(self):
        code = "x = eval(input('Enter something: '))"
        response = client.post("/analyze-code", json={"code": code, "filename": "script.py"})
        assert response.status_code in [200, 429]
        if response.status_code == 200:
            data = response.json()
            assert any("command_injection" in str(v.get("type", "")).lower() or "code_injection" in str(v.get("type", "")).lower() for v in data.get("vulnerabilities", []))

    def test_explain_command(self):
        payload = {"command": "checksec ./binary", "context": "Context"}
        response = client.post("/explain-command", json=payload)
        assert response.status_code in [200, 503, 429]

    def test_analyze_image_fallback(self):
        response = client.post("/analyze-image", files={"file": ("test.png", b"invalid_png_magic")})
        assert response.status_code == 400


# ═══════════════════════════════════════════════════════════════════════
# 7. Pwntools Template Tests
# ═══════════════════════════════════════════════════════════════════════
class TestPwntoolsTemplate:
    def test_32bit_template(self):
        checksec = {"arch": "i386"}
        tpl = generate_pwn_template("test.elf", ELF_32, checksec, {}, [])
        assert "context.arch = 'i386'" in tpl or "context.binary = elf" in tpl

    def test_64bit_template(self):
        checksec = {"arch": "amd64"}
        tpl = generate_pwn_template("test.elf", ELF_64, checksec, {}, [])
        assert "context.arch = 'amd64'" in tpl or "context.binary = elf" in tpl

    def test_no_pie_template(self):
        checksec = {"pie": False}
        tpl = generate_pwn_template("test.elf", ELF_64, checksec, {}, [])
        assert "PIE is disabled" in tpl

    def test_overflow_offset_template(self):
        offset_hint = {"likely_offset": 72}
        tpl = generate_pwn_template("test.elf", ELF_64, {}, {}, [], overflow_hint=offset_hint)
        assert "72" in tpl

    def test_rop_gadgets_template(self):
        rop = [{"address": "0x4000", "gadget": "pop rdi; ret"}, {"address": "0x4001", "gadget": "ret"}]
        tpl = generate_pwn_template("test.elf", ELF_64, {}, {}, [], rop_gadgets=rop)
        assert "ROP" in tpl or "pop rdi" in tpl.lower()


# ═══════════════════════════════════════════════════════════════════════
# 8. Rate Limiting Tests
# ═══════════════════════════════════════════════════════════════════════
class TestRateLimiting:
    """Rate limits have been intentionally removed. These tests verify no throttling occurs."""

    def test_analyze_no_rate_limit(self):
        status_codes = []
        for _ in range(12):
            resp = client.post("/analyze", files={"file": ("test.elf", ELF_32)})
            status_codes.append(resp.status_code)
        assert 429 not in status_codes

    def test_chat_no_rate_limit(self):
        payload = {"messages": [{"role": "user", "content": "hi"}], "context": ""}
        status_codes = []
        for _ in range(22):
            resp = client.post("/chat", json=payload)
            status_codes.append(resp.status_code)
        assert 429 not in status_codes

    def test_explain_command_no_rate_limit(self):
        payload = {"command": "ls", "context": ""}
        status_codes = []
        for _ in range(22):
            resp = client.post("/explain-command", json=payload)
            status_codes.append(resp.status_code)
        assert 429 not in status_codes


# ═══════════════════════════════════════════════════════════════════════
# 9. Security Tests
# ═══════════════════════════════════════════════════════════════════════
class TestSecurityMechanisms:
    def test_path_traversal_filename(self):
        response = client.post("/analyze", files={"file": ("../../../etc/passwd", ELF_64)})
        if response.status_code == 200:
            assert "/" not in response.json()["filename"]
            assert "\\" not in response.json()["filename"]

    def test_zip_bomb_protection(self):
        import zipfile
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            for i in range(21):
                zf.writestr(f"file_{i}.elf", ELF_64)
        response = client.post("/analyze", files={"file": ("bomb.zip", buf.getvalue())}, headers={"X-Forwarded-For": "10.0.0.1"})
        assert response.status_code in [400, 429]

    def test_zip_over_10mb(self):
        import zipfile
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("huge.bin", b"0" * (11 * 1024 * 1024))
        response = client.post("/analyze", files={"file": ("large.zip", buf.getvalue())}, headers={"X-Forwarded-For": "10.0.0.2"})
        assert response.status_code in [400, 429]

    def test_chat_history_capped(self):
        messages = [{"role": "user", "content": "hello"}] * 11
        payload = {"messages": messages, "context": ""}
        response = client.post("/chat", json=payload)
        if response.status_code != 429:
            assert response.status_code == 400


# ═══════════════════════════════════════════════════════════════════════
# 10. Source Code Analysis Tests
# ═══════════════════════════════════════════════════════════════════════
class TestSourceCodeAnalysis:
    def test_c_code_gets_template(self):
        code = "void main() { char buf[64]; gets(buf); }"
        response = client.post("/analyze-code", json={"code": code, "filename": "vuln.c"})
        assert response.status_code in [200, 429]
        if response.status_code == 200:
            data = response.json()
            assert "exploit_template" in data
            assert "padding = b\"A\" * 64" in data["exploit_template"] or "64" in data["exploit_template"]

    def test_python_code_eval(self):
        code = "eval(input())"
        response = client.post("/analyze-code", json={"code": code, "filename": "vuln.py"})
        assert response.status_code in [200, 429]
        if response.status_code == 200:
            data = response.json()
            assert any("command_injection" in str(v.get("type", "")).lower() or "code_injection" in str(v.get("type", "")).lower() for v in data.get("vulnerabilities", []))

    def test_c_code_printf(self):
        code = "void main() { char buf[64]; gets(buf); printf(buf); }"
        response = client.post("/analyze-code", json={"code": code, "filename": "vuln.c"})
        assert response.status_code in [200, 429]
        if response.status_code == 200:
            data = response.json()
            assert any("format_string" in str(v.get("type", "")).lower() for v in data.get("vulnerabilities", []))

    def test_code_over_10000_chars(self):
        code = "A" * 10001
        response = client.post("/analyze-code", json={"code": code, "filename": "vuln.c"})
        assert response.status_code == 422

    def test_empty_code(self):
        response = client.post("/analyze-code", json={"code": "", "filename": "vuln.c"})
        assert response.status_code == 422
