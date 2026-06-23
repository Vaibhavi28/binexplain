"""
Tests for ZIP mixed content analysis — binary + source code files.

Verifies that:
1. ZIP with binary + source code → both analyzed, source_code_results returned
2. ZIP with only source code → analyzed, no error
3. ZIP with only binaries → backward compatible, source_code_results is empty
4. Source code file too large → skipped gracefully
5. Source code file limit (3) → excess files skipped
6. Response structure includes all expected keys
7. Frontend-facing fields are correct
"""

import io
import os
import sys
import zipfile
import pytest
from fastapi.testclient import TestClient

# ── Import the app ────────────────────────────────────────────────────
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from main import app

client = TestClient(app)

# Bypass rate limiting
import itertools as _itertools
_ip_counter = _itertools.count(100)

_original_post = client.post
def _post_with_unique_ip(*args, **kwargs):
    headers = kwargs.get("headers", {})
    if "X-Forwarded-For" not in headers:
        headers["X-Forwarded-For"] = f"10.20.20.{next(_ip_counter)}"
        kwargs["headers"] = headers
    return _original_post(*args, **kwargs)
client.post = _post_with_unique_ip


# ── Minimal ELF header for testing ────────────────────────────────────
ELF_64 = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8 + b"\x02\x00\x3e\x00" + b"\x01\x00\x00\x00" + b"\x00" * 200

# ── Sample source code snippets ──────────────────────────────────────
VULN_C_CODE = b"""#include <stdio.h>
#include <string.h>

void win() {
    system("cat flag.txt");
}

int main() {
    char buf[64];
    printf("Enter input: ");
    gets(buf);
    return 0;
}
"""

FMTSTR_C_CODE = b"""#include <stdio.h>

int main() {
    char buf[128];
    fgets(buf, sizeof(buf), stdin);
    printf(buf);
    return 0;
}
"""

PYTHON_EVAL_CODE = b"""import os
user_input = input("Enter: ")
result = eval(user_input)
print(result)
"""


def _make_zip(files: dict[str, bytes]) -> bytes:
    """Create an in-memory ZIP with the given filename->content mapping."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    return buf.getvalue()


# ═══════════════════════════════════════════════════════════════════════
# 1. ZIP with Binary + Source Code
# ═══════════════════════════════════════════════════════════════════════
class TestZipBinaryAndSourceCode:
    """Upload a ZIP with both a binary and source code → both analyzed."""

    def test_binary_and_c_source(self):
        """ZIP with vuln (ELF) + vuln.c → binary + source analyzed."""
        zip_data = _make_zip({"vuln": ELF_64, "vuln.c": VULN_C_CODE})
        response = client.post("/analyze", files={"file": ("challenge.zip", zip_data)})
        assert response.status_code == 200
        data = response.json()

        # Archive metadata
        assert data["archive"] == "challenge.zip"
        assert data["analyzed_count"] >= 1
        assert data["source_code_count"] >= 1

        # Binary results
        assert len(data["results"]) >= 1
        assert data["results"][0]["filename"] == "vuln"

        # Source code results
        assert len(data["source_code_results"]) >= 1
        src = data["source_code_results"][0]
        assert src["filename"] == "vuln.c"
        assert "dangerous_functions" in src
        assert "vulnerabilities" in src

    def test_binary_and_python_source(self):
        """ZIP with binary + Python source → both analyzed."""
        zip_data = _make_zip({"exploit": ELF_64, "solve.py": PYTHON_EVAL_CODE})
        response = client.post("/analyze", files={"file": ("ctf.zip", zip_data)})
        assert response.status_code == 200
        data = response.json()

        assert data["analyzed_count"] >= 1
        assert data["source_code_count"] >= 1
        assert any(s["filename"] == "solve.py" for s in data["source_code_results"])

    def test_binary_and_multiple_sources(self):
        """ZIP with binary + multiple source files → all analyzed (up to cap)."""
        zip_data = _make_zip({
            "vuln": ELF_64,
            "vuln.c": VULN_C_CODE,
            "fmtstr.c": FMTSTR_C_CODE,
            "solve.py": PYTHON_EVAL_CODE,
        })
        response = client.post("/analyze", files={"file": ("multi.zip", zip_data)})
        assert response.status_code == 200
        data = response.json()

        assert data["analyzed_count"] >= 1
        assert data["source_code_count"] == 3  # All 3 source files analyzed


# ═══════════════════════════════════════════════════════════════════════
# 2. ZIP with Only Source Code
# ═══════════════════════════════════════════════════════════════════════
class TestZipSourceCodeOnly:
    """Upload a ZIP with only source code files — should succeed."""

    def test_source_only_c(self):
        """ZIP with only .c file → analyzed, not rejected."""
        zip_data = _make_zip({"vuln.c": VULN_C_CODE})
        response = client.post("/analyze", files={"file": ("src.zip", zip_data)})
        assert response.status_code == 200
        data = response.json()

        assert data["analyzed_count"] == 0  # No binaries
        assert data["source_code_count"] == 1
        assert len(data["source_code_results"]) == 1
        assert data["source_code_results"][0]["filename"] == "vuln.c"

    def test_source_only_multiple(self):
        """ZIP with only source files → all analyzed."""
        zip_data = _make_zip({
            "main.c": VULN_C_CODE,
            "helper.py": PYTHON_EVAL_CODE,
        })
        response = client.post("/analyze", files={"file": ("sources.zip", zip_data)})
        assert response.status_code == 200
        data = response.json()

        assert data["analyzed_count"] == 0
        assert data["source_code_count"] == 2


# ═══════════════════════════════════════════════════════════════════════
# 3. ZIP with Only Binaries (Backward Compatibility)
# ═══════════════════════════════════════════════════════════════════════
class TestZipBinaryOnlyBackcompat:
    """ZIP with only binary files → backward compatible."""

    def test_binary_only_unchanged(self):
        """ZIP with only ELF binary → analyzed, source_code_results empty."""
        zip_data = _make_zip({"vuln": ELF_64})
        response = client.post("/analyze", files={"file": ("bin.zip", zip_data)})
        assert response.status_code == 200
        data = response.json()

        assert data["analyzed_count"] >= 1
        assert data["source_code_count"] == 0
        assert data["source_code_results"] == []
        # Backward compat: results array still present
        assert "results" in data
        assert len(data["results"]) >= 1

    def test_response_has_all_keys(self):
        """ZIP response includes all expected keys including new ones."""
        zip_data = _make_zip({"test": ELF_64})
        response = client.post("/analyze", files={"file": ("test.zip", zip_data)})
        assert response.status_code == 200
        data = response.json()

        # All expected keys
        assert "archive" in data
        assert "total_entries" in data
        assert "analyzed_count" in data
        assert "source_code_count" in data
        assert "skipped_count" in data
        assert "results" in data
        assert "source_code_results" in data
        assert "skipped" in data


# ═══════════════════════════════════════════════════════════════════════
# 4. Source Code Too Large → Skipped
# ═══════════════════════════════════════════════════════════════════════
class TestZipSourceCodeLimits:
    """Source code files exceeding limits are skipped gracefully."""

    def test_source_code_too_large(self):
        """Source file > 10,000 chars → skipped with reason."""
        large_code = b"// " + b"A" * 12000 + b"\nint main() { return 0; }\n"
        zip_data = _make_zip({"vuln": ELF_64, "huge.c": large_code})
        response = client.post("/analyze", files={"file": ("big.zip", zip_data)})
        assert response.status_code == 200
        data = response.json()

        # Binary analyzed, source skipped
        assert data["analyzed_count"] >= 1
        assert data["source_code_count"] == 0

        # Check it appears in skipped with correct reason
        skipped_names = [s["filename"] for s in data["skipped"]]
        assert "huge.c" in skipped_names
        huge_skip = next(s for s in data["skipped"] if s["filename"] == "huge.c")
        assert "character limit" in huge_skip["reason"].lower()

    def test_source_file_cap_at_3(self):
        """Only first 3 source files are analyzed; rest are skipped."""
        zip_data = _make_zip({
            "a.c": VULN_C_CODE,
            "b.c": FMTSTR_C_CODE,
            "c.py": PYTHON_EVAL_CODE,
            "d.c": b"int main() { return 0; }\n",
            "e.py": b"print('hello')\n",
        })
        response = client.post("/analyze", files={"file": ("many.zip", zip_data)})
        assert response.status_code == 200
        data = response.json()

        assert data["source_code_count"] == 3  # Capped at 3

        # The 4th and 5th should be skipped
        skipped_reasons = {s["filename"]: s["reason"] for s in data["skipped"]}
        # At least one of d.c or e.py should be in skipped with "limit" reason
        limit_skipped = [name for name, reason in skipped_reasons.items()
                         if "limit" in reason.lower()]
        assert len(limit_skipped) >= 1  # At least one was capped


# ═══════════════════════════════════════════════════════════════════════
# 5. Source Code Results Structure
# ═══════════════════════════════════════════════════════════════════════
class TestZipSourceCodeResultsStructure:
    """Verify source code result objects have the expected fields."""

    def test_source_result_has_expected_fields(self):
        """Each source code result should have key analysis fields."""
        zip_data = _make_zip({"vuln.c": VULN_C_CODE})
        response = client.post("/analyze", files={"file": ("src.zip", zip_data)})
        assert response.status_code == 200
        data = response.json()

        assert len(data["source_code_results"]) == 1
        src = data["source_code_results"][0]

        # Required fields from analyze_source_code()
        assert "language" in src
        assert "filename" in src
        assert "dangerous_functions" in src
        assert "vulnerabilities" in src
        assert "risk_score" in src

    def test_c_source_detects_gets(self):
        """C source with gets() should detect buffer overflow vulnerability."""
        zip_data = _make_zip({"overflow.c": VULN_C_CODE})
        response = client.post("/analyze", files={"file": ("bof.zip", zip_data)})
        assert response.status_code == 200
        data = response.json()

        src = data["source_code_results"][0]
        # Should detect gets() as dangerous
        func_names = [f["name"] for f in src["dangerous_functions"]]
        assert any("gets" in name.lower() for name in func_names)

    def test_python_source_detects_eval(self):
        """Python source with eval() should detect code execution vulnerability."""
        zip_data = _make_zip({"evil.py": PYTHON_EVAL_CODE})
        response = client.post("/analyze", files={"file": ("py.zip", zip_data)})
        assert response.status_code == 200
        data = response.json()

        src = data["source_code_results"][0]
        func_names = [f["name"] for f in src["dangerous_functions"]]
        assert any("eval" in name.lower() for name in func_names)


# ═══════════════════════════════════════════════════════════════════════
# 6. Empty/Invalid ZIP Edge Cases
# ═══════════════════════════════════════════════════════════════════════
class TestZipEdgeCases:
    """Edge cases for ZIP handling with source code."""

    def test_zip_with_no_analyzable_files(self):
        """ZIP with only unsupported files → 400 error."""
        zip_data = _make_zip({"readme.txt": b"Hello world", "image.png": b"\x89PNG\r\n"})
        response = client.post("/analyze", files={"file": ("junk.zip", zip_data)})
        assert response.status_code == 400

    def test_zip_with_empty_source_file(self):
        """ZIP with empty .c file → skipped as empty."""
        zip_data = _make_zip({"vuln": ELF_64, "empty.c": b""})
        response = client.post("/analyze", files={"file": ("empty.zip", zip_data)})
        assert response.status_code == 200
        data = response.json()

        # Binary analyzed, empty source skipped
        assert data["analyzed_count"] >= 1
        skipped_names = [s["filename"] for s in data["skipped"]]
        assert "empty.c" in skipped_names

    def test_source_code_extensions_recognized(self):
        """All SOURCE_CODE_EXTENSIONS are recognized in ZIP."""
        files = {
            "vuln": ELF_64,
            "test.c": b"int main() { return 0; }\n",
            "test.py": b"print('hello')\n",
            "test.js": b"console.log('hi');\n",
        }
        zip_data = _make_zip(files)
        response = client.post("/analyze", files={"file": ("multi.zip", zip_data)})
        assert response.status_code == 200
        data = response.json()

        assert data["source_code_count"] == 3
        src_names = [s["filename"] for s in data["source_code_results"]]
        assert "test.c" in src_names
        assert "test.py" in src_names
        assert "test.js" in src_names


def test_detect_ctf_category_from_source_logic():
    from main import detect_ctf_category_from_source
    
    # Test ret2win
    res = detect_ctf_category_from_source("void win() { }", "c", [])
    assert res["category"] == "ret2win"
    
    # Test format_string
    res = detect_ctf_category_from_source("printf(userInput);", "c", [])
    assert res["category"] == "format_string"
    
    # Test ret2libc
    res = detect_ctf_category_from_source("system(\"/bin/sh\");", "c", [])
    assert res["category"] == "ret2libc"
    
    # Test heap_exploitation
    res = detect_ctf_category_from_source("malloc(8); free(p); free(p);", "c", [])
    assert res["category"] == "heap_exploitation"
    
    # Test shellcode
    res = detect_ctf_category_from_source("mprotect(ptr, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC);", "c", [])
    assert res["category"] == "shellcode"
    
    # Test rop_chain
    res = detect_ctf_category_from_source("void vuln() { gets(buf); }", "c", [{"type": "buffer_overflow"}])
    assert res["category"] == "rop_chain"
    
    # Test unknown
    res = detect_ctf_category_from_source("int main() { return 0; }", "c", [])
    assert res["category"] == "unknown"


def test_source_result_has_ctf_category():
    """Source code analysis should include ctf_category in response."""
    zip_data = _make_zip({"win.c": VULN_C_CODE})
    response = client.post("/analyze", files={"file": ("src.zip", zip_data)})
    assert response.status_code == 200
    data = response.json()

    assert len(data["source_code_results"]) == 1
    src = data["source_code_results"][0]
    assert "ctf_category" in src
    assert src["ctf_category"]["category"] == "ret2win"
    assert src["ctf_category"]["confidence"] == "High"

