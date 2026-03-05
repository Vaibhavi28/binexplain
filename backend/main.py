"""
BinExplain Backend — FastAPI application for static binary analysis.

Security invariants
───────────────────
• Uploaded binaries are NEVER executed.
• Temp files are ALWAYS deleted after processing (try/finally).
• File size AND type are validated BEFORE the file touches disk.
• File contents are NEVER logged.
• Temp files live in the OS temp directory, never in the project tree.
• Only extracted strings (never the binary itself) are sent to Claude.
• The Anthropic API key is read from the ANTHROPIC_API_KEY env var.
"""

import logging
import os
import re
import subprocess
import tempfile
from pathlib import Path

import anthropic

from fastapi import FastAPI, File, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MB
ALLOWED_EXTENSIONS: set[str] = {".bin", ".elf", ".exe"}
MIN_STRING_LENGTH = 4  # minimum printable-ASCII run to extract
MAX_STRINGS_FOR_AI = 100  # cap strings sent to Claude to avoid token abuse

ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")

AI_SYSTEM_PROMPT = (
    "You are a CTF mentor helping beginners learn binary exploitation. "
    "Given extracted strings and patterns from a binary, provide 3-5 specific, "
    "actionable next steps a beginner should take. Be encouraging, specific, "
    "and explain WHY each step matters. Format as numbered list. Keep each "
    "hint under 3 sentences."
)

logger = logging.getLogger("binexplain")

# Expected magic-byte prefixes for known binary formats
FILE_SIGNATURES: dict[str, bytes] = {
    ".elf": b"\x7fELF",
    ".exe": b"MZ",
}

# If an alleged .bin file starts with any of these, reject it —
# the file is likely a script or markup masquerading as a binary.
SUSPICIOUS_HEADERS: list[bytes] = [
    b"#!",          # shell / script shebang
    b"<html",       # HTML
    b"<!doctype",   # HTML doctype
    b"<script",     # JavaScript / XSS payload
    b"<?php",       # PHP
    b"<%",          # ASP / JSP
    b"<?xml",       # XML
    b"{\n",         # JSON
    b"[",           # JSON array
]

# ---------------------------------------------------------------------------
# Application & middleware
# ---------------------------------------------------------------------------
limiter = Limiter(key_func=get_remote_address)

app = FastAPI(
    title="BinExplain API",
    description="Static analysis of binary files — extract readable strings without executing anything.",
    version="0.1.0",
)

app.state.limiter = limiter


@app.exception_handler(RateLimitExceeded)
async def _rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(
        status_code=429,
        content={"detail": "Rate limit exceeded. Maximum 10 requests per IP per hour."},
    )


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],          # ← tighten to your frontend origin in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------
def _validate_extension(filename: str | None) -> str:
    """Return the lower-cased extension or raise HTTP 400."""
    if not filename:
        raise HTTPException(status_code=400, detail="Filename is missing from the upload.")
    ext = Path(filename).suffix.lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Extension '{ext}' is not allowed. Accepted: {', '.join(sorted(ALLOWED_EXTENSIONS))}",
        )
    return ext


def _validate_size(content: bytes) -> None:
    """Reject files that exceed the size cap or are empty."""
    if len(content) == 0:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")
    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=413,
            detail=f"File exceeds the {MAX_FILE_SIZE // (1024 * 1024)} MB size limit.",
        )


def _validate_mime(content: bytes, ext: str) -> None:
    """
    Lightweight content-sniffing: verify the file's magic bytes match the
    declared extension and reject anything that looks like a script/markup.
    """
    # For formats with known signatures, the header MUST match.
    if ext in FILE_SIGNATURES:
        expected = FILE_SIGNATURES[ext]
        if not content[: len(expected)] == expected:
            raise HTTPException(
                status_code=400,
                detail=f"File content does not match the expected signature for '{ext}'.",
            )
        return

    # For generic .bin — reject obvious non-binary content.
    header = content[:64].lower()
    for sig in SUSPICIOUS_HEADERS:
        if header.startswith(sig):
            raise HTTPException(
                status_code=400,
                detail="File appears to be a script or markup file, not a binary.",
            )


# ---------------------------------------------------------------------------
# String extraction
# ---------------------------------------------------------------------------
def _extract_strings_python(data: bytes, min_len: int = MIN_STRING_LENGTH) -> list[str]:
    """
    Pure-Python fallback that replicates the basic behaviour of the Unix
    `strings` utility: find runs of >= *min_len* printable ASCII characters.
    """
    pattern = rb"[\x20-\x7e]{" + str(min_len).encode() + rb",}"
    return [m.decode("ascii", errors="replace") for m in re.findall(pattern, data)]


def _run_strings(filepath: str) -> list[str]:
    """
    Run the system `strings` command on *filepath*.
    Falls back to the pure-Python extractor if the command is unavailable
    or times out.

    ⚠  This function ONLY reads the file — it never executes it.
    """
    try:
        result = subprocess.run(
            ["strings", filepath],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode == 0:
            return [line for line in result.stdout.splitlines() if line.strip()]
    except FileNotFoundError:
        pass  # `strings` is not installed on this system
    except subprocess.TimeoutExpired:
        pass  # analysis took too long — fall back

    # Fallback: extract strings in pure Python
    with open(filepath, "rb") as fh:
        data = fh.read()
    return _extract_strings_python(data)


# ---------------------------------------------------------------------------
# Pattern detection
# ---------------------------------------------------------------------------
def detect_patterns(strings: list[str]) -> dict[str, list[str]]:
    """
    Scan extracted strings and tag interesting findings for CTF analysis.
    Returns a dict mapping category names to lists of matching strings.
    """
    patterns: dict[str, list[str]] = {
        "flag_reads": [],
        "win_conditions": [],
        "dangerous_functions": [],
        "memory_functions": [],
        "stack_protection": [],
        "menu_driven": [],
        "glibc_versions": [],
        "file_operations": [],
    }

    win_keywords = ("you win", "correct", "success", "congratulations")
    dangerous_funcs = ("gets", "strcpy", "sprintf", "system", "exec")
    memory_funcs = ("malloc", "free", "realloc")
    file_ops = ("fopen", "fread", "fclose")
    menu_indicators = ("1)", "2)", "option", "menu")

    for s in strings:
        s_lower = s.lower()

        # Flag file reads
        if "flag" in s_lower:
            patterns["flag_reads"].append(s)

        # Win conditions
        if any(kw in s_lower for kw in win_keywords):
            patterns["win_conditions"].append(s)

        # Dangerous functions
        for func in dangerous_funcs:
            if func in s:
                patterns["dangerous_functions"].append(s)
                break

        # Memory functions (hint at heap vulns)
        for func in memory_funcs:
            if func in s:
                patterns["memory_functions"].append(s)
                break

        # Stack protection
        if "__stack_chk_fail" in s:
            patterns["stack_protection"].append(s)

        # Menu-driven programs
        if any(ind in s_lower for ind in menu_indicators):
            patterns["menu_driven"].append(s)

        # GLIBC versions
        if "GLIBC" in s:
            patterns["glibc_versions"].append(s)

        # File operations
        for func in file_ops:
            if func in s:
                patterns["file_operations"].append(s)
                break

    # Remove empty categories for a cleaner response
    return {k: v for k, v in patterns.items() if v}


# ---------------------------------------------------------------------------
# AI hints (Anthropic Claude)
# ---------------------------------------------------------------------------
def get_ai_hints(strings: list[str], patterns: dict[str, list[str]]) -> str:
    """
    Send extracted strings and detected patterns to Claude for beginner-
    friendly CTF hints.  Returns hints as a string.

    Security:
    • Never sends the raw binary — only extracted strings.
    • Caps strings at MAX_STRINGS_FOR_AI to limit token usage.
    • API key is read from the ANTHROPIC_API_KEY env var.
    """
    if not ANTHROPIC_API_KEY:
        return (
            "AI hints unavailable — set the ANTHROPIC_API_KEY environment "
            "variable to enable Claude-powered analysis hints."
        )

    # Build a concise summary for the prompt
    truncated = strings[:MAX_STRINGS_FOR_AI]
    user_message = (
        f"Here are up to {len(truncated)} strings extracted from a binary:\n"
        + "\n".join(truncated)
        + "\n\nDetected patterns:\n"
        + "\n".join(
            f"- {category}: {', '.join(items[:10])}"
            for category, items in patterns.items()
        )
    )

    try:
        client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
        message = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=1024,
            system=AI_SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_message}],
        )
        return message.content[0].text
    except Exception as exc:
        logger.warning("Anthropic API call failed: %s", exc)
        return (
            "AI hints could not be generated at this time. "
            "Tip: review the detected patterns above — look for dangerous "
            "functions (gets, strcpy) and flag-related strings as a starting point."
        )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
@app.get("/health")
async def health():
    """Lightweight health-check — returns ``{"status": "ok"}``."""
    return {"status": "ok"}


@app.post("/analyze")
@limiter.limit("10/hour")
async def analyze(request: Request, file: UploadFile = File(...)):
    """
    Accept a binary file upload, validate it strictly, extract readable
    strings via static analysis, and return the results as JSON.

    The uploaded file is saved to a temporary location and **always**
    deleted after processing — even when an error occurs.
    """
    # ── 1. Validate extension (before reading the full body) ──────────
    ext = _validate_extension(file.filename)

    # ── 2. Read content into memory & validate size ───────────────────
    content = await file.read()
    _validate_size(content)

    # ── 3. Validate content signature / MIME ───────────────────────────
    _validate_mime(content, ext)

    # ── 4. Write to temp file → run analysis → clean up ───────────────
    tmp_path: str | None = None
    try:
        fd, tmp_path = tempfile.mkstemp(suffix=ext, dir=tempfile.gettempdir())
        os.write(fd, content)
        os.close(fd)

        strings = _run_strings(tmp_path)

        # ── 5. Detect patterns & generate AI hints ────────────────────
        patterns = detect_patterns(strings)
        hints = get_ai_hints(strings, patterns)

        return {
            "filename": file.filename,
            "size_bytes": len(content),
            "extension": ext,
            "strings_count": len(strings),
            "strings": strings,
            "patterns": patterns,
            "hints": hints,
        }
    finally:
        # ALWAYS delete the temp file — no exceptions.
        if tmp_path and os.path.exists(tmp_path):
            os.unlink(tmp_path)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
