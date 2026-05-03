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
• Chat messages are NEVER stored — history lives only in the client.
• Extracted ZIP contents are NEVER executed and are deleted in try/finally.
• VirusTotal API key is read from VIRUSTOTAL_API_KEY env var only.
• File contents sent to VT are NEVER logged — only filename and scan status.
• ZIP passwords are NEVER stored or logged — used only for extraction, then discarded.
"""

import logging
import os
import re
import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path
from dotenv import load_dotenv
load_dotenv(Path(__file__).resolve().parent / ".env")

import anthropic
import groq
import openai
import requests
from typing import Literal

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, field_validator
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MB
MAX_ZIP_SIZE = 10 * 1024 * 1024  # 10 MB for ZIP archives
MAX_ZIP_FILES = 20              # zip-bomb protection
ALLOWED_EXTENSIONS: set[str] = {
    ".bin", ".elf", ".exe",
    ".so", ".dll", ".out", ".o",  # additional binary formats
    ".zip",                       # archive support
}
MIN_STRING_LENGTH = 4  # minimum printable-ASCII run to extract
MAX_STRINGS_FOR_AI = 100  # cap strings sent to Claude to avoid token abuse
MAX_CHAT_MESSAGES = 10    # max conversation turns kept per request
MAX_CHAT_CHARS = 2000     # max characters per single chat message
MAX_SOURCE_CODE_CHARS = 10000  # max characters for source code analysis
SOURCE_CODE_EXTENSIONS: set[str] = {
    ".c", ".cpp", ".h", ".hpp",  # C/C++
    ".py",                        # Python
    ".js",                        # JavaScript
    ".rs",                        # Rust
    ".go",                        # Go
    ".java",                      # Java
}

OLLAMA_BASE_URL = "http://localhost:11434"
OLLAMA_MODELS = ["llama3.2", "qwen2.5-coder", "qwen2.5"]

ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY") or ""
GROQ_API_KEY = os.environ.get("GROQ_API_KEY") or ""
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY") or ""
VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY") or ""

# CORS: read allowed origins from env (comma-separated), default to localhost
_raw_origins = os.environ.get("ALLOWED_ORIGINS", "http://localhost:5173")
ALLOWED_ORIGINS = [o.strip() for o in _raw_origins.split(",") if o.strip()]

# ── Startup debug: confirm API key status ─────────────────────────────
if ANTHROPIC_API_KEY:
    print(f"[BinExplain] ANTHROPIC_API_KEY loaded (OK)  (length={len(ANTHROPIC_API_KEY)})")
else:
    print("[BinExplain] WARNING: ANTHROPIC_API_KEY is NOT set -- Claude hints will be disabled")

if GROQ_API_KEY:
    print(f"[BinExplain] GROQ_API_KEY loaded (OK)  (length={len(GROQ_API_KEY)})")
else:
    print("[BinExplain] WARNING: GROQ_API_KEY is NOT set -- Groq fallback will be disabled")

if OPENAI_API_KEY:
    print(f"[BinExplain] OPENAI_API_KEY loaded (OK)  (length={len(OPENAI_API_KEY)})")
else:
    print("[BinExplain] WARNING: OPENAI_API_KEY is NOT set -- GPT-4o fallback will be disabled")

if VIRUSTOTAL_API_KEY:
    print(f"[BinExplain] VIRUSTOTAL_API_KEY loaded (OK)  (length={len(VIRUSTOTAL_API_KEY)})")
else:
    print("[BinExplain] WARNING: VIRUSTOTAL_API_KEY is NOT set -- VirusTotal scanning disabled")

AI_SYSTEM_PROMPT = (
    "You are a CTF mentor helping beginners learn binary exploitation. "
    "Given extracted strings and patterns from a binary, respond using ONLY the format below.\n\n"
    "ABSOLUTE RULES — you must follow every single one:\n"
    "1. Start with • bullet points. ZERO prose, ZERO paragraphs, ZERO introductions or conclusions.\n"
    "2. NEVER use markdown headers (#), numbered lists (1. 2. 3.), bold (**), italic (*), or any markdown formatting.\n"
    "3. Each • bullet = one specific action + the exact Linux command to run. No bullet without a command.\n"
    "4. Maximum 5 • bullets. Each bullet is 1 sentence, 2 sentences absolute max.\n"
    "5. After the • bullets, add a blank line then \"🔗 Kill Chain:\" followed by 2-3 • bullets explaining: "
    "(a) what the binary is likely trying to do based on the strings/patterns, "
    "(b) what the attacker's goal appears to be, "
    "(c) the likely exploitation path for a CTF player.\n"
    "6. Your LAST line must be exactly: 🔥 Try this first: <the single most important command to run>\n"
    "7. Do NOT write anything before the first • or after the 🔥 line.\n\n"
    "EXAMPLE (follow this format exactly):\n"
    "• Run `checksec ./binary` to see if NX, PIE, or stack canaries are enabled.\n"
    "• The binary uses `gets()` — test for overflow with `python3 -c 'print(\"A\"*100)' | ./binary`.\n"
    "• List all functions with `objdump -d binary | grep '<' | head -20` to find win/flag functions.\n"
    "• Search for flag strings with `strings binary | grep -i flag`.\n\n"
    "🔗 Kill Chain:\n"
    "• Binary reads flag.txt — goal is to trigger the win condition that prints the flag.\n"
    "• fgets() with no bounds check suggests a buffer overflow path.\n"
    "• Likely exploit: overflow buffer → overwrite return address → redirect to win function.\n\n"
    "🔥 Try this first: `checksec ./binary`"
)

CHAT_SYSTEM_PROMPT = (
    "You are a CTF mentor helping a beginner analyze a binary they just uploaded. "
    "The user has already received an initial analysis summary (provided as context).\n\n"
    "ABSOLUTE RULES — you must follow every single one:\n"
    "1. Start with • bullet points. ZERO prose, ZERO paragraphs, ZERO introductions or conclusions.\n"
    "2. NEVER use markdown headers (#), numbered lists (1. 2. 3.), bold (**), italic (*), or any markdown formatting.\n"
    "3. Each • bullet = one specific action + the exact Linux command to run where relevant.\n"
    "4. Maximum 5 • bullets. Each bullet is 1 sentence, 2 sentences absolute max.\n"
    "5. After the • bullets, add a blank line then \"🔗 Kill Chain:\" followed by 2-3 • bullets explaining: "
    "(a) what the binary is likely trying to do, "
    "(b) what the attacker's goal appears to be, "
    "(c) the likely exploitation path for a CTF player.\n"
    "6. Your LAST line must be exactly: 🔥 Try this first: <the single most important command>\n"
    "7. Do NOT write anything before the first • or after the 🔥 line.\n"
    "8. If the user asks something outside binary exploitation / CTF scope, "
    "reply with a single • bullet redirecting them back.\n\n"
    "EXAMPLE (follow this format exactly):\n"
    "• Run `checksec ./binary` to see if NX, PIE, or stack canaries are enabled.\n"
    "• The binary uses `gets()` — test for overflow with `python3 -c 'print(\"A\"*100)' | ./binary`.\n"
    "• Use `gdb ./binary` then `info functions` to find interesting function addresses.\n\n"
    "🔗 Kill Chain:\n"
    "• Binary reads flag.txt — goal is to trigger the win condition that prints the flag.\n"
    "• fgets() with no bounds check suggests a buffer overflow path.\n"
    "• Likely exploit: overflow buffer → overwrite return address → redirect to win function.\n\n"
    "🔥 Try this first: `checksec ./binary`"
)

SOURCE_CODE_SYSTEM_PROMPT = (
    "You are a security-focused code reviewer and CTF mentor helping beginners analyze source code "
    "for vulnerabilities.\n\n"
    "Given source code, respond using ONLY the format below.\n\n"
    "ABSOLUTE RULES — you must follow every single one:\n"
    "1. Start with a single line: LANGUAGE: <detected language>\n"
    "2. Then a blank line, then VULNERABILITIES: on its own line, followed by • bullet points.\n"
    "   Each • bullet = one vulnerability with the line number(s) if identifiable, what's wrong, and why it's dangerous.\n"
    "   Maximum 8 bullets. If no vulnerabilities found, write: • No obvious vulnerabilities detected.\n"
    "3. Then a blank line, then DANGEROUS FUNCTIONS: on its own line, followed by • bullet points.\n"
    "   Each • lists a dangerous function call found and why it's risky.\n"
    "   Maximum 6 bullets. If none found, write: • No dangerous function calls detected.\n"
    "4. Then a blank line, then CTF HINTS: on its own line, followed by • bullet points.\n"
    "   Each • = one specific actionable hint for a CTF player (how to exploit, what to look for).\n"
    "   Maximum 5 bullets.\n"
    "5. Then a blank line, then NEXT STEPS: on its own line, followed by • bullet points.\n"
    "   Each • = one concrete command or action to take next, with examples.\n"
    "   Maximum 4 bullets.\n"
    "6. NEVER use markdown headers (#), numbered lists (1. 2. 3.), bold (**), or italic (*).\n"
    "7. Do NOT write anything before LANGUAGE: or any prose paragraphs anywhere.\n\n"
    "EXAMPLE (follow this format exactly):\n"
    "LANGUAGE: C\n\n"
    "VULNERABILITIES:\n"
    "• Line 12: gets(buffer) — unbounded read into stack buffer, classic buffer overflow.\n"
    "• Line 18: strcpy(dest, src) — no bounds checking, can overflow dest.\n"
    "• Line 25: printf(user_input) — format string vulnerability, attacker can read/write memory.\n\n"
    "DANGEROUS FUNCTIONS:\n"
    "• gets() — never use, no way to limit input length.\n"
    "• system() — executes shell commands, can be hijacked via buffer overflow.\n\n"
    "CTF HINTS:\n"
    "• The buffer on line 12 is 64 bytes — overflow it to overwrite the return address.\n"
    "• Look for a win() function that reads flag.txt — redirect execution there.\n"
    "• The format string on line 25 can leak stack addresses with %p.\n\n"
    "NEXT STEPS:\n"
    "• Compile with: gcc -fno-stack-protector -no-pie -o vuln vuln.c\n"
    "• Test overflow: python3 -c 'print(\"A\"*100)' | ./vuln\n"
    "• Find offset: cyclic 100 | ./vuln then cyclic -l <crash_value>\n"
)

logger = logging.getLogger("binexplain")


# ---------------------------------------------------------------------------
# Chat request models
# ---------------------------------------------------------------------------
class ChatMessage(BaseModel):
    role: Literal["user", "assistant"]
    content: str

    @field_validator("content")
    @classmethod
    def cap_content_length(cls, v: str) -> str:
        if len(v) > MAX_CHAT_CHARS:
            raise ValueError(f"Message content exceeds {MAX_CHAT_CHARS} character limit.")
        return v


class ChatRequest(BaseModel):
    messages: list[ChatMessage]
    context: str = ""


class CodeAnalysisRequest(BaseModel):
    code: str
    filename: str = ""

    @field_validator("code")
    @classmethod
    def validate_code(cls, v: str) -> str:
        if len(v) > MAX_SOURCE_CODE_CHARS:
            raise ValueError(f"Source code exceeds {MAX_SOURCE_CODE_CHARS} character limit.")
        if not v.strip():
            raise ValueError("Source code is empty.")
        return v

    @field_validator("filename")
    @classmethod
    def cap_filename(cls, v: str) -> str:
        return v[:200]

# Expected magic-byte prefixes for known binary formats
FILE_SIGNATURES: dict[str, bytes] = {
    ".elf": b"\x7fELF",
    ".exe": b"MZ",
    ".so":  b"\x7fELF",   # shared libraries are ELF
    ".dll": b"MZ",        # Windows DLLs use PE/MZ
}

# Magic bytes used for auto-detecting extensionless files
MAGIC_BYTE_MAP: list[tuple[bytes, str]] = [
    (b"\x7fELF",         "ELF"),
    (b"MZ",              "PE"),
    (b"\xcf\xfa\xed\xfe", "Mach-O (64-bit)"),
    (b"\xce\xfa\xed\xfe", "Mach-O (32-bit)"),
    (b"\xfe\xed\xfa\xcf", "Mach-O (64-bit, big-endian)"),
    (b"\xfe\xed\xfa\xce", "Mach-O (32-bit, big-endian)"),
]

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
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------
def _validate_extension(filename: str | None) -> str:
    """
    Return the lower-cased extension, or '' for extensionless files.
    Raises HTTP 400 for unsupported extensions.
    """
    if not filename:
        raise HTTPException(status_code=400, detail="Filename is missing from the upload.")
    ext = Path(filename).suffix.lower()
    # Extensionless files are allowed — they'll be auto-detected via magic bytes
    if ext == "":
        return ext
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Extension '{ext}' is not allowed. "
                f"Accepted: {', '.join(sorted(ALLOWED_EXTENSIONS))} or no extension (auto-detect)."
            ),
        )
    return ext


def _validate_size(content: bytes, *, is_zip: bool = False) -> None:
    """Reject files that exceed the size cap or are empty."""
    if len(content) == 0:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")
    limit = MAX_ZIP_SIZE if is_zip else MAX_FILE_SIZE
    if len(content) > limit:
        raise HTTPException(
            status_code=413,
            detail=f"File exceeds the {limit // (1024 * 1024)} MB size limit.",
        )


def _detect_type_from_magic(content: bytes) -> str:
    """
    Auto-detect a binary's type from its magic bytes.
    Returns a human-readable type string (e.g. 'ELF', 'PE').
    Raises HTTP 400 if the file cannot be identified.
    """
    for magic, label in MAGIC_BYTE_MAP:
        if content[:len(magic)] == magic:
            return label
    raise HTTPException(
        status_code=400,
        detail=(
            "Cannot identify file type — no known magic bytes found. "
            "Supported formats: ELF (Linux binaries), PE/MZ (Windows .exe/.dll), "
            "Mach-O (macOS binaries). Try uploading with an explicit extension "
            f"({', '.join(sorted(ALLOWED_EXTENSIONS))})."
        ),
    )


def _validate_mime(content: bytes, ext: str) -> None:
    """
    Lightweight content-sniffing: verify the file's magic bytes match the
    declared extension and reject anything that looks like a script/markup.
    """
    # ZIP files have their own signature check
    if ext == ".zip":
        if not content.startswith(b"PK"):
            raise HTTPException(
                status_code=400,
                detail="File does not appear to be a valid ZIP archive.",
            )
        return

    # For formats with known signatures, the header MUST match.
    if ext in FILE_SIGNATURES:
        expected = FILE_SIGNATURES[ext]
        if not content[: len(expected)] == expected:
            raise HTTPException(
                status_code=400,
                detail=f"File content does not match the expected signature for '{ext}'.",
            )
        return

    # For generic .bin / .out / .o / extensionless — reject obvious non-binary content.
    header = content[:64].lower()
    for sig in SUSPICIOUS_HEADERS:
        if header.startswith(sig):
            raise HTTPException(
                status_code=400,
                detail="File appears to be a script or markup file, not a binary.",
            )




# ---------------------------------------------------------------------------
# Encoding detection
# ---------------------------------------------------------------------------
_BASE64_RE = re.compile(r'[A-Za-z0-9+/]{20,}={0,2}')
_HEX_RE = re.compile(r'[0-9a-fA-F]{16,}')
_XOR_KEYWORDS = ("xor", "key", "encrypt", "decode", "cipher", "crypt")


def detect_encodings(strings: list[str]) -> dict[str, list[str]]:
    """
    Scan extracted strings for potential encoded or obfuscated data.

    Detects:
    • Base64 patterns (20+ chars of Base64 alphabet)
    • Long hex strings (16+ hex chars)
    • XOR / encryption hints (keywords)
    • ROT13 — applies ROT13 to each string, flags if result contains
      'flag' or 'ctf' (hidden flags)

    Returns a dict mapping category → list of matching strings.
    """
    import codecs

    encodings: dict[str, list[str]] = {
        "base64": [],
        "hex_strings": [],
        "xor_hints": [],
        "rot13_flags": [],
    }

    for s in strings:
        # Base64 patterns
        for m in _BASE64_RE.finditer(s):
            match = m.group()
            # Filter out strings that are purely hex (overlap with hex detector)
            if not all(c in '0123456789abcdefABCDEF' for c in match.rstrip('=')):
                encodings["base64"].append(match[:80])  # truncate long matches

        # Hex strings
        for m in _HEX_RE.finditer(s):
            encodings["hex_strings"].append(m.group()[:64])

        # XOR / encryption hints
        s_lower = s.lower()
        if any(kw in s_lower for kw in _XOR_KEYWORDS):
            encodings["xor_hints"].append(s)

        # ROT13 hidden flags
        try:
            rotated = codecs.decode(s, "rot_13")
            if "flag" in rotated.lower() or "ctf" in rotated.lower():
                encodings["rot13_flags"].append(f"{s} → ROT13 → {rotated}")
        except Exception:
            pass

    # Deduplicate and cap
    for key in encodings:
        encodings[key] = list(dict.fromkeys(encodings[key]))[:20]

    # Remove empty categories
    return {k: v for k, v in encodings.items() if v}


# ---------------------------------------------------------------------------
# Encoding detection helpers (URL/IP regexes kept for detect_encodings)
# ---------------------------------------------------------------------------
_IP_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
_URL_RE = re.compile(r'https?://[^\s\x00]+', re.IGNORECASE)
_FORMAT_STRING_RE = re.compile(r'%[0-9]*[nxspdl]', re.IGNORECASE)




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
# CTF flag detection
# ---------------------------------------------------------------------------
def detect_flags(strings: list[str]) -> list[str]:
    """
    Scan extracted strings for CTF flag formats using regex.
    Detects 10 named formats plus a generic [A-Z0-9]{2,8}\\{...} pattern.
    Returns a deduplicated list of all matches found.
    """
    FLAG_PATTERNS = [
        r'flag\{[^}]+\}',
        r'CTF\{[^}]+\}',
        r'picoCTF\{[^}]+\}',
        r'HTB\{[^}]+\}',
        r'THM\{[^}]+\}',
        r'DUCTF\{[^}]+\}',
        r'LACTF\{[^}]+\}',
        r'FLAG\{[^}]+\}',
        r'0ctf\{[^}]+\}',
        r'rtcp\{[^}]+\}',
        r'[A-Z0-9]{2,8}\{[^}]+\}',
    ]
    combined = re.compile('|'.join(f'({p})' for p in FLAG_PATTERNS))
    matches = []
    for s in strings:
        for m in combined.finditer(s):
            matches.append(m.group())
    return list(dict.fromkeys(matches))  # deduplicate, preserve order


# ---------------------------------------------------------------------------
# Risk scoring
# ---------------------------------------------------------------------------
def calculate_risk_score(
    patterns: dict[str, list[str]],
    flags_detected: list[str],
) -> dict:
    """
    Calculate a confidence/risk score for a binary based on detected patterns
    and flags.

    Returns a dict with:
    • score:   int 0–100
    • level:   "Clean" | "Warning" | "Critical"
    • reasons: list[str] explaining each score contribution
    """
    score = 0
    reasons: list[str] = []

    # +30: dangerous functions (gets, strcpy, system, exec)
    if patterns.get("dangerous_functions"):
        score += 30
        funcs = ", ".join(patterns["dangerous_functions"][:5])
        reasons.append(f"Dangerous functions found: {funcs}")

    # +20: missing stack protection (no __stack_chk_fail)
    if not patterns.get("stack_protection"):
        score += 20
        reasons.append("Stack protection appears missing (no __stack_chk_fail)")

    # +20: flag reads detected (references to flag files)
    if patterns.get("flag_reads"):
        score += 20
        reasons.append(f"Flag file references found ({len(patterns['flag_reads'])} match{'es' if len(patterns['flag_reads']) != 1 else ''})")

    # +15: memory functions (heap vulnerability potential)
    if patterns.get("memory_functions"):
        score += 15
        reasons.append("Heap-related functions detected (malloc/free/realloc — potential heap vulnerability)")

    # +10: file operations
    if patterns.get("file_operations"):
        score += 10
        reasons.append("File I/O operations found (fopen/fread/fclose)")

    # +5: menu-driven (larger attack surface)
    if patterns.get("menu_driven"):
        score += 5
        reasons.append("Menu-driven interface detected (larger attack surface)")

    # +20: actual flags detected in strings
    if flags_detected:
        score += 20
        reasons.append(f"CTF flag format{'s' if len(flags_detected) != 1 else ''} found in strings ({len(flags_detected)} match{'es' if len(flags_detected) != 1 else ''})")

    # Clamp to 100
    score = min(score, 100)

    # Determine level
    if score <= 30:
        level = "Clean"
    elif score <= 60:
        level = "Warning"
    else:
        level = "Critical"

    if not reasons:
        reasons.append("No suspicious patterns detected")

    return {
        "score": score,
        "level": level,
        "reasons": reasons,
    }


# ---------------------------------------------------------------------------
# AI hints (Anthropic Claude)
# ---------------------------------------------------------------------------
def get_ai_hints(
    strings: list[str],
    patterns: dict[str, list[str]],
    ctf_category: dict | None = None,
) -> str:
    """
    Send extracted strings and detected patterns to Claude for beginner-
    friendly CTF hints.  Returns hints as a string.

    Security:
    • Never sends the raw binary — only extracted strings.
    • Caps strings at MAX_STRINGS_FOR_AI to limit token usage.
    • API key is read from the ANTHROPIC_API_KEY env var.
    """
    if not ANTHROPIC_API_KEY and not GROQ_API_KEY and not OPENAI_API_KEY:
        return (
            "AI hints unavailable — set the ANTHROPIC_API_KEY, GROQ_API_KEY, or OPENAI_API_KEY "
            "environment variable to enable AI-powered analysis hints."
        )

    # Build category-aware system prompt
    system_prompt = AI_SYSTEM_PROMPT
    if ctf_category and ctf_category.get("category") and ctf_category["category"] != "unknown":
        cat = ctf_category["category"]
        system_prompt += (
            f"\n\nThis binary has been categorized as: {cat}. "
            f"Focus your hints specifically on {cat} exploitation techniques."
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
            system=system_prompt,
            messages=[{"role": "user", "content": user_message}],
        )
        return message.content[0].text
    except Exception as exc:
        logger.warning("Anthropic API call failed: %s", exc)

    # ── Fallback 1: try Groq ───────────────────────────────────────────
    groq_result = _try_groq(
        messages=[{"role": "user", "content": user_message}],
        system_prompt=system_prompt,
    )
    if groq_result:
        return groq_result

    # ── Fallback 2: try OpenAI GPT-4o-mini ────────────────────────────
    openai_result = _try_openai(
        messages=[{"role": "user", "content": user_message}],
        system_prompt=system_prompt,
    )
    if openai_result:
        return openai_result

    # ── Fallback 3: try Ollama locally ────────────────────────────────
    ollama_result = _try_ollama(user_message)
    if ollama_result:
        return ollama_result

    return (
        "AI hints could not be generated — Anthropic, Groq, OpenAI, and Ollama all failed. "
        "Tip: review the detected patterns above — look for dangerous "
        "functions (gets, strcpy) and flag-related strings as a starting point."
    )


def _try_groq(messages: list[dict], system_prompt: str) -> str | None:
    """
    Try to generate a response using Groq (llama-3.3-70b-versatile).
    Returns the response text, or None if the call fails.
    """
    if not GROQ_API_KEY:
        return None
    try:
        client = groq.Groq(api_key=GROQ_API_KEY)
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            max_tokens=1024,
            messages=[
                {"role": "system", "content": system_prompt},
                *messages,
            ],
        )
        text = response.choices[0].message.content
        if text and text.strip():
            logger.info("Groq hint generated with model: llama-3.3-70b-versatile")
            return text.strip()
    except Exception as exc:
        logger.warning("Groq API call failed: %s", exc)
    return None


def _try_openai(messages: list[dict], system_prompt: str) -> str | None:
    """
    Try to generate a response using OpenAI GPT-4o-mini.
    Returns the response text, or None if the call fails.
    """
    if not OPENAI_API_KEY:
        return None
    try:
        client = openai.OpenAI(api_key=OPENAI_API_KEY)
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            max_tokens=1024,
            messages=[
                {"role": "system", "content": system_prompt},
                *messages,
            ],
        )
        text = response.choices[0].message.content
        if text and text.strip():
            logger.info("OpenAI hint generated with model: gpt-4o-mini")
            return text.strip()
    except Exception as exc:
        logger.warning("OpenAI API call failed (%s): %s", type(exc).__name__, exc)
    return None


def _try_ollama(user_message: str) -> str | None:
    """
    Try to generate hints using a local Ollama instance.
    Attempts models in order: qwen2.5-coder, qwen2.5, qwen3.
    Returns the response text, or None if all models fail.
    """
    for model in OLLAMA_MODELS:
        try:
            resp = requests.post(
                f"{OLLAMA_BASE_URL}/api/generate",
                json={
                    "model": model,
                    "prompt": user_message,
                    "system": AI_SYSTEM_PROMPT,
                    "stream": False,
                },
                timeout=120,
            )
            if resp.status_code == 200:
                data = resp.json()
                text = data.get("response", "").strip()
                if text:
                    logger.info("Ollama hint generated with model: %s", model)
                    return text
        except requests.RequestException as exc:
            logger.warning("Ollama model '%s' failed: %s", model, exc)
            continue
    return None


def _try_ollama_chat(messages: list[dict]) -> str | None:
    """
    Try Ollama's multi-turn /api/chat endpoint.
    Attempts models in order: qwen2.5-coder, qwen2.5, qwen3.
    Returns the response text, or None if all models fail.
    """
    for model in OLLAMA_MODELS:
        try:
            resp = requests.post(
                f"{OLLAMA_BASE_URL}/api/chat",
                json={
                    "model": model,
                    "messages": messages,
                    "stream": False,
                },
                timeout=120,
            )
            if resp.status_code == 200:
                data = resp.json()
                text = data.get("message", {}).get("content", "").strip()
                if text:
                    logger.info("Ollama chat generated with model: %s", model)
                    return text
        except requests.RequestException as exc:
            logger.warning("Ollama chat model '%s' failed: %s", model, exc)
            continue
    return None


# ---------------------------------------------------------------------------
# Decompilation hints — AI-powered disassembly explanation
# ---------------------------------------------------------------------------
DECOMPILATION_SYSTEM_PROMPT = (
    "You are a reverse engineering mentor helping a CTF beginner understand "
    "disassembled binary code.\n\n"
    "Given disassembly instructions and extracted strings from a binary, explain:\n"
    "1. What each function likely does based on the assembly patterns and strings.\n"
    "2. Key observations about the control flow (loops, conditionals, function calls).\n"
    "3. What data structures or buffers are being used.\n"
    "4. Any security-relevant patterns (stack operations, function prologues, dangerous calls).\n\n"
    "RULES:\n"
    "• Start with FUNCTION ANALYSIS: on its own line, then • bullet points.\n"
    "• Each • bullet = one observation about the code. Maximum 8 bullets.\n"
    "• Then a blank line, then KEY OBSERVATIONS: with 3-4 • bullets.\n"
    "• Then a blank line, then LIKELY BEHAVIOR: with a 1-2 sentence summary.\n"
    "• NEVER use markdown headers (#), numbered lists, bold (**), or italic (*).\n"
    "• Be specific — reference actual addresses and instructions when possible.\n"
)


def get_decompilation_hints(
    disassembly: list[dict],
    strings: list[str],
    ctf_category: dict | None = None,
) -> str:
    """
    Send disassembly instructions and strings to AI for function-level
    explanations and decompilation-style hints.

    Security:
    • Never sends the raw binary — only disassembly text and strings.
    • Caps data sent to AI to limit token usage.
    • API key is read from env vars.
    """
    if not disassembly:
        return "No disassembly available — decompilation hints require a valid ELF binary."

    if not ANTHROPIC_API_KEY and not GROQ_API_KEY and not OPENAI_API_KEY:
        return (
            "Decompilation hints unavailable — set ANTHROPIC_API_KEY, GROQ_API_KEY, "
            "or OPENAI_API_KEY to enable AI-powered decompilation analysis."
        )

    # Build category-aware system prompt
    system_prompt = DECOMPILATION_SYSTEM_PROMPT
    if ctf_category and ctf_category.get("category") and ctf_category["category"] != "unknown":
        cat = ctf_category["category"]
        system_prompt += (
            f"\nThis binary has been categorized as: {cat}. "
            f"Focus your analysis specifically on {cat} exploitation techniques."
        )

    # Format disassembly as text (cap at 80 instructions)
    disasm_lines = []
    for insn in disassembly[:80]:
        addr = insn.get("address", "")
        mnemonic = insn.get("mnemonic", "")
        op_str = insn.get("op_str", "")
        disasm_lines.append(f"  {addr}:  {mnemonic:8s} {op_str}")
    disasm_text = "\n".join(disasm_lines)

    # Include relevant strings for context (cap at 50)
    strings_text = "\n".join(strings[:50])

    user_message = (
        f"Here is the disassembly of the binary's main function:\n\n"
        f"{disasm_text}\n\n"
        f"Extracted strings from the binary:\n{strings_text}\n\n"
        f"Please explain what each function likely does based on the assembly "
        f"patterns, string references, and calling conventions."
    )

    # Try AI providers (Claude → Groq → OpenAI → Ollama)
    try:
        client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
        message = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=1024,
            system=system_prompt,
            messages=[{"role": "user", "content": user_message}],
        )
        return message.content[0].text
    except Exception as exc:
        logger.warning("Anthropic decompilation hints failed: %s", exc)

    groq_result = _try_groq(
        messages=[{"role": "user", "content": user_message}],
        system_prompt=system_prompt,
    )
    if groq_result:
        return groq_result

    openai_result = _try_openai(
        messages=[{"role": "user", "content": user_message}],
        system_prompt=system_prompt,
    )
    if openai_result:
        return openai_result

    ollama_result = _try_ollama(user_message)
    if ollama_result:
        return ollama_result

    return (
        "Decompilation hints could not be generated — all AI providers failed. "
        "Review the disassembly manually: look for call instructions, stack "
        "allocations (sub rsp), and string references."
    )


# ---------------------------------------------------------------------------
# Source code analysis
# ---------------------------------------------------------------------------
# Dangerous function patterns by language family
_DANGEROUS_PATTERNS: dict[str, list[tuple[str, str]]] = {
    "all": [
        (r'(?i)(password|passwd|secret|api_key|apikey)\s*=\s*["\'][^"\']*["\']', "Hardcoded credential (password=, secret=, api_key=)"),
        (r'(?i)(SELECT|INSERT|UPDATE|DELETE).*(execute|query)', "SQL injection pattern (SELECT, INSERT, execute, query)"),
        (r'(?i)(os\.system|subprocess|eval|exec)\s*\(', "Command injection pattern (os.system, subprocess, eval, exec)"),
    ],
    "c": [
        (r'\bgets\s*\(', "gets() — unbounded read, classic buffer overflow"),
        (r'\bstrcpy\s*\(', "strcpy() — no bounds check, can overflow destination"),
        (r'\bstrcat\s*\(', "strcat() — no bounds check on concatenation"),
        (r'\bsprintf\s*\(', "sprintf() — no bounds check on formatted output"),
        (r'\bscanf\s*\(\s*"%s"', "scanf(\"%s\") — no width limit, buffer overflow"),
        (r'\bsystem\s*\(', "system() — shell command execution, potential injection"),
        (r'\bexecve?\s*\(', "exec() — direct process execution"),
        (r'\bprintf\s*\(\s*[a-zA-Z_]', "printf(var) — possible format string vulnerability"),
        (r'\bmalloc\s*\(.*\)\s*;(?!.*if)', "malloc() — unchecked return value (possible NULL deref)"),
        (r'\bfree\s*\(', "free() — check for double-free or use-after-free"),
    ],
    "python": [
        (r'\beval\s*\(', "eval() — arbitrary code execution from user input"),
        (r'\bexec\s*\(', "exec() — arbitrary code execution"),
        (r'\b__import__\s*\(', "__import__() — dynamic import, potential code injection"),
        (r'\bos\.system\s*\(', "os.system() — shell command injection"),
        (r'\bsubprocess\.\w+\s*\(.*shell\s*=\s*True', "subprocess(shell=True) — shell injection"),
        (r'\bpickle\.loads?\s*\(', "pickle.load() — deserialization attack vector"),
        (r'\byaml\.load\s*\((?!.*Loader)', "yaml.load() without SafeLoader — code execution"),
        (r'\binput\s*\(.*\)\s*$', "input() — in Python 2 this executes code"),
    ],
    "javascript": [
        (r'\beval\s*\(', "eval() — arbitrary code execution"),
        (r'\bnew\s+Function\s*\(', "new Function() — dynamic code execution"),
        (r'\bsetTimeout\s*\(\s*["\']', "setTimeout(string) — implicit eval"),
        (r'\binnerHTML\s*=', "innerHTML assignment — XSS vulnerability"),
        (r'\bdocument\.write\s*\(', "document.write() — potential XSS"),
        (r'\b(child_process|exec|spawn)', "child_process — command injection risk"),
    ],
    "rust": [
        (r'\bunsafe\s*\{', "unsafe block — bypasses Rust's memory safety guarantees"),
        (r'\.unwrap\s*\(\s*\)', ".unwrap() — can panic on None/Err, potential DoS"),
        (r'\bstd::process::Command', "Command execution — shell injection risk"),
        (r'\braw\s+pointer', "Raw pointer usage — manual memory management"),
    ],
    "go": [
        (r'\bexec\.Command\s*\(', "exec.Command() — OS command execution"),
        (r'\bunsafe\.Pointer', "unsafe.Pointer — bypasses Go's type safety"),
        (r'\bcgo\b', "CGo — interfacing with C, inherits C's memory unsafety"),
        (r'\bos\.Exec\s*\(', "os.Exec() — replaces current process"),
    ],
}

# Language extension map
_EXT_TO_LANG: dict[str, str] = {
    ".c": "c", ".h": "c", ".cpp": "c", ".hpp": "c", ".cc": "c",
    ".py": "python",
    ".js": "javascript", ".ts": "javascript", ".jsx": "javascript",
    ".rs": "rust",
    ".go": "go",
    ".java": "c",  # Java shares many C-family patterns
}


def _detect_language_from_code(code: str) -> str:
    """
    Heuristically detect the programming language from code content.
    """
    first_lines = code[:2000].lower()
    if "#include" in first_lines or "int main" in first_lines or "void " in first_lines:
        return "c"
    if "def " in first_lines and ("import " in first_lines or "print(" in first_lines):
        return "python"
    if "function " in first_lines or "const " in first_lines or "=>" in first_lines:
        return "javascript"
    if "fn " in first_lines and ("let " in first_lines or "mut " in first_lines):
        return "rust"
    if "func " in first_lines and "package " in first_lines:
        return "go"
    if "class " in first_lines and "public " in first_lines:
        return "c"  # Java / C#
    return "unknown"


def _find_dangerous_functions(code: str, lang: str) -> list[dict]:
    """
    Scan source code for dangerous function patterns.
    Returns list of {function, description, line} dicts.
    """
    patterns = _DANGEROUS_PATTERNS.get(lang, []).copy()
    patterns.extend(_DANGEROUS_PATTERNS.get("all", []))
    if not patterns or len(patterns) == len(_DANGEROUS_PATTERNS.get("all", [])):
        # Try all pattern sets if language unknown
        for k, _patterns in _DANGEROUS_PATTERNS.items():
            if k != "all" and k != lang:
                patterns.extend(_patterns)

    results: list[dict] = []
    lines = code.split("\n")
    seen: set[str] = set()

    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("#") or stripped.startswith("*"):
            continue  # skip comments
        for pattern, description in patterns:
            if re.search(pattern, line) and description not in seen:
                results.append({
                    "function": description.split("(")[0].split("—")[0].strip(),
                    "description": description,
                    "line": i,
                })
                seen.add(description)
    return results[:20]  # cap


def analyze_source_code(code: str, filename: str = "") -> dict:
    """
    Analyze source code for vulnerabilities and dangerous patterns.

    Security:
    • Code is NEVER stored to disk or executed.
    • Code is only sent to AI APIs in memory.
    • No temp files are created.
    """
    # Detect language
    ext = Path(filename).suffix.lower() if filename else ""
    lang = _EXT_TO_LANG.get(ext, "")
    if not lang:
        lang = _detect_language_from_code(code)

    lang_display = {
        "c": "C/C++", "python": "Python", "javascript": "JavaScript",
        "rust": "Rust", "go": "Go", "unknown": "Unknown",
    }.get(lang, lang.title())

    # Static pattern matching
    dangerous = _find_dangerous_functions(code, lang)

    # Build AI prompt
    line_count = len(code.split("\n"))
    user_message = (
        f"Analyze this source code ({lang_display}, {line_count} lines, filename: {filename or 'unknown'}):\n\n"
        f"```\n{code[:MAX_SOURCE_CODE_CHARS]}\n```"
    )

    # Try AI providers (Claude → Groq → OpenAI → Ollama)
    ai_response = ""

    if ANTHROPIC_API_KEY:
        try:
            client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
            message = client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=1500,
                system=SOURCE_CODE_SYSTEM_PROMPT,
                messages=[{"role": "user", "content": user_message}],
            )
            ai_response = message.content[0].text
        except Exception as exc:
            logger.warning("Anthropic source code analysis failed: %s", exc)

    if not ai_response:
        result = _try_groq(
            messages=[{"role": "user", "content": user_message}],
            system_prompt=SOURCE_CODE_SYSTEM_PROMPT,
        )
        if result:
            ai_response = result

    if not ai_response:
        result = _try_openai(
            messages=[{"role": "user", "content": user_message}],
            system_prompt=SOURCE_CODE_SYSTEM_PROMPT,
        )
        if result:
            ai_response = result

    if not ai_response:
        result = _try_ollama(user_message)
        if result:
            ai_response = result

    if not ai_response:
        ai_response = (
            "AI analysis unavailable — set ANTHROPIC_API_KEY, GROQ_API_KEY, or OPENAI_API_KEY "
            "to enable AI-powered code review."
        )

    # Parse AI response into sections
    sections = {
        "language": lang_display,
        "vulnerabilities": "",
        "dangerous_functions_ai": "",
        "hints": "",
        "next_steps": "",
    }

    current_section = None
    for line in ai_response.split("\n"):
        line_stripped = line.strip()
        upper = line_stripped.upper()

        if upper.startswith("LANGUAGE:"):
            detected = line_stripped[len("LANGUAGE:"):].strip()
            if detected:
                sections["language"] = detected
            continue
        elif upper.startswith("VULNERABILITIES:"):
            current_section = "vulnerabilities"
            continue
        elif upper.startswith("DANGEROUS FUNCTIONS:"):
            current_section = "dangerous_functions_ai"
            continue
        elif upper.startswith("CTF HINTS:"):
            current_section = "hints"
            continue
        elif upper.startswith("NEXT STEPS:"):
            current_section = "next_steps"
            continue

        if current_section and line_stripped:
            sections[current_section] += line + "\n"

    # Calculate risk score
    risk_score = "Low"
    if dangerous:
        if len(dangerous) >= 3:
            risk_score = "High"
        else:
            risk_score = "Medium"
    if "vulnerabilities" in sections and sections["vulnerabilities"].strip():
        val = sections["vulnerabilities"].lower()
        if "no obvious" not in val and "none detected" not in val:
            risk_score = "High"

    return {
        "language": sections["language"],
        "line_count": line_count,
        "char_count": len(code),
        "filename": filename or "(pasted)",
        "dangerous_functions": dangerous,
        "vulnerabilities": sections["vulnerabilities"].strip(),
        "dangerous_functions_ai": sections["dangerous_functions_ai"].strip(),
        "hints": sections["hints"].strip(),
        "next_steps": sections["next_steps"].strip(),
        "raw_ai_response": ai_response,
        "risk_score": risk_score,
    }


# ---------------------------------------------------------------------------
# VirusTotal API v3 integration (background scanning)
# ---------------------------------------------------------------------------
import time as _time
import threading
import uuid

# In-memory store for VT scan results.  Keys are scan_id (UUID strings).
# Entries are auto-cleaned after 10 minutes to avoid memory leaks.
_vt_scans: dict[str, dict] = {}
_VT_SCAN_TTL = 600  # seconds


def _cleanup_old_scans() -> None:
    """Remove scan entries older than _VT_SCAN_TTL."""
    now = _time.time()
    expired = [k for k, v in _vt_scans.items() if now - v.get("_created", 0) > _VT_SCAN_TTL]
    for k in expired:
        _vt_scans.pop(k, None)


def _parse_vt_analysis(analysis_result: dict) -> dict:
    """
    Parse a completed VirusTotal analysis response into our result dict.
    """
    attrs = analysis_result.get("data", {}).get("attributes", {})
    stats = attrs.get("stats", {})
    results_map = attrs.get("results", {})

    detection_count = stats.get("malicious", 0) + stats.get("suspicious", 0)
    total_engines = sum(stats.values())

    # Find the first threat name from detections
    threat_names = []
    for engine, detail in results_map.items():
        if detail.get("category") in ("malicious", "suspicious"):
            result_name = detail.get("result", "")
            if result_name:
                threat_names.append(result_name)
    threat_name = threat_names[0] if threat_names else None

    # Build behavior summary from category counts
    behavior_parts = []
    if stats.get("malicious", 0) > 0:
        behavior_parts.append(f"{stats['malicious']} engine(s) flagged as malicious")
    if stats.get("suspicious", 0) > 0:
        behavior_parts.append(f"{stats['suspicious']} engine(s) flagged as suspicious")
    if stats.get("undetected", 0) > 0:
        behavior_parts.append(f"{stats['undetected']} engine(s) found no threat")
    behavior_summary = "; ".join(behavior_parts) if behavior_parts else "No detections"

    # Determine status label
    if detection_count == 0:
        vt_status = "clean"
    elif detection_count <= 5:
        vt_status = "suspicious"
    else:
        vt_status = "malicious"

    return {
        "status": vt_status,
        "detection_count": detection_count,
        "total_engines": total_engines,
        "threat_name": threat_name,
        "behavior_summary": behavior_summary,
    }


def _vt_background_worker(scan_id: str, analysis_id: str) -> None:
    """
    Background thread: poll VirusTotal for results (max 60 seconds,
    every 5 seconds).  Writes final result into _vt_scans[scan_id].
    """
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    max_wait = 60
    poll_interval = 5
    elapsed = 0

    while elapsed < max_wait:
        _time.sleep(poll_interval)
        elapsed += poll_interval

        try:
            poll_resp = requests.get(analysis_url, headers=headers, timeout=15)
        except requests.RequestException:
            continue

        if poll_resp.status_code != 200:
            continue

        poll_data = poll_resp.json()
        status = poll_data.get("data", {}).get("attributes", {}).get("status", "")

        if status == "completed":
            # Extract file ID for permalink
            file_id = ""
            meta = poll_data.get("meta", {})
            file_info = meta.get("file_info", {})
            file_id = file_info.get("sha256", "")
            if not file_id:
                links = poll_data.get("data", {}).get("links", {})
                item_link = links.get("item", "")
                if "/files/" in item_link:
                    file_id = item_link.split("/files/")[-1]

            permalink = f"https://www.virustotal.com/gui/file/{file_id}" if file_id else ""

            result = _parse_vt_analysis(poll_data)
            result["permalink"] = permalink
            result["_created"] = _vt_scans[scan_id].get("_created", _time.time())
            _vt_scans[scan_id] = result
            return

    # Timed out — mark as pending
    _vt_scans[scan_id] = {
        "status": "pending",
        "message": "VirusTotal analysis is still in progress. Check back later.",
        "permalink": _vt_scans.get(scan_id, {}).get("permalink", ""),
        "_created": _vt_scans.get(scan_id, {}).get("_created", _time.time()),
    }


def _parse_vt_file_report(file_data: dict, sha256: str) -> dict | None:
    """
    Parse a VirusTotal GET /files/{hash} response into our result dict.

    The /files/ endpoint returns last_analysis_stats and last_analysis_results
    (different structure from the /analyses/ endpoint used during polling).

    Returns None if the report has no analysis data yet.
    """
    attrs = file_data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats")
    if not stats:
        return None  # no analysis available yet

    results_map = attrs.get("last_analysis_results", {})

    detection_count = stats.get("malicious", 0) + stats.get("suspicious", 0)
    total_engines = sum(stats.values())

    # Find threat names
    threat_names = []
    for engine, detail in results_map.items():
        if detail.get("category") in ("malicious", "suspicious"):
            result_name = detail.get("result", "")
            if result_name:
                threat_names.append(result_name)
    threat_name = threat_names[0] if threat_names else None

    # Behavior summary
    behavior_parts = []
    if stats.get("malicious", 0) > 0:
        behavior_parts.append(f"{stats['malicious']} engine(s) flagged as malicious")
    if stats.get("suspicious", 0) > 0:
        behavior_parts.append(f"{stats['suspicious']} engine(s) flagged as suspicious")
    if stats.get("undetected", 0) > 0:
        behavior_parts.append(f"{stats['undetected']} engine(s) found no threat")
    behavior_summary = "; ".join(behavior_parts) if behavior_parts else "No detections"

    # Status label
    if detection_count == 0:
        vt_status = "clean"
    elif detection_count <= 5:
        vt_status = "suspicious"
    else:
        vt_status = "malicious"

    permalink = f"https://www.virustotal.com/gui/file/{sha256}"

    return {
        "status": vt_status,
        "detection_count": detection_count,
        "total_engines": total_engines,
        "threat_name": threat_name,
        "behavior_summary": behavior_summary,
        "permalink": permalink,
    }


def _vt_lookup_by_hash(sha256: str, headers: dict) -> dict | None:
    """
    Try to fetch an existing VirusTotal report by SHA256 hash.

    Returns parsed result dict if a report exists, None otherwise.
    """
    try:
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/files/{sha256}",
            headers=headers,
            timeout=15,
        )
    except requests.RequestException:
        return None

    if resp.status_code != 200:
        return None

    return _parse_vt_file_report(resp.json(), sha256)


def submit_virustotal(content: bytes, filename: str) -> dict:
    """
    Upload a binary to VirusTotal API v3 and return immediately with a
    scan_id.  The actual polling happens in a background thread.

    Optimized flow (saves API quota):
    1. Compute SHA256 of file content
    2. Try hash lookup first (GET /files/{sha256})
    3. If report exists → return immediately (no upload needed)
    4. If not found → upload file, get analysis ID
    5. If 409 (AlreadyExistsError) → fall back to hash lookup
    6. Start background polling thread for new uploads

    Returns:
    • {"status": "disabled"} if no API key
    • {"status": "scanning", "scan_id": "..."} on new upload
    • {"status": "clean/suspicious/malicious", ...} on existing report
    • {"status": "error", "message": "..."} on failure

    Security:
    • NEVER logs file contents — only the filename and scan status.
    • API key is read from VIRUSTOTAL_API_KEY env var.
    """
    import hashlib as _hashlib

    if not VIRUSTOTAL_API_KEY:
        return {"status": "disabled"}

    # Cleanup old entries before adding new ones
    _cleanup_old_scans()

    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    # ── Step 1: Compute SHA256 ─────────────────────────────────────────
    sha256 = _hashlib.sha256(content).hexdigest()
    logger.info("VirusTotal: file=%s sha256=%s", filename, sha256)

    # ── Step 2: Try hash lookup first (saves API quota) ────────────────
    existing = _vt_lookup_by_hash(sha256, headers)
    if existing:
        logger.info("VirusTotal: existing report found for %s (hash hit)", filename)
        return existing

    # ── Step 3: Upload file to VT ──────────────────────────────────────
    try:
        upload_resp = requests.post(
            "https://www.virustotal.com/api/v3/files",
            headers=headers,
            files={"file": (filename, content)},
            timeout=30,
        )
    except requests.RequestException as exc:
        logger.warning("VirusTotal upload failed: %s", exc)
        return {"status": "error", "message": f"Upload failed: {str(exc)[:200]}"}

    # ── Step 4: Handle 409 AlreadyExistsError ──────────────────────────
    if upload_resp.status_code == 409:
        logger.info("VirusTotal: 409 AlreadyExistsError for %s — trying hash lookup", filename)
        # The file was already submitted.  Fall back to hash lookup.
        fallback = _vt_lookup_by_hash(sha256, headers)
        if fallback:
            return fallback

        # If hash lookup also fails, return a permalink anyway
        return {
            "status": "pending",
            "message": "File already submitted to VirusTotal. Report may still be processing.",
            "permalink": f"https://www.virustotal.com/gui/file/{sha256}",
        }

    if upload_resp.status_code not in (200, 201):
        logger.warning("VirusTotal upload returned %d", upload_resp.status_code)
        return {
            "status": "error",
            "message": f"VirusTotal returned HTTP {upload_resp.status_code}",
        }

    upload_data = upload_resp.json()
    analysis_id = upload_data.get("data", {}).get("id", "")
    if not analysis_id:
        return {"status": "error", "message": "No analysis ID returned by VirusTotal."}

    # ── Step 5: Start background polling ───────────────────────────────
    scan_id = str(uuid.uuid4())
    _vt_scans[scan_id] = {
        "status": "scanning",
        "sha256": sha256,
        "permalink": f"https://www.virustotal.com/gui/file/{sha256}",
        "_created": _time.time(),
    }

    thread = threading.Thread(
        target=_vt_background_worker,
        args=(scan_id, analysis_id),
        daemon=True,
    )
    thread.start()

    return {"status": "scanning", "scan_id": scan_id}


# ---------------------------------------------------------------------------
# Checksec — binary security protections
# ---------------------------------------------------------------------------
import json as _json
import struct as _struct


def run_checksec(filepath: str) -> dict:
    """
    Detect security protections on a binary file.

    Strategy:
    1. Try running the system `checksec` tool (JSON output).
    2. Fall back to pyelftools-based ELF header parsing.
    3. Fall back to raw ELF header byte parsing.

    Returns dict with: nx, pie, canary, relro, fortify — each True/False.
    Returns all-None if the file is not an ELF binary.
    """
    # ── 1. Try system checksec ────────────────────────────────────────
    try:
        result = subprocess.run(
            ["checksec", f"--file={filepath}", "--format=json"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0 and result.stdout.strip():
            data = _json.loads(result.stdout)
            # checksec JSON format: {filepath: {properties}}
            info = list(data.values())[0] if data else {}
            return {
                "nx": info.get("nx", "").lower() != "no",
                "pie": info.get("pie", "").lower() not in ("no", "no pie"),
                "canary": info.get("canary", "").lower() != "no",
                "relro": info.get("relro", "").lower() not in ("no", "no relro"),
                "fortify": info.get("fortify_source", "").lower() != "no",
            }
    except (FileNotFoundError, subprocess.TimeoutExpired, _json.JSONDecodeError, Exception):
        pass

    # ── 2. Fall back to pyelftools ────────────────────────────────────
    try:
        from elftools.elf.elffile import ELFFile
        from elftools.elf.segments import Segment
        from elftools.elf.dynamic import DynamicSection

        with open(filepath, "rb") as f:
            elf = ELFFile(f)

            # NX: check if any PT_GNU_STACK segment has PF_X flag
            nx = True  # default: NX enabled
            for seg in elf.iter_segments():
                if seg.header.p_type == "PT_GNU_STACK":
                    # PF_X = 0x1 — if executable flag is set, NX is disabled
                    nx = not bool(seg.header.p_flags & 0x1)
                    break

            # PIE: ET_DYN = position-independent
            pie = elf.header.e_type == "ET_DYN"

            # RELRO: check for PT_GNU_RELRO segment
            has_relro = any(
                seg.header.p_type == "PT_GNU_RELRO"
                for seg in elf.iter_segments()
            )

            # Full RELRO requires BIND_NOW in dynamic section
            full_relro = False
            if has_relro:
                for section in elf.iter_sections():
                    if isinstance(section, DynamicSection):
                        for tag in section.iter_tags():
                            if tag.entry.d_tag == "DT_BIND_NOW":
                                full_relro = True
                                break
                            if tag.entry.d_tag == "DT_FLAGS" and (tag.entry.d_val & 0x8):
                                full_relro = True
                                break

            relro = has_relro  # partial or full

            # Canary: check for __stack_chk_fail in symbol table
            canary = False
            for section in elf.iter_sections():
                if hasattr(section, "iter_symbols"):
                    for sym in section.iter_symbols():
                        if "__stack_chk_fail" in sym.name:
                            canary = True
                            break
                    if canary:
                        break

            # Fortify: check for _chk functions (fortified versions)
            fortify = False
            fortify_funcs = ("__printf_chk", "__fprintf_chk", "__sprintf_chk",
                             "__snprintf_chk", "__memcpy_chk", "__strcpy_chk",
                             "__strcat_chk", "__read_chk")
            for section in elf.iter_sections():
                if hasattr(section, "iter_symbols"):
                    for sym in section.iter_symbols():
                        if any(fn in sym.name for fn in fortify_funcs):
                            fortify = True
                            break
                    if fortify:
                        break

            return {
                "nx": nx,
                "pie": pie,
                "canary": canary,
                "relro": relro,
                "fortify": fortify,
            }
    except ImportError:
        pass
    except Exception:
        pass

    # ── 3. Fall back to raw ELF header parsing ────────────────────────
    try:
        with open(filepath, "rb") as f:
            header = f.read(64)

        # Check ELF magic
        if header[:4] != b"\x7fELF":
            return {"nx": None, "pie": None, "canary": None, "relro": None, "fortify": None}

        # e_type at offset 16 (2 bytes, little-endian)
        e_type = _struct.unpack_from("<H", header, 16)[0]
        pie = e_type == 3  # ET_DYN = 3

        # Read the full binary to search for markers
        with open(filepath, "rb") as f:
            raw = f.read()

        canary = b"__stack_chk_fail" in raw
        fortify = any(fn.encode() in raw for fn in
                      ("__printf_chk", "__sprintf_chk", "__memcpy_chk"))

        # Check for PT_GNU_STACK in program headers
        nx = True  # assume enabled
        relro = False

        return {
            "nx": nx,
            "pie": pie,
            "canary": canary,
            "relro": relro,
            "fortify": fortify,
        }
    except Exception:
        return {"nx": None, "pie": None, "canary": None, "relro": None, "fortify": None}


# ---------------------------------------------------------------------------
# Hex viewer — first N bytes of a binary
# ---------------------------------------------------------------------------
def get_hex_view(content: bytes, max_bytes: int = 512) -> list[dict]:
    """
    Return the first *max_bytes* of *content* as a list of hex-view rows.

    Each row is a dict:
      {"offset": "0x0000", "hex": "7f 45 4c 46 ...", "ascii": ".ELF..."}

    16 bytes per row.  Non-printable chars are shown as '.' in the ASCII column.
    """
    data = content[:max_bytes]
    rows: list[dict] = []

    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        offset = f"0x{i:04x}"
        hex_str = " ".join(f"{b:02x}" for b in chunk)
        # Pad last row to align columns
        if len(chunk) < 16:
            hex_str += "   " * (16 - len(chunk))
        ascii_str = "".join(chr(b) if 0x20 <= b < 0x7f else "." for b in chunk)
        rows.append({"offset": offset, "hex": hex_str, "ascii": ascii_str})

    return rows


# ---------------------------------------------------------------------------
# Disassembly — capstone-based function disassembly with symbol table parsing
# ---------------------------------------------------------------------------
def disassemble_binary(content: bytes) -> dict:
    """
    Disassemble a specific function from an ELF binary using capstone.

    Strategy:
    1. Parse ELF symbol table (.symtab / .dynsym) to find 'main'
    2. If main found → disassemble from main's address, stop at ret after 10+ insns
    3. If main not found → fall back to ELF entry point + first 50 instructions

    Returns dict:
      {
        "function": "main" | "entry point" | "_start",
        "instructions": [{"address": "0x...", "mnemonic": "push", "op_str": "rbp"}, ...]
      }
    Returns {"function": "", "instructions": []} on failure.
    """
    empty = {"function": "", "instructions": []}

    try:
        import capstone
    except ImportError:
        return empty

    if len(content) < 64 or content[:4] != b"\x7fELF":
        return empty

    try:
        # ── Parse ELF header ───────────────────────────────────────────
        ei_class = content[4]
        ei_data = content[5]
        is_32 = ei_class == 1
        endian = "little" if ei_data == 1 else "big"

        def read_u16(off):
            return int.from_bytes(content[off:off + 2], endian)

        def read_u32(off):
            return int.from_bytes(content[off:off + 4], endian)

        def read_u64(off):
            return int.from_bytes(content[off:off + 8], endian)

        e_machine = read_u16(18)

        # Entry point
        if is_32:
            e_entry = read_u32(24)
            e_shoff = read_u32(32)
            e_shentsize = read_u16(46)
            e_shnum = read_u16(48)
            e_shstrndx = read_u16(50)
        else:
            e_entry = read_u64(24)
            e_shoff = read_u64(40)
            e_shentsize = read_u16(58)
            e_shnum = read_u16(60)
            e_shstrndx = read_u16(62)

        if e_shoff == 0 or e_shnum == 0 or e_shentsize == 0:
            return empty

        # ── Read section name string table ─────────────────────────────
        if e_shstrndx >= e_shnum:
            return empty

        shstrtab_hdr = e_shoff + e_shstrndx * e_shentsize
        if is_32:
            shstrtab_off = read_u32(shstrtab_hdr + 16)
            shstrtab_sz = read_u32(shstrtab_hdr + 20)
        else:
            shstrtab_off = read_u64(shstrtab_hdr + 24)
            shstrtab_sz = read_u64(shstrtab_hdr + 32)

        if shstrtab_off + shstrtab_sz > len(content):
            return empty

        shstrtab = content[shstrtab_off:shstrtab_off + shstrtab_sz]

        def _section_name(sh_off):
            idx = read_u32(sh_off)
            if idx >= len(shstrtab):
                return ""
            end = shstrtab.index(b"\x00", idx) if b"\x00" in shstrtab[idx:] else idx
            return shstrtab[idx:end].decode("ascii", errors="replace")

        # ── Scan all sections: find .text, .symtab, .strtab, .dynsym ──
        text_offset = text_size = text_addr = 0
        symtab_off = symtab_sz = symtab_entsize = 0
        symtab_link = 0  # index of associated string table
        dynsym_off = dynsym_sz = dynsym_entsize = 0
        dynsym_link = 0
        section_hdrs = []  # (offset, name) for resolving strtab links

        for i in range(e_shnum):
            sh_off = e_shoff + i * e_shentsize
            if sh_off + e_shentsize > len(content):
                break

            name = _section_name(sh_off)
            sh_type = read_u32(sh_off + 4)

            if is_32:
                s_addr = read_u32(sh_off + 12)
                s_offset = read_u32(sh_off + 16)
                s_size = read_u32(sh_off + 20)
                s_link = read_u32(sh_off + 24)
                s_entsize = read_u32(sh_off + 36)
            else:
                s_addr = read_u64(sh_off + 16)
                s_offset = read_u64(sh_off + 24)
                s_size = read_u64(sh_off + 32)
                s_link = read_u32(sh_off + 40)
                s_entsize = read_u64(sh_off + 56)

            section_hdrs.append({
                "idx": i, "name": name, "type": sh_type,
                "offset": s_offset, "size": s_size, "addr": s_addr,
                "link": s_link, "entsize": s_entsize,
            })

            if name == ".text":
                text_offset, text_size, text_addr = s_offset, s_size, s_addr
            elif sh_type == 2:  # SHT_SYMTAB
                symtab_off, symtab_sz = s_offset, s_size
                symtab_entsize = s_entsize or (16 if is_32 else 24)
                symtab_link = s_link
            elif sh_type == 11:  # SHT_DYNSYM
                dynsym_off, dynsym_sz = s_offset, s_size
                dynsym_entsize = s_entsize or (16 if is_32 else 24)
                dynsym_link = s_link

        if text_size == 0:
            return empty

        # ── Helper: read string from a strtab section ──────────────────
        def _read_strtab_string(link_idx, str_idx):
            if link_idx >= len(section_hdrs):
                return ""
            st = section_hdrs[link_idx]
            base = st["offset"]
            sz = st["size"]
            if str_idx >= sz:
                return ""
            start = base + str_idx
            end = content.index(b"\x00", start) if b"\x00" in content[start:start + 256] else start
            return content[start:end].decode("ascii", errors="replace")

        # ── Search symbol tables for 'main' ────────────────────────────
        main_addr = 0
        main_size = 0
        main_name = ""

        def _find_main_in_symtab(sym_off, sym_sz, sym_entsz, link):
            nonlocal main_addr, main_size, main_name
            if sym_off == 0 or sym_sz == 0 or sym_entsz == 0:
                return False
            count = sym_sz // sym_entsz
            for j in range(count):
                ent = sym_off + j * sym_entsz
                if ent + sym_entsz > len(content):
                    break

                if is_32:
                    st_name = read_u32(ent)
                    st_value = read_u32(ent + 4)
                    st_size = read_u32(ent + 8)
                    st_info = content[ent + 12]
                else:
                    st_name = read_u32(ent)
                    st_info = content[ent + 4]
                    st_value = read_u64(ent + 8)
                    st_size = read_u64(ent + 16)

                # Only look at FUNC type symbols (STT_FUNC = 2)
                st_type = st_info & 0xf
                if st_type != 2:
                    continue

                fname = _read_strtab_string(link, st_name)
                if fname == "main":
                    main_addr = st_value
                    main_size = st_size
                    main_name = "main"
                    return True
            return False

        # Try .symtab first (has more symbols), then .dynsym
        if not _find_main_in_symtab(symtab_off, symtab_sz, symtab_entsize, symtab_link):
            _find_main_in_symtab(dynsym_off, dynsym_sz, dynsym_entsize, dynsym_link)

        # ── Determine disassembly target ───────────────────────────────
        if main_addr:
            # Disassemble main function
            target_addr = main_addr
            target_name = "main"
            max_insns = 100  # generous limit for main
            stop_on_ret = True
        else:
            # Fall back to entry point
            target_addr = e_entry
            target_name = "_start (entry point)"
            max_insns = 50
            stop_on_ret = False

        # Convert virtual address to file offset within .text
        if target_addr < text_addr or target_addr >= text_addr + text_size:
            # Target is outside .text — use entry point offset heuristic
            # For non-PIE: entry is typically at 0x400000 + file_offset region
            disasm_file_offset = text_offset
            disasm_vaddr = text_addr
        else:
            offset_in_text = target_addr - text_addr
            disasm_file_offset = text_offset + offset_in_text
            disasm_vaddr = target_addr

        # Limit how much data we read (main_size if known, else 2048 bytes)
        read_limit = main_size if main_size > 0 else 2048
        read_limit = min(read_limit, 8192)  # safety cap
        disasm_data = content[disasm_file_offset:disasm_file_offset + read_limit]

        if not disasm_data:
            return empty

        # ── Map architecture to capstone ───────────────────────────────
        cs_arch = capstone.CS_ARCH_X86
        cs_mode = capstone.CS_MODE_64

        if is_32:
            arch_map = {3: (capstone.CS_ARCH_X86, capstone.CS_MODE_32),
                        40: (capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM),
                        8: (capstone.CS_ARCH_MIPS, capstone.CS_MODE_MIPS32)}
            cs_arch, cs_mode = arch_map.get(e_machine, (capstone.CS_ARCH_X86, capstone.CS_MODE_32))
        else:
            arch_map = {62: (capstone.CS_ARCH_X86, capstone.CS_MODE_64),
                        183: (capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM),
                        8: (capstone.CS_ARCH_MIPS, capstone.CS_MODE_MIPS64)}
            cs_arch, cs_mode = arch_map.get(e_machine, (capstone.CS_ARCH_X86, capstone.CS_MODE_64))

        if ei_data == 2:
            cs_mode |= capstone.CS_MODE_BIG_ENDIAN
        else:
            cs_mode |= capstone.CS_MODE_LITTLE_ENDIAN

        # ── Disassemble ────────────────────────────────────────────────
        md = capstone.Cs(cs_arch, cs_mode)
        instructions = []

        for insn in md.disasm(disasm_data, disasm_vaddr):
            instructions.append({
                "address": f"0x{insn.address:x}",
                "mnemonic": insn.mnemonic,
                "op_str": insn.op_str,
            })

            # Stop at ret after we've seen enough of the function (≥10 insns)
            if stop_on_ret and len(instructions) >= 10:
                mn = insn.mnemonic.lower()
                if mn in ("ret", "retn", "retf"):
                    break

            if len(instructions) >= max_insns:
                break

        return {
            "function": target_name,
            "instructions": instructions,
        }

    except Exception:
        return empty


# ---------------------------------------------------------------------------
# Pwntools exploit template generator
# ---------------------------------------------------------------------------
def generate_pwn_template(
    filename: str,
    content: bytes,
    checksec: dict,
    patterns: dict[str, list[str]],
    strings_list: list[str],
    overflow_hint: dict | None = None,
    rop_gadgets: list[dict] | None = None,
    libc_info: dict | None = None,
) -> str:
    """
    Generate a Python pwntools exploit template based on deep static analysis.

    The template includes:
    • Architecture detection from ELF magic bytes (class + e_machine)
    • Automatic win function detection (win, get_flag, print_flag, shell, backdoor, secret)
    • Architecture-correct cyclic pattern commands (32 vs 64-bit)
    • Pre-filled menu interaction from actual detected menu strings
    • One-liner offset finder using corefile
    • Binary base address comments when PIE is disabled
    • Pre-filled protections from checksec
    • Payload scaffold based on detected exploit technique
    • Predicted buffer overflow offset (from disassembly analysis)
    • Discovered ROP gadgets listed as comments
    • ret2libc section when libc version is identified
    """

    # ── 1. Detect architecture from ELF header ─────────────────────────
    arch = "amd64"  # default
    bits = 64
    endian = "little"
    is_elf = False

    if len(content) >= 20 and content[:4] == b"\x7fELF":
        is_elf = True
        ei_class = content[4]      # 1 = 32-bit, 2 = 64-bit
        ei_data = content[5]       # 1 = little-endian, 2 = big-endian
        endian = "little" if ei_data == 1 else "big"

        e_machine = int.from_bytes(content[18:20], endian)

        if ei_class == 1:
            bits = 32
            arch_map = {3: "i386", 40: "arm", 8: "mips"}
            arch = arch_map.get(e_machine, "i386")
        else:
            bits = 64
            arch_map = {62: "amd64", 183: "aarch64", 8: "mips64"}
            arch = arch_map.get(e_machine, "amd64")

    # ── 2. Win function detection (prioritized) ────────────────────────
    win_function_names = [
        "win", "get_flag", "print_flag", "read_flag", "cat_flag",
        "shell", "get_shell", "spawn_shell",
        "backdoor", "secret", "flag",
        "system",  # only as custom function, not libc
    ]
    func_re = re.compile(r'^[a-zA-Z_][a-zA-Z0-9_]{2,40}$')
    libc_funcs = {
        "printf", "puts", "gets", "fgets", "scanf", "read", "write",
        "malloc", "free", "realloc", "calloc", "system", "execve",
        "open", "close", "strcpy", "strncpy", "strcmp", "strlen",
        "memcpy", "memset", "memmove", "fopen", "fread", "fwrite",
        "fclose", "setbuf", "setvbuf", "exit", "_exit", "atoi",
        "strtol", "sprintf", "snprintf", "fprintf", "alarm",
        "signal", "mprotect", "mmap", "munmap",
    }

    known_funcs: list[str] = []
    custom_funcs: list[str] = []
    win_func: str | None = None
    all_win_candidates: list[str] = []

    for s in strings_list:
        s_stripped = s.strip()
        if not func_re.match(s_stripped) or len(s_stripped) <= 2:
            continue

        if s_stripped in libc_funcs:
            known_funcs.append(s_stripped)
            continue

        # Skip common ELF/compiler noise
        if s_stripped in ("ELF", "GNU", "GCC", "GLIBC", "GLIBCXX", "CXXABI"):
            continue

        if s_stripped[0].isupper() or "_" in s_stripped:
            custom_funcs.append(s_stripped)

        # Check against win function names
        s_low = s_stripped.lower()
        for wname in win_function_names:
            if wname == s_low or s_low.startswith(wname) or s_low.endswith(wname):
                # Don't count 'system' from libc as win
                if s_stripped != "system":
                    all_win_candidates.append(s_stripped)
                break

    known_funcs = list(dict.fromkeys(known_funcs))[:15]
    custom_funcs = list(dict.fromkeys(custom_funcs))[:15]
    all_win_candidates = list(dict.fromkeys(all_win_candidates))

    # Pick best win function by priority
    if all_win_candidates:
        # Prefer exact matches first
        for wname in win_function_names:
            for cand in all_win_candidates:
                if cand.lower() == wname:
                    win_func = cand
                    break
            if win_func:
                break
        if not win_func:
            win_func = all_win_candidates[0]

    # ── 3. Parse menu options from strings ─────────────────────────────
    menu_re = re.compile(r'^(\d+)[).\]:\-]\s*(.+)', re.IGNORECASE)
    menu_options: list[tuple[str, str]] = []  # (number, description)
    menu_prompt: str | None = None

    for s in strings_list:
        s_stripped = s.strip()
        m = menu_re.match(s_stripped)
        if m:
            num, desc = m.group(1), m.group(2).strip()
            if len(desc) > 2 and len(desc) < 60:
                menu_options.append((num, desc))

        # Detect menu prompt characters
        s_low = s_stripped.lower()
        if any(p in s_low for p in ("choice", "option", "select", "enter your", ">>", "> ")):
            if len(s_stripped) < 40:
                menu_prompt = s_stripped

    menu_options = menu_options[:8]  # cap

    # ── 4. Build protections string ────────────────────────────────────
    nx_val = checksec.get("nx")
    pie_val = checksec.get("pie")
    canary_val = checksec.get("canary")
    relro_val = checksec.get("relro")
    fortify_val = checksec.get("fortify")

    prot_parts = []
    if nx_val is not None:
        prot_parts.append(f"NX={'Enabled' if nx_val else 'Disabled'}")
    if pie_val is not None:
        prot_parts.append(f"PIE={'Enabled' if pie_val else 'Disabled'}")
    if canary_val is not None:
        prot_parts.append(f"Canary={'Enabled' if canary_val else 'Disabled'}")
    if relro_val is not None:
        prot_parts.append(f"RELRO={'Enabled' if relro_val else 'Disabled'}")
    if fortify_val is not None:
        prot_parts.append(f"Fortify={'Enabled' if fortify_val else 'Disabled'}")
    protections_line = ", ".join(prot_parts) if prot_parts else "Unknown"

    # ── 5. Build hints from patterns ───────────────────────────────────
    hints = []
    if patterns.get("dangerous_functions"):
        funcs = ", ".join(patterns["dangerous_functions"][:3])
        hints.append(f"Dangerous function(s) detected: {funcs}")
        if any("gets" in f for f in patterns["dangerous_functions"]):
            hints.append("gets() detected — classic buffer overflow target")
        if any("strcpy" in f for f in patterns["dangerous_functions"]):
            hints.append("strcpy() detected — potential buffer overflow")
        if any("system" in f for f in patterns["dangerous_functions"]):
            hints.append("system() call found — possible ret2system target")

    if patterns.get("flag_reads"):
        hints.append("flag.txt / flag reference — find the win condition")

    if patterns.get("win_conditions"):
        hints.append("Win condition detected — redirect control flow here")

    if patterns.get("memory_functions"):
        hints.append("Heap functions (malloc/free) — consider heap exploitation")

    if patterns.get("menu_driven"):
        hints.append("Menu-driven program — look for UAF, double-free, or heap overflow")

    if patterns.get("stack_protection"):
        hints.append("Stack canary enabled — need canary leak or bypass")

    if patterns.get("glibc_versions"):
        ver = patterns["glibc_versions"][0]
        hints.append(f"GLIBC version: {ver}")

    if patterns.get("file_operations"):
        hints.append("File operations detected — check for path traversal or read primitives")

    # ── 6. Determine exploit technique ─────────────────────────────────
    technique = "buffer_overflow"  # default
    if patterns.get("memory_functions") and patterns.get("menu_driven"):
        technique = "heap"
    elif pie_val is False and nx_val is True and patterns.get("dangerous_functions"):
        technique = "rop"
    elif nx_val is False:
        technique = "shellcode"

    # ── 7. Architecture-specific values ────────────────────────────────
    p32_or_64 = "p32" if bits == 32 else "p64"
    cyclic_find_val = "0x61616161" if bits == 32 else "0x6161616161616161"
    word_size = 4 if bits == 32 else 8

    # ── 8. Assemble template ───────────────────────────────────────────
    lines = [
        "#!/usr/bin/env python3",
        "from pwn import *",
        "",
        f"# Binary: {filename}",
        f"# Architecture: {arch} ({bits}-bit, {'little' if endian == 'little' else 'big'}-endian)",
        f"# Protections: {protections_line}",
        "",
        f'binary = "./{filename}"',
        "elf = ELF(binary)",
        f"context.arch = '{arch}'",
        "context.log_level = 'info'",
        "",
    ]

    # Libc loading hint
    lines.append("# libc = ELF('./libc.so.6')  # uncomment if you have the target libc")
    lines.append("")

    # PIE disabled — add base address comment
    if pie_val is False:
        lines.append("# PIE is disabled — addresses are fixed:")
        lines.append("# binary_base = elf.address  # default: 0x400000 (64-bit) or 0x8048000 (32-bit)")
        if bits == 32:
            lines.append("# elf.address = 0x8048000")
        else:
            lines.append("# elf.address = 0x400000")
        lines.append("")

    # Win function — FOUND banner
    if win_func:
        lines.append(f"# ╔══════════════════════════════════════════╗")
        lines.append(f"# ║  WIN FUNCTION FOUND: {win_func:<20s} ║")
        lines.append(f"# ╚══════════════════════════════════════════╝")
        lines.append(f"win = elf.sym['{win_func}']  # WIN FUNCTION FOUND!")
        if len(all_win_candidates) > 1:
            others = [c for c in all_win_candidates if c != win_func]
            lines.append(f"# Other candidates: {', '.join(others)}")
        lines.append("")

    # Known functions
    if custom_funcs:
        lines.append("# Custom functions detected in binary:")
        for fn in custom_funcs[:10]:
            lines.append(f"#   - {fn}")
        lines.append("")

    if known_funcs:
        lines.append("# Known libc functions used:")
        lines.append(f"#   {', '.join(known_funcs[:10])}")
        lines.append("")

    # Hints
    if hints:
        lines.append("# ═══ Analysis Hints ═══")
        for h in hints:
            lines.append(f"# → {h}")
        lines.append("")

    # ── ROP Gadgets (from static analysis) ─────────────────────────────
    if rop_gadgets:
        lines.append("# ═══ ROP Gadgets Found ═══")
        for g in rop_gadgets[:15]:
            addr = g.get("address", "???")
            gadget = g.get("gadget", "???")
            lines.append(f"# {addr}: {gadget}")
        if len(rop_gadgets) > 15:
            lines.append(f"# ... and {len(rop_gadgets) - 15} more gadgets")
        lines.append("")

    # ── Offset finder ──────────────────────────────────────────────────
    predicted_offset = None
    if overflow_hint and overflow_hint.get("likely_offset"):
        predicted_offset = overflow_hint["likely_offset"]
        stack_size = overflow_hint.get("stack_size", 0)
        evidence = overflow_hint.get("evidence", "")
        confidence = overflow_hint.get("confidence", "Low")
        lines.append("# ═══ Predicted Offset ═══")
        lines.append(f"# Confidence: {confidence}")
        lines.append(f"# {evidence}")
        lines.append("")
    else:
        lines.append("# ═══ Find Offset ═══")
        lines.append("# RUN THIS FIRST to find the buffer overflow offset:")
        lines.append(f"# python3 -c \"from pwn import *; p=process('./{filename}'); p.sendline(cyclic(200)); p.wait(); core=p.corefile; print(cyclic_find(core.fault_addr))\"")
        lines.append("")
        lines.append(f"# Or manually:")
        lines.append(f"# 1. Send cyclic(200) to the binary")
        lines.append(f"# 2. Check crash address in debugger")
        if bits == 32:
            lines.append(f"# 3. offset = cyclic_find(0x61616161)  # 32-bit: 'aaaa' pattern")
        else:
            lines.append(f"# 3. offset = cyclic_find(0x6161616161616161)  # 64-bit: 'aaaaaaaa' pattern")
        lines.append("")

    # Connection setup
    lines.extend([
        "# ═══ Connection ═══",
        "p = process(binary)",
        '# p = remote("target.ctf.com", 1337)  # for remote exploit',
        "",
    ])

    # ── Technique-specific scaffold ────────────────────────────────────
    if technique == "shellcode":
        if predicted_offset:
            offset_line = f"offset = {predicted_offset}  # predicted from: sub rsp, 0x{overflow_hint.get('stack_size', 0):x}"
        else:
            offset_line = f"offset = 0  # TODO: replace with value from cyclic_find({cyclic_find_val})"
        lines.extend([
            "# ═══ Shellcode Exploit (NX disabled) ═══",
            "# NX is disabled — you can execute shellcode on the stack",
            "shellcode = asm(shellcraft.sh())",
            "",
            offset_line,
            "",
            "payload = flat(",
            "    shellcode,",
            f"    b'A' * (offset - len(shellcode)),",
            f"    # {p32_or_64}(stack_addr),  # return address → shellcode on stack",
            ")",
        ])
    elif technique == "heap":
        lines.extend([
            "# ═══ Heap Exploit Template ═══",
            "# Menu-driven program with heap operations detected",
            "",
        ])

        # Generate menu helpers from parsed menu options
        prompt_bytes = f"b'{menu_prompt}'" if menu_prompt else "b'> '"

        if menu_options:
            lines.append("# Detected menu options:")
            for num, desc in menu_options:
                lines.append(f"#   {num}) {desc}")
            lines.append("")

            # Generate wrapper functions based on detected menu text
            func_names_generated = set()
            for num, desc in menu_options[:4]:
                # Derive function name from description
                desc_lower = desc.lower()
                if any(w in desc_lower for w in ("add", "create", "new", "alloc")):
                    fname = "create"
                elif any(w in desc_lower for w in ("delete", "remove", "free", "destroy")):
                    fname = "delete"
                elif any(w in desc_lower for w in ("show", "view", "print", "display", "read", "get")):
                    fname = "show"
                elif any(w in desc_lower for w in ("edit", "modify", "update", "change")):
                    fname = "edit"
                elif any(w in desc_lower for w in ("exit", "quit", "leave")):
                    continue  # skip exit option
                else:
                    fname = f"option_{num}"

                if fname in func_names_generated:
                    fname = f"{fname}_{num}"
                func_names_generated.add(fname)

                lines.append(f"def {fname}(data=b'A'):")
                lines.append(f"    p.sendlineafter({prompt_bytes}, b'{num}')")
                lines.append(f"    # TODO: fill in expected prompts for '{desc}'")
                lines.append(f"    # p.sendlineafter(b':', data)")
                lines.append("")
        else:
            # Fallback generic menu helpers
            lines.extend([
                f"def create(size, data=b'A'):",
                f"    p.sendlineafter({prompt_bytes}, b'1')",
                "    p.sendlineafter(b'size', str(size).encode())",
                "    p.sendafter(b'data', data)",
                "",
                "def delete(idx):",
                f"    p.sendlineafter({prompt_bytes}, b'2')",
                "    p.sendlineafter(b'index', str(idx).encode())",
                "",
                "def show(idx):",
                f"    p.sendlineafter({prompt_bytes}, b'3')",
                "    p.sendlineafter(b'index', str(idx).encode())",
                "    return p.recvline()",
                "",
            ])

        lines.extend([
            "# TODO: Implement exploit",
            "# Common techniques: UAF, tcache poisoning, fastbin dup, house-of-force",
        ])
    elif technique == "rop":
        if predicted_offset:
            offset_line = f"offset = {predicted_offset}  # predicted from: sub rsp, 0x{overflow_hint.get('stack_size', 0):x}"
        else:
            offset_line = f"offset = 0  # TODO: replace with value from cyclic_find({cyclic_find_val})"
        lines.extend([
            "# ═══ ROP Exploit (NX enabled, no PIE) ═══",
            "# Use ROP gadgets to build a chain",
            "rop = ROP(elf)",
            "",
            offset_line,
            "",
        ])
        if win_func:
            lines.extend([
                "# Direct ret2win — win function detected!",
            ])
            if bits == 64:
                lines.extend([
                    "# NOTE: 64-bit requires stack alignment (ret gadget before win)",
                    "ret = rop.find_gadget(['ret'])[0]  # stack alignment",
                    "",
                    "payload = flat(",
                    "    b'A' * offset,",
                    "    p64(ret),       # stack alignment for movaps",
                    f"    p64(win),       # → {win_func}",
                    ")",
                ])
            else:
                lines.extend([
                    "payload = flat(",
                    "    b'A' * offset,",
                    f"    p32(win),       # → {win_func}",
                    ")",
                ])
        else:
            lines.extend([
                "# Option 1: ret2system (if system@plt exists)",
                f"# bin_sh = next(elf.search(b'/bin/sh'))",
            ])
            if bits == 64:
                lines.extend([
                    "# pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]",
                    "# ret = rop.find_gadget(['ret'])[0]",
                    "# payload = flat(",
                    "#     b'A' * offset,",
                    "#     p64(ret),",
                    "#     p64(pop_rdi),",
                    "#     p64(bin_sh),",
                    "#     p64(elf.plt['system']),",
                    "# )",
                ])
            else:
                lines.extend([
                    "# payload = flat(",
                    "#     b'A' * offset,",
                    "#     p32(elf.plt['system']),",
                    "#     p32(0xdeadbeef),  # fake return address",
                    "#     p32(bin_sh),",
                    "# )",
                ])
            lines.extend([
                "",
                "# Option 2: Auto-build ROP chain",
                "payload = flat(",
                f"    b'A' * offset,",
                "    rop.chain(),",
                ")",
            ])
    else:
        # Generic buffer overflow
        if predicted_offset:
            offset_line = f"offset = {predicted_offset}  # predicted from: sub rsp, 0x{overflow_hint.get('stack_size', 0):x}"
        else:
            offset_line = f"offset = 0  # TODO: replace with value from cyclic_find({cyclic_find_val})"
        lines.extend([
            "# ═══ Buffer Overflow Template ═══",
            offset_line,
            "",
            "payload = flat(",
            f"    b'A' * offset,",
        ])
        if win_func:
            if bits == 64:
                lines.append("    # NOTE: 64-bit may need ret gadget for stack alignment")
                lines.append(f"    # ret = ROP(elf).find_gadget(['ret'])[0]")
                lines.append(f"    # p64(ret),")
                lines.append(f"    p64(win),       # → {win_func}")
            else:
                lines.append(f"    p32(win),       # → {win_func}")
        else:
            lines.append(f"    # {p32_or_64}(elf.sym['win_function']),  # replace with actual target")
        lines.append(")")

    # ── ret2libc section (when libc version is identified) ─────────────
    libc_version = (libc_info or {}).get("glibc_version")
    if libc_version:
        likely_os = (libc_info or {}).get("likely_os", "Unknown")
        libc_db_url = (libc_info or {}).get("libc_db_url", "")
        lines.extend([
            "",
            "# ═══ ret2libc Section ═══",
            f"# Detected GLIBC version: {libc_version} (likely {likely_os})",
            f"# Libc database: {libc_db_url}" if libc_db_url else "",
            "#",
            "# To use ret2libc, you need the target's libc:",
            "#   1. Leak a GOT address (e.g., puts@GOT)",
            "#   2. Look up the libc version at https://libc.blukat.me/",
            "#   3. Calculate system() and /bin/sh offsets",
            "#",
            "# libc = ELF('./libc.so.6')",
            "# libc.address = leaked_puts - libc.sym['puts']",
            "# system_addr = libc.sym['system']",
            "# bin_sh_addr = next(libc.search(b'/bin/sh'))",
        ])
        if bits == 64:
            lines.extend([
                "#",
                "# # 64-bit ret2libc payload:",
                "# pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]",
                "# ret = rop.find_gadget(['ret'])[0]",
                "# payload_libc = flat(",
                "#     b'A' * offset,",
                "#     p64(ret),          # stack alignment",
                "#     p64(pop_rdi),",
                "#     p64(bin_sh_addr),",
                "#     p64(system_addr),",
                "# )",
            ])
        else:
            lines.extend([
                "#",
                "# # 32-bit ret2libc payload:",
                "# payload_libc = flat(",
                "#     b'A' * offset,",
                "#     p32(system_addr),",
                "#     p32(0xdeadbeef),   # fake return address",
                "#     p32(bin_sh_addr),",
                "# )",
            ])
        lines.append("")

    # Send payload and interact
    lines.extend([
        "",
        "# ═══ Send & Interact ═══",
        "p.sendline(payload)",
        "p.interactive()",
        "",
    ])

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Deep Static Analysis Helpers
# ---------------------------------------------------------------------------
import io
from elftools.elf.elffile import ELFFile

def get_function_list(elffile):
    functions = []
    symtab = elffile.get_section_by_name('.symtab')
    if not symtab:
        symtab = elffile.get_section_by_name('.dynsym')
    if symtab:
        for symbol in symtab.iter_symbols():
            if symbol['st_info']['type'] == 'STT_FUNC' and symbol.name:
                functions.append({
                    "name": symbol.name,
                    "address": hex(symbol['st_value']),
                    "size": symbol['st_size']
                })
    return functions


def get_imports_exports(elffile):
    imports = []
    exports = []
    
    dynsym = elffile.get_section_by_name('.dynsym')
    if dynsym:
        for symbol in dynsym.iter_symbols():
            if symbol['st_shndx'] == 'SHN_UNDEF':
                if symbol.name:
                    imports.append(symbol.name)
            elif symbol['st_info']['type'] == 'STT_FUNC':
                if symbol.name:
                    exports.append(symbol.name)
    
    return {"imports": imports, "exports": exports}

def calculate_cvss_score(patterns: dict[str, list[str]], flags_detected: list[str], checksec: dict):
    base_score = 0.0
    
    nx = checksec.get("nx", True)
    canary = checksec.get("canary", True)
    pie = checksec.get("pie", True)
    
    vuln_score = 0.0
    if nx is False: vuln_score += 2.5
    if canary is False: vuln_score += 2.0
    if pie is False: vuln_score += 1.5
    
    if patterns.get("dangerous_functions"):
        vuln_score += 3.0
    if patterns.get("flag_reads") or flags_detected:
        vuln_score += 2.0
    if patterns.get("memory_functions"):
        vuln_score += 1.0
        
    score = min(vuln_score, 10.0)
    
    if score >= 9.0:
        severity = "Critical"
    elif score >= 7.0:
        severity = "High"
    elif score >= 4.0:
        severity = "Medium"
    elif score > 0.0:
        severity = "Low"
    else:
        severity = "None"
        
    return {"cvss_score": round(score, 1), "cvss_severity": severity}

def analyze_data_flow(disassembly: list[dict], patterns: dict):
    flows = []
    input_funcs = ["gets", "fgets", "scanf", "read"]
    dangerous_sinks = ["system", "execve", "strcpy", "sprintf"]
    
    found_inputs = []
    for insn in disassembly:
        if insn["mnemonic"] == "call":
            op = insn["op_str"]
            for fun in input_funcs:
                if fun in op:
                    found_inputs.append(fun)
            for fun in dangerous_sinks:
                if fun in op and found_inputs:
                    flows.append(f"Input enters at {found_inputs[-1]}() → passes through registers/stack → potentially flows into dangerous sink {fun}()")
                    
    if found_inputs and not flows:
        flows.append(f"Input enters at {found_inputs[-1]}() → stored in stack/heap wrapper → no immediate dangerous sink branch detected in this block.")
        
    if not flows:
        flows.append("No obvious linear data flow from input to sink found in disassembled block.")
        
    return flows


# ---------------------------------------------------------------------------
# ROP Gadget finder (capstone-based)
# ---------------------------------------------------------------------------
def find_rop_gadgets(content: bytes, arch: str = "x86_64") -> list[dict]:
    """
    Scan the .text section of an ELF binary for useful ROP gadgets using capstone.

    Looks for common patterns: ret, pop REG; ret, syscall; ret, leave; ret.
    Returns a list of dicts: [{"address": "0x401234", "gadget": "pop rdi; ret"}]
    Max 20 gadgets returned, deduplicated by gadget text.
    """
    try:
        import capstone
    except ImportError:
        return []

    if not content.startswith(b"\x7fELF"):
        return []

    # Desired gadget patterns (mnemonic sequences ending in ret)
    WANTED_GADGETS = [
        ("ret",),
        ("pop rdi", "ret"),
        ("pop rsi", "ret"),
        ("pop rdx", "ret"),
        ("pop rax", "ret"),
        ("pop rbx", "ret"),
        ("pop rcx", "ret"),
        ("pop rbp", "ret"),
        ("syscall", "ret"),
        ("leave", "ret"),
        ("pop rdi", "pop rsi", "ret"),
        ("pop rsi", "pop r15", "ret"),
        # 32-bit equivalents
        ("pop edi", "ret"),
        ("pop esi", "ret"),
        ("pop ebx", "ret"),
        ("pop eax", "ret"),
        ("int 0x80",),
    ]

    try:
        from elftools.elf.elffile import ELFFile
        import io as _io

        elf = ELFFile(_io.BytesIO(content))
        text_section = elf.get_section_by_name('.text')
        if not text_section:
            return []

        text_data = text_section.data()
        text_addr = text_section['sh_addr']

        # Determine arch/mode
        is_32 = elf.elfclass == 32
        if is_32:
            cs_mode = capstone.CS_MODE_32
        else:
            cs_mode = capstone.CS_MODE_64

        ei_data = elf.header['e_ident']['EI_DATA']
        if ei_data == 'ELFDATA2MSB':
            cs_mode |= capstone.CS_MODE_BIG_ENDIAN
        else:
            cs_mode |= capstone.CS_MODE_LITTLE_ENDIAN

        md = capstone.Cs(capstone.CS_ARCH_X86, cs_mode)

        # Scan for gadgets: search backwards from every ret/syscall/int
        gadgets: list[dict] = []
        seen_gadgets: set[str] = set()
        MAX_GADGET_LEN = 6  # max instructions in a gadget
        MAX_GADGETS = 20

        # Find all ret offsets in .text
        for offset in range(len(text_data)):
            # 0xc3 = ret, 0xcb = retf
            if text_data[offset] not in (0xc3, 0xcb, 0x0f):
                continue
            # 0x0f 0x05 = syscall
            if text_data[offset] == 0x0f:
                if offset + 1 < len(text_data) and text_data[offset + 1] == 0x05:
                    pass  # syscall
                else:
                    continue

            # Try disassembling a few bytes before this point
            for back in range(1, MAX_GADGET_LEN * 8):
                start = offset - back
                if start < 0:
                    break
                chunk = text_data[start:offset + 2]  # +2 for 2-byte opcodes
                insns = list(md.disasm(chunk, text_addr + start))
                if not insns:
                    continue

                # Check if the last instruction ends exactly at offset (or offset+1 for syscall)
                last_insn = insns[-1]
                last_end = last_insn.address + last_insn.size - (text_addr + start)
                expected_end = (offset + 2 if text_data[offset] == 0x0f else offset + 1)
                if start + last_end != expected_end:
                    continue

                # Build mnemonic sequence
                mnemonic_seq = tuple(
                    f"{i.mnemonic} {i.op_str}".strip() if i.op_str else i.mnemonic
                    for i in insns
                )

                # Check against wanted patterns (prefix match)
                for wanted in WANTED_GADGETS:
                    if len(insns) == len(wanted):
                        match = True
                        for got, want in zip(mnemonic_seq, wanted):
                            if want not in got:
                                match = False
                                break
                        if match:
                            gadget_str = " ; ".join(mnemonic_seq)
                            if gadget_str not in seen_gadgets:
                                seen_gadgets.add(gadget_str)
                                gadgets.append({
                                    "address": f"0x{insns[0].address:x}",
                                    "gadget": gadget_str,
                                })
                            break

                if len(gadgets) >= MAX_GADGETS:
                    break
            if len(gadgets) >= MAX_GADGETS:
                break

        return gadgets[:MAX_GADGETS]

    except Exception as e:
        logger.warning("ROP gadget scan failed: %s", e)
        return []


# ---------------------------------------------------------------------------
# Format String Vulnerability Detector
# ---------------------------------------------------------------------------
def detect_format_string(strings: list[str], patterns: dict) -> dict:
    """
    Detect potential format string vulnerabilities.

    Checks if printf/fprintf/sprintf are used and whether user-controlled
    format specifiers (%s, %p, %x, %n) are present in nearby strings.

    Returns:
        {"vulnerable": bool, "evidence": list[str], "severity": "High"|"Medium"|"Low"}
    """
    printf_funcs = ("printf", "fprintf", "sprintf", "snprintf", "syslog", "err", "warn")
    fmt_specifiers = ("%n", "%x", "%p", "%s", "%d", "%hn", "%hhn", "%ln")
    dangerous_specs = ("%n", "%hn", "%hhn", "%ln")

    evidence: list[str] = []
    has_printf = False
    has_dangerous_spec = False
    has_any_spec = False

    for s in strings:
        s_lower = s.lower()

        # Check for printf-family functions
        for fn in printf_funcs:
            if fn in s_lower:
                has_printf = True
                # Check if the function call lacks a literal format string
                # (heuristic: printf is in the string but no "%" immediately follows)
                if fn in s and "%" not in s:
                    evidence.append(f"{fn}() called — potential user-controlled format string")
                break

        # Check for format specifiers in strings (user input patterns)
        for spec in fmt_specifiers:
            if spec in s:
                has_any_spec = True
                if spec in dangerous_specs:
                    has_dangerous_spec = True
                    evidence.append(f"Dangerous format specifier '{spec}' found in: {s[:80]}")
                break

    # Also check if dangerous_functions from patterns contains printf-family
    dangerous = patterns.get("dangerous_functions", [])
    for d in dangerous:
        d_lower = d.lower()
        for fn in printf_funcs:
            if fn in d_lower:
                has_printf = True
                break

    vulnerable = has_printf and (has_dangerous_spec or has_any_spec)

    if has_dangerous_spec:
        severity = "High"
    elif has_printf and has_any_spec:
        severity = "Medium"
    elif has_printf:
        severity = "Low"
    else:
        severity = "Low"

    # Deduplicate evidence
    evidence = list(dict.fromkeys(evidence))[:10]

    return {
        "vulnerable": vulnerable,
        "evidence": evidence,
        "severity": severity,
    }


# ---------------------------------------------------------------------------
# Libc Version Identifier
# ---------------------------------------------------------------------------
# Maps GLIBC minimum versions to likely Ubuntu/Debian releases
_GLIBC_OS_MAP = {
    "2.39": "Ubuntu 24.04 (Noble) / Debian 13",
    "2.38": "Ubuntu 23.10 (Mantic) / Debian Trixie",
    "2.37": "Ubuntu 23.04 (Lunar)",
    "2.36": "Ubuntu 22.10 (Kinetic) / Debian 12",
    "2.35": "Ubuntu 22.04 (Jammy)",
    "2.34": "Ubuntu 21.10 (Impish)",
    "2.33": "Ubuntu 21.04 (Hirsute)",
    "2.31": "Ubuntu 20.04 (Focal) / Debian 11",
    "2.28": "Debian 10 (Buster)",
    "2.27": "Ubuntu 18.04 (Bionic)",
    "2.24": "Debian 9 (Stretch)",
    "2.23": "Ubuntu 16.04 (Xenial)",
    "2.19": "Ubuntu 14.04 (Trusty) / Debian 8",
    "2.17": "CentOS 7 / RHEL 7",
    "2.15": "Ubuntu 12.04 (Precise)",
    "2.12": "CentOS 6 / RHEL 6",
}


def identify_libc(strings: list[str]) -> dict:
    """
    Parse GLIBC version strings and GCC version to identify the likely OS.

    Returns:
        {
            "glibc_version": "2.27",
            "all_versions": ["2.17", "2.23", "2.27"],
            "likely_os": "Ubuntu 18.04 (Bionic)",
            "gcc_version": "7.5.0",
            "libc_db_url": "https://libc.blukat.me/?q=..."
        }
    """
    glibc_re = re.compile(r'GLIBC_(\d+\.\d+)')
    gcc_re = re.compile(r'GCC:\s*\(.*?\)\s*([\d.]+)')

    versions: set[str] = set()
    gcc_version = ""

    for s in strings:
        for m in glibc_re.finditer(s):
            versions.add(m.group(1))
        if not gcc_version:
            gcc_match = gcc_re.search(s)
            if gcc_match:
                gcc_version = gcc_match.group(1)

    if not versions:
        return {
            "glibc_version": None,
            "all_versions": [],
            "likely_os": "Unknown",
            "gcc_version": gcc_version or None,
            "libc_db_url": "",
        }

    sorted_versions = sorted(versions, key=lambda v: tuple(int(x) for x in v.split(".")))
    max_version = sorted_versions[-1]

    # Find the best OS match (exact or closest lower)
    likely_os = "Unknown"
    for ver in sorted(
        _GLIBC_OS_MAP.keys(),
        key=lambda v: tuple(int(x) for x in v.split(".")),
        reverse=True,
    ):
        if tuple(int(x) for x in max_version.split(".")) >= tuple(int(x) for x in ver.split(".")):
            likely_os = _GLIBC_OS_MAP[ver]
            break

    libc_db_url = f"https://libc.blukat.me/?q=__libc_start_main"

    return {
        "glibc_version": max_version,
        "all_versions": sorted_versions,
        "likely_os": likely_os,
        "gcc_version": gcc_version or None,
        "libc_db_url": libc_db_url,
    }


# ---------------------------------------------------------------------------
# CTF Category Detector
# ---------------------------------------------------------------------------
def detect_ctf_category(
    patterns: dict,
    checksec: dict,
    strings: list[str],
    format_string_result: dict | None = None,
    rop_gadgets: list | None = None,
    imports_exports: dict | None = None,
) -> dict:
    """
    Analyze all findings and categorize the binary into the most likely
    CTF exploitation category.

    Categories:
    - ret2win:           No PIE, win function, simple overflow
    - ret2libc:          No PIE, no canary, system/execve in imports
    - format_string:     printf without format arg detected
    - heap_exploitation: malloc/free/UAF patterns
    - stack_canary_bypass: canary present + format string present
    - rop_chain:         NX enabled, no PIE, many gadgets
    - shellcode:         No NX, writable+executable sections

    Returns:
        {"category": str, "confidence": "High"|"Medium"|"Low", "explanation": str}
    """
    nx = checksec.get("nx", True)
    pie = checksec.get("pie", True)
    canary = checksec.get("canary", True)

    has_win = bool(patterns.get("win_conditions")) or any(
        kw in s.lower()
        for s in strings
        for kw in ("win(", "get_flag", "print_flag", "read_flag", "open_flag",
                    "give_shell", "spawn_shell", "cat flag")
    )

    has_dangerous_funcs = bool(patterns.get("dangerous_functions"))
    has_memory_funcs = bool(patterns.get("memory_functions"))
    has_flag_reads = bool(patterns.get("flag_reads"))

    fmt_vuln = format_string_result.get("vulnerable", False) if format_string_result else False
    fmt_severity = format_string_result.get("severity", "Low") if format_string_result else "Low"
    gadget_count = len(rop_gadgets) if rop_gadgets else 0

    # Check for system/execve in imports
    imports = (imports_exports or {}).get("imports", [])
    has_system = any(fn in ("system", "execve", "execvp", "popen") for fn in imports)

    # --- Scoring each category ---
    scores: dict[str, tuple[int, str, str]] = {}  # category -> (score, confidence, explanation)

    # ret2win
    if has_win and not pie:
        score = 90 if has_dangerous_funcs else 70
        conf = "High" if score >= 80 else "Medium"
        scores["ret2win"] = (score, conf,
            "Win/flag function detected with no PIE — overflow the return address to jump directly to the win function.")

    # ret2libc
    if has_system and not pie and not canary:
        score = 85 if has_dangerous_funcs else 65
        conf = "High" if score >= 80 else "Medium"
        scores["ret2libc"] = (score, conf,
            "system()/execve() available with no PIE and no stack canary — classic ret2libc: overflow to call system(\"/bin/sh\").")

    # format_string
    if fmt_vuln:
        score = 90 if fmt_severity == "High" else 70
        conf = "High" if fmt_severity == "High" else "Medium"
        scores["format_string"] = (score, conf,
            "Format string vulnerability detected — use %p to leak addresses, %n to write arbitrary values.")

    # heap_exploitation
    if has_memory_funcs:
        malloc_count = sum(1 for s in strings if "malloc" in s.lower())
        free_count = sum(1 for s in strings if "free" in s.lower())
        has_menu = bool(patterns.get("menu_driven"))
        if malloc_count >= 1 and free_count >= 1:
            score = 80 if has_menu else 60
            conf = "High" if has_menu else "Medium"
            scores["heap_exploitation"] = (score, conf,
                "malloc/free patterns detected (likely use-after-free or heap overflow). "
                + ("Menu-driven interface suggests interactive heap exploitation." if has_menu else "Look for dangling pointers and double-free."))

    # stack_canary_bypass
    if canary and fmt_vuln:
        score = 80
        conf = "High"
        scores["stack_canary_bypass"] = (score, conf,
            "Stack canary is present but format string vulnerability can leak it — read the canary with %p, then overflow past it.")

    # rop_chain
    if nx and not pie and gadget_count >= 3:
        score = 75 if gadget_count >= 8 else 60
        conf = "High" if gadget_count >= 8 else "Medium"
        scores["rop_chain"] = (score, conf,
            f"NX enabled (no shellcode) with no PIE and {gadget_count} ROP gadgets found — build a ROP chain to call system or execve.")

    # shellcode
    if not nx:
        score = 75 if has_dangerous_funcs else 55
        conf = "High" if has_dangerous_funcs else "Medium"
        scores["shellcode"] = (score, conf,
            "NX is disabled — the stack is executable. Inject shellcode directly via a buffer overflow.")

    if not scores:
        return {
            "category": "unknown",
            "confidence": "Low",
            "explanation": "Could not confidently determine the CTF exploitation category. Try manual analysis with checksec and gdb.",
        }

    # Pick the highest-scoring category
    best_cat = max(scores, key=lambda k: scores[k][0])
    _, best_conf, best_expl = scores[best_cat]

    return {
        "category": best_cat,
        "confidence": best_conf,
        "explanation": best_expl,
    }


# ---------------------------------------------------------------------------
# Buffer Overflow Offset Predictor
# ---------------------------------------------------------------------------
def predict_overflow_offset(disassembly: list[dict]) -> dict:
    """
    Scan disassembly for stack frame allocation (sub rsp/esp, 0xXX) to
    estimate the likely buffer overflow offset.

    Returns:
        {
            "likely_offset": int | None,
            "stack_size": int | None,
            "confidence": "High" | "Medium" | "Low",
            "evidence": str
        }
    """
    sub_re = re.compile(r'(r|e)sp,\s*0x([0-9a-fA-F]+)')

    best_size = 0
    best_addr = ""

    for insn in disassembly:
        mn = insn.get("mnemonic", "").lower()
        op = insn.get("op_str", "")
        addr = insn.get("address", "")

        if mn == "sub":
            m = sub_re.search(op)
            if m:
                try:
                    size = int(m.group(2), 16)
                    # Skip tiny allocations (alignment) and huge ones (unlikely single buffer)
                    if 0x10 <= size <= 0x1000 and size > best_size:
                        best_size = size
                        best_addr = addr
                except ValueError:
                    continue

    if best_size == 0:
        return {
            "likely_offset": None,
            "stack_size": None,
            "confidence": "Low",
            "evidence": "No stack allocation (sub rsp/esp) found in disassembly.",
        }

    # The offset to overwrite the return address is typically:
    # stack_size + 8 (saved RBP) for 64-bit, stack_size + 4 for 32-bit
    # We'll estimate 64-bit by default (most common in CTFs)
    offset = best_size + 8  # saved rbp + return address starts here

    # Confidence based on whether the allocation is a "nice" size
    if best_size in (0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x100, 0x200):
        confidence = "High"
    elif best_size % 0x10 == 0:
        confidence = "Medium"
    else:
        confidence = "Low"

    return {
        "likely_offset": offset,
        "stack_size": best_size,
        "confidence": confidence,
        "evidence": f"sub rsp, 0x{best_size:x} found at {best_addr} — buffer is likely {best_size} bytes, offset to RIP ≈ {offset}",
    }


# ---------------------------------------------------------------------------
# PLT / GOT Table Parser
# ---------------------------------------------------------------------------
def get_plt_got(content: bytes) -> dict:
    """
    Parse PLT and GOT entries from an ELF binary using pyelftools.

    Returns:
        {
            "plt": [{"name": "puts", "address": "0x401030"}, ...],
            "got": [{"name": "puts", "address": "0x404018"}, ...]
        }
    """
    result = {"plt": [], "got": []}

    if not content.startswith(b"\x7fELF"):
        return result

    try:
        from elftools.elf.elffile import ELFFile
        from elftools.elf.relocation import RelocationSection
        import io as _io

        elf = ELFFile(_io.BytesIO(content))

        # --- Parse PLT ---
        # The .rela.plt (or .rel.plt) section maps PLT entries to symbol names
        for section_name in ('.rela.plt', '.rel.plt'):
            relplt = elf.get_section_by_name(section_name)
            if relplt and isinstance(relplt, RelocationSection):
                symtab = elf.get_section(relplt['sh_link'])
                for rel in relplt.iter_relocations():
                    sym = symtab.get_symbol(rel['r_info_sym'])
                    name = sym.name if sym and sym.name else f"unknown_{rel['r_offset']:x}"
                    if name:
                        result["got"].append({
                            "name": name,
                            "address": f"0x{rel['r_offset']:x}",
                        })

        # --- Parse PLT section addresses ---
        plt_section = elf.get_section_by_name('.plt')
        plt_sec_section = elf.get_section_by_name('.plt.sec')  # newer GCC
        plt_got_section = elf.get_section_by_name('.plt.got')

        # Use the PLT section with the best data
        target_plt = plt_sec_section or plt_section
        if target_plt:
            plt_addr = target_plt['sh_addr']
            plt_size = target_plt['sh_size']
            entry_size = target_plt['sh_entsize'] or 16  # default PLT entry = 16 bytes

            # Build PLT entries — first entry is the resolver, skip it
            got_names = [g["name"] for g in result["got"]]
            for i, name in enumerate(got_names):
                addr = plt_addr + (i + 1) * entry_size
                if addr < plt_addr + plt_size:
                    result["plt"].append({
                        "name": name,
                        "address": f"0x{addr:x}",
                    })

        # Cap results
        result["plt"] = result["plt"][:50]
        result["got"] = result["got"][:50]

    except Exception as e:
        logger.warning("PLT/GOT parsing failed: %s", e)

    return result


# ---------------------------------------------------------------------------
# Difficulty Predictor
# ---------------------------------------------------------------------------
def predict_difficulty(checksec: dict, patterns: dict, ctf_category: dict) -> dict:
    """
    Predict CTF challenge difficulty based on binary protections and patterns.

    Scoring:
    - No PIE + No Canary + No NX = Easy
    - PIE disabled + Canary or NX = Medium
    - Full RELRO + PIE + Canary + NX = Hard

    Returns:
        {"difficulty": "Easy"|"Medium"|"Hard", "score": int, "reason": str}
    """
    nx = checksec.get("nx", True)
    pie = checksec.get("pie", True)
    canary = checksec.get("canary", True)
    relro = checksec.get("relro", True)

    # Count enabled protections
    score = 0
    reasons_hard = []
    reasons_easy = []

    if nx:
        score += 1
        reasons_hard.append("NX enabled")
    else:
        reasons_easy.append("NX disabled (stack executable)")

    if pie:
        score += 2  # PIE is the hardest to bypass
        reasons_hard.append("PIE enabled")
    else:
        reasons_easy.append("No PIE (fixed addresses)")

    if canary:
        score += 1
        reasons_hard.append("Stack canary present")
    else:
        reasons_easy.append("No stack canary")

    if relro:
        score += 1
        reasons_hard.append("RELRO enabled")
    else:
        reasons_easy.append("No RELRO (GOT writable)")

    # Category-based adjustments
    category = ctf_category.get("category", "unknown")
    if category in ("ret2win",):
        score = max(0, score - 1)  # ret2win is inherently simpler
    elif category in ("heap_exploitation", "stack_canary_bypass"):
        score += 1  # these are inherently harder

    # Determine difficulty
    if score <= 1:
        difficulty = "Easy"
        reason = " • ".join(reasons_easy) if reasons_easy else "Minimal protections"
    elif score <= 3:
        difficulty = "Medium"
        combined = reasons_easy + reasons_hard
        reason = " • ".join(combined[:3]) if combined else "Some protections enabled"
    else:
        difficulty = "Hard"
        reason = " • ".join(reasons_hard) if reasons_hard else "Full protections enabled"

    return {
        "difficulty": difficulty,
        "score": score,
        "reason": reason,
    }


# ---------------------------------------------------------------------------
# Single-file analysis helper
# ---------------------------------------------------------------------------
def _analyze_single_file(
    content: bytes,
    filename: str,
    ext: str,
    detected_type: str = "",
    skip_virustotal: bool = False,
) -> dict:
    """
    Analyze a single binary file's content.  Writes to a temp file, extracts
    strings, detects patterns/flags, and generates AI hints.
    The temp file is ALWAYS deleted after processing.

    skip_virustotal: if True, VirusTotal submission is skipped entirely.
    """
    tmp_path: str | None = None
    try:
        suffix = ext if ext else ".bin"
        fd, tmp_path = tempfile.mkstemp(suffix=suffix, dir=tempfile.gettempdir())
        os.write(fd, content)
        os.close(fd)

        strings = _run_strings(tmp_path)
        patterns = detect_patterns(strings)
        flags = detect_flags(strings)
        risk = calculate_risk_score(patterns, flags)
        encodings = detect_encodings(strings)

        # VirusTotal: optional — only submit if requested by the client
        if skip_virustotal:
            vt_result = {"status": "disabled", "message": "VirusTotal scan was skipped."}
        else:
            vt_result = submit_virustotal(content, filename)

        # Checksec: detect binary security protections
        checksec_result = run_checksec(tmp_path)

        # Hex view: first 512 bytes
        hex_view = get_hex_view(content)

        # Disassembly: main function or entry point
        disasm_result = disassemble_binary(content)
        disassembly = disasm_result.get("instructions", [])
        disassembly_function = disasm_result.get("function", "")

        # Deep static analysis for ELFs
        function_list = []
        imports_exports = {"imports": [], "exports": []}
        data_flows = []
        cvss = {"cvss_score": 0.0, "cvss_severity": "None"}

        if ext in (".elf", ".so", "") and content.startswith(b"\x7fELF"):
            try:
                elffile = ELFFile(io.BytesIO(content))
                function_list = get_function_list(elffile)
                imports_exports = get_imports_exports(elffile)
                data_flows = analyze_data_flow(disassembly, patterns)
                cvss = calculate_cvss_score(patterns, flags, checksec_result)
            except Exception as e:
                logger.warning("Failed to parse ELF for deep analysis: %s", e)

        # CTF-focused analysis modules
        rop_gadgets = find_rop_gadgets(content)
        format_string = detect_format_string(strings, patterns)
        libc_info = identify_libc(strings)
        ctf_category = detect_ctf_category(
            patterns, checksec_result, strings,
            format_string_result=format_string,
            rop_gadgets=rop_gadgets,
            imports_exports=imports_exports,
        )

        # Overflow offset prediction, PLT/GOT, and difficulty
        overflow_hint = predict_overflow_offset(disassembly)
        plt_got = get_plt_got(content)
        difficulty = predict_difficulty(checksec_result, patterns, ctf_category)

        # AI hints — pass CTF category for category-aware prompting
        hints = get_ai_hints(strings, patterns, ctf_category=ctf_category)

        # AI decompilation hints — explain disassembly using AI
        decompilation_hints = get_decompilation_hints(
            disassembly, strings, ctf_category=ctf_category,
        )

        # Pwntools exploit template — uses predicted offset, ROP gadgets, libc info
        pwn_template = generate_pwn_template(
            filename, content, checksec_result, patterns, strings,
            overflow_hint=overflow_hint,
            rop_gadgets=rop_gadgets,
            libc_info=libc_info,
        )

        result = {
            "filename": filename,
            "size_bytes": len(content),
            "extension": ext or "(none)",
            "strings_count": len(strings),
            "strings": strings,
            "patterns": patterns,
            "flags_detected": flags,
            "hints": hints,
            "cvss_score": cvss["cvss_score"],
            "cvss_severity": cvss["cvss_severity"],
            "encodings": encodings,
            "virustotal": vt_result,
            "checksec": checksec_result,
            "hex_view": hex_view,
            "pwn_template": pwn_template,
            "disassembly": disassembly,
            "disassembly_function": disassembly_function,
            "decompilation_hints": decompilation_hints,
            "function_list": function_list,
            "imports_exports": imports_exports,
            "data_flows": data_flows,
            "rop_gadgets": rop_gadgets,
            "format_string": format_string,
            "libc_info": libc_info,
            "ctf_category": ctf_category,
            "overflow_hint": overflow_hint,
            "plt_got": plt_got,
            "difficulty": difficulty,
        }
        if detected_type:
            result["detected_type"] = detected_type
        return result
    finally:
        if tmp_path and os.path.exists(tmp_path):
            os.unlink(tmp_path)


# ---------------------------------------------------------------------------
# ZIP analysis helper
# ---------------------------------------------------------------------------
def _analyze_zip(
    content: bytes,
    original_filename: str,
    password: str | None = None,
    skip_virustotal: bool = False,
) -> dict:
    """
    Extract a ZIP archive into a temp directory, analyze every binary
    file found inside, and return results for each file.

    Security:
    • Rejects ZIPs > MAX_ZIP_SIZE (10 MB).
    • Rejects ZIPs with > MAX_ZIP_FILES entries (zip-bomb protection).
    • Never executes any extracted file.
    • Always deletes the temp directory in try/finally.
    • Password is NEVER stored or logged — used only for extraction.
    """
    import io

    try:
        zf = zipfile.ZipFile(io.BytesIO(content))
    except zipfile.BadZipFile:
        raise HTTPException(status_code=400, detail="File is not a valid ZIP archive.")

    # ── Detect password-protected ZIP ─────────────────────────────────
    _has_encrypted = any(
        info.flag_bits & 0x1  # bit 0 = encrypted
        for info in zf.infolist()
    )
    if _has_encrypted and not password:
        return JSONResponse(
            status_code=422,
            content={
                "detail": "This ZIP archive is password-protected.",
                "error_code": "password_required",
            },
        )

    # ── Zip-bomb protection ───────────────────────────────────────────
    entries = zf.namelist()
    if len(entries) > MAX_ZIP_FILES:
        raise HTTPException(
            status_code=400,
            detail=f"ZIP contains {len(entries)} files — maximum {MAX_ZIP_FILES} allowed (zip-bomb protection).",
        )

    # Check total uncompressed size
    total_uncompressed = sum(info.file_size for info in zf.infolist())
    if total_uncompressed > MAX_ZIP_SIZE:
        raise HTTPException(
            status_code=400,
            detail=f"ZIP uncompressed size ({total_uncompressed // (1024 * 1024)} MB) exceeds the {MAX_ZIP_SIZE // (1024 * 1024)} MB limit.",
        )

    tmp_dir: str | None = None
    try:
        tmp_dir = tempfile.mkdtemp(prefix="binexplain_zip_", dir=tempfile.gettempdir())

        # Extract with optional password
        pwd_bytes = password.encode("utf-8") if password else None
        try:
            zf.extractall(tmp_dir, pwd=pwd_bytes)
        except NotImplementedError:
            # stdlib zipfile can't handle AES encryption (compress_type 99).
            # Fall back to pyzipper which supports AES decryption.
            try:
                import pyzipper
            except ImportError:
                raise HTTPException(
                    status_code=400,
                    detail="This ZIP uses AES encryption which requires the 'pyzipper' package. Please install it.",
                )
            try:
                pzf = pyzipper.AESZipFile(io.BytesIO(content))
                pzf.extractall(tmp_dir, pwd=pwd_bytes)
            except RuntimeError as exc:
                exc_msg = str(exc).lower()
                if "password" in exc_msg or "bad password" in exc_msg or "wrong password" in exc_msg or "crc" in exc_msg:
                    if password:
                        return JSONResponse(
                            status_code=422,
                            content={
                                "detail": "Incorrect password for this ZIP archive.",
                                "error_code": "wrong_password",
                            },
                        )
                    else:
                        return JSONResponse(
                            status_code=422,
                            content={
                                "detail": "This ZIP archive is password-protected.",
                                "error_code": "password_required",
                            },
                        )
                raise HTTPException(status_code=400, detail=f"Failed to extract ZIP: {str(exc)[:200]}")
            except Exception as exc:
                exc_msg = str(exc).lower()
                if "password" in exc_msg or "bad password" in exc_msg or "wrong password" in exc_msg:
                    if password:
                        return JSONResponse(
                            status_code=422,
                            content={
                                "detail": "Incorrect password for this ZIP archive.",
                                "error_code": "wrong_password",
                            },
                        )
                    else:
                        return JSONResponse(
                            status_code=422,
                            content={
                                "detail": "This ZIP archive is password-protected.",
                                "error_code": "password_required",
                            },
                        )
                raise
        except RuntimeError as exc:
            # zipfile raises RuntimeError for wrong password / missing password
            exc_msg = str(exc).lower()
            if "password" in exc_msg or "bad password" in exc_msg or "encrypted" in exc_msg:
                if password:
                    return JSONResponse(
                        status_code=422,
                        content={
                            "detail": "Incorrect password for this ZIP archive.",
                            "error_code": "wrong_password",
                        },
                    )
                else:
                    return JSONResponse(
                        status_code=422,
                        content={
                            "detail": "This ZIP archive is password-protected.",
                            "error_code": "password_required",
                        },
                    )
            raise HTTPException(status_code=400, detail=f"Failed to extract ZIP: {str(exc)[:200]}")
        except Exception as exc:
            # pyzipper or other extraction errors for wrong password
            exc_msg = str(exc).lower()
            if "password" in exc_msg or "bad password" in exc_msg or "wrong password" in exc_msg:
                if password:
                    return JSONResponse(
                        status_code=422,
                        content={
                            "detail": "Incorrect password for this ZIP archive.",
                            "error_code": "wrong_password",
                        },
                    )
                else:
                    return JSONResponse(
                        status_code=422,
                        content={
                            "detail": "This ZIP archive is password-protected.",
                            "error_code": "password_required",
                        },
                    )
            raise
        finally:
            # Clear password from memory immediately after extraction
            pwd_bytes = None

        results: list[dict] = []
        skipped: list[dict] = []

        for entry in entries:
            entry_path = os.path.join(tmp_dir, entry)

            # Skip directories
            if os.path.isdir(entry_path):
                continue

            # Read file content
            try:
                with open(entry_path, "rb") as f:
                    file_content = f.read()
            except (OSError, IOError):
                skipped.append({"filename": entry, "reason": "Could not read file."})
                continue

            if len(file_content) == 0:
                skipped.append({"filename": entry, "reason": "File is empty."})
                continue

            if len(file_content) > MAX_FILE_SIZE:
                skipped.append({"filename": entry, "reason": "File exceeds 5 MB limit."})
                continue

            # Determine extension and validate
            inner_ext = Path(entry).suffix.lower()
            detected_type = ""

            if inner_ext == "":
                # Extensionless — try magic byte detection
                try:
                    detected_type = _detect_type_from_magic(file_content)
                except HTTPException:
                    skipped.append({"filename": entry, "reason": "Unknown file type (no extension, no known magic bytes)."})
                    continue
            elif inner_ext == ".zip":
                skipped.append({"filename": entry, "reason": "Nested ZIP archives are not supported."})
                continue
            elif inner_ext not in ALLOWED_EXTENSIONS:
                skipped.append({"filename": entry, "reason": f"Extension '{inner_ext}' is not a supported binary format."})
                continue
            else:
                # Validate magic bytes for known formats
                if inner_ext in FILE_SIGNATURES:
                    expected = FILE_SIGNATURES[inner_ext]
                    if not file_content[:len(expected)] == expected:
                        skipped.append({"filename": entry, "reason": f"Magic bytes don't match expected format for '{inner_ext}'."})
                        continue

                # Reject suspicious content for generic extensions
                header = file_content[:64].lower()
                is_suspicious = any(header.startswith(sig) for sig in SUSPICIOUS_HEADERS)
                if is_suspicious:
                    skipped.append({"filename": entry, "reason": "File appears to be a script or markup, not a binary."})
                    continue

            # Analyze this binary
            try:
                result = _analyze_single_file(file_content, entry, inner_ext, detected_type, skip_virustotal=skip_virustotal)
                results.append(result)
            except Exception as exc:
                logger.warning("Failed to analyze '%s' from ZIP: %s", entry, exc)
                skipped.append({"filename": entry, "reason": f"Analysis failed: {exc}"})

        if not results:
            raise HTTPException(
                status_code=400,
                detail="No analyzable binary files found in the ZIP archive.",
            )

        return {
            "archive": original_filename,
            "total_entries": len(entries),
            "analyzed_count": len(results),
            "skipped_count": len(skipped),
            "results": results,
            "skipped": skipped,
        }
    finally:
        # ALWAYS delete the extracted directory — no exceptions.
        if tmp_dir and os.path.exists(tmp_dir):
            shutil.rmtree(tmp_dir, ignore_errors=True)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
@app.get("/health")
async def health():
    """Lightweight health-check — returns ``{"status": "ok"}``."""
    return {"status": "ok"}


@app.post("/analyze")
@limiter.limit("10/hour")
async def analyze(
    request: Request,
    file: UploadFile = File(...),
    password: str | None = Form(default=None),
    skip_virustotal: str = Form(default="false"),
):
    """
    Accept a binary file upload, validate it strictly, extract readable
    strings via static analysis, and return the results as JSON.

    Supports:
    • Named binary files (.bin, .elf, .exe, .so, .dll, .out, .o)
    • Extensionless files (auto-detected via magic bytes — ELF, PE, Mach-O)
    • ZIP archives (extracts and analyzes each binary inside)
    • Password-protected ZIP archives (password provided via form field)

    The uploaded file is saved to a temporary location and **always**
    deleted after processing — even when an error occurs.

    Security:
    • Password is NEVER stored or logged — used only for ZIP extraction.
    • Wrong password attempts are counted in the rate limit.
    """
    skip_vt = skip_virustotal.lower() in ("true", "1", "yes")

    # ── 1. Validate extension (before reading the full body) ──────────
    ext = _validate_extension(file.filename)

    # ── 2. Read content into memory & validate size ───────────────────
    content = await file.read()
    _validate_size(content, is_zip=(ext == ".zip"))

    # ── 3. Handle ZIP archives ────────────────────────────────────────
    if ext == ".zip":
        _validate_mime(content, ext)
        # Pass password (never logged) — clear from locals immediately after
        zip_password = password
        password = None  # clear from function scope
        try:
            return _analyze_zip(content, file.filename or "archive.zip", password=zip_password, skip_virustotal=skip_vt)
        finally:
            zip_password = None  # clear from memory

    # ── 4. Auto-detect extensionless files via magic bytes ────────────
    detected_type = ""
    if ext == "":
        detected_type = _detect_type_from_magic(content)
    else:
        # ── 5. Validate content signature / MIME ──────────────────────
        _validate_mime(content, ext)

    # ── 6. Analyze the single binary ─────────────────────────────────
    return _analyze_single_file(content, file.filename or "unknown", ext, detected_type, skip_virustotal=skip_vt)


@app.post("/analyze-code")
@limiter.limit("10/hour")
async def analyze_code_endpoint(request: Request, body: CodeAnalysisRequest):
    """
    Analyze source code for vulnerabilities and dangerous patterns.

    Accepts source code as text (max 10,000 characters), sends to AI
    (Claude → Groq → OpenAI → Ollama fallback), and returns structured
    analysis results.

    Security:
    • Code is NEVER stored to disk or executed.
    • Code is only sent to AI APIs in memory.
    • No temp files are created.
    • Rate limited to 10 requests per hour per IP.
    """
    return analyze_source_code(body.code, body.filename)


@app.get("/virustotal/{scan_id}")
@limiter.limit("30/hour")
async def get_virustotal_result(request: Request, scan_id: str):
    """
    Poll for VirusTotal scan results by scan_id.

    Returns the current status of the background VT scan:
    • {"status": "scanning"} — still in progress
    • {"status": "clean/suspicious/malicious", ...} — completed
    • {"status": "pending", ...} — VT timed out, check permalink
    • 404 — unknown scan_id
    """
    if scan_id not in _vt_scans:
        raise HTTPException(status_code=404, detail="Unknown scan ID.")

    entry = _vt_scans[scan_id].copy()
    # Strip internal fields
    entry.pop("_created", None)
    return entry


# ---------------------------------------------------------------------------
# POST /feedback — anonymous hint quality feedback
# ---------------------------------------------------------------------------
class FeedbackRequest(BaseModel):
    vote: Literal["up", "down"]
    filename: str = ""

    @field_validator("filename")
    @classmethod
    def cap_filename(cls, v: str) -> str:
        return v[:200]


@app.post("/feedback")
@limiter.limit("30/hour")
async def submit_feedback(request: Request, body: FeedbackRequest):
    """
    Accept anonymous thumbs-up/down feedback on AI hints.

    Nothing is stored — the vote is logged to stdout only for now.
    Rate limited to 30/hour per IP to prevent abuse.
    """
    logger.info(
        "[Feedback] vote=%s filename=%s ip=%s",
        body.vote,
        body.filename or "(none)",
        get_remote_address(request),
    )
    return {"status": "ok", "message": "Thanks for your feedback!"}


@app.post("/chat")
@limiter.limit("20/hour")
async def chat(request: Request, body: ChatRequest):
    """
    Conversational follow-up endpoint.

    Accepts the full conversation history from the client (nothing is stored
    server-side) plus the initial analysis context, forwards to Anthropic
    Claude (with Ollama fallback), and returns a single AI response.

    Security:
    • Max 10 messages in history, max 2000 chars per message.
    • No database, no file writes, no storage of any kind.
    • User text goes directly to the AI only.
    """
    # ── Validate message count ────────────────────────────────────────
    if len(body.messages) > MAX_CHAT_MESSAGES:
        raise HTTPException(
            status_code=400,
            detail=f"Too many messages. Maximum {MAX_CHAT_MESSAGES} allowed.",
        )

    if not body.messages:
        raise HTTPException(status_code=400, detail="No messages provided.")

    # ── Build message list for the AI ─────────────────────────────────
    ai_messages: list[dict] = []

    # Inject analysis context as a leading user→assistant exchange so the
    # AI knows what binary was analysed.
    if body.context:
        ai_messages.append({
            "role": "user",
            "content": "Here is the initial analysis summary of the binary I uploaded:\n\n" + body.context[:MAX_CHAT_CHARS],
        })
        ai_messages.append({
            "role": "assistant",
            "content": "Got it — I've reviewed the analysis. Ask me anything about this binary!",
        })

    # Append the actual conversation history
    for msg in body.messages:
        ai_messages.append({"role": msg.role, "content": msg.content})

    # ── Try Anthropic Claude first ────────────────────────────────────
    if ANTHROPIC_API_KEY:
        try:
            client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
            response = client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=1024,
                system=CHAT_SYSTEM_PROMPT,
                messages=ai_messages,
            )
            return {"response": response.content[0].text}
        except Exception as exc:
            logger.warning("Anthropic chat call failed: %s", exc)

    # ── Fallback 1: Groq ──────────────────────────────────────────────
    groq_result = _try_groq(messages=ai_messages, system_prompt=CHAT_SYSTEM_PROMPT)
    if groq_result:
        return {"response": groq_result}

    # ── Fallback 2: OpenAI GPT-4o-mini ────────────────────────────────
    openai_result = _try_openai(messages=ai_messages, system_prompt=CHAT_SYSTEM_PROMPT)
    if openai_result:
        return {"response": openai_result}

    # ── Fallback 3: Ollama multi-turn chat ────────────────────────────
    ollama_messages = [{"role": "system", "content": CHAT_SYSTEM_PROMPT}] + ai_messages
    ollama_result = _try_ollama_chat(ollama_messages)
    if ollama_result:
        return {"response": ollama_result}

    raise HTTPException(
        status_code=503,
        detail="Chat is temporarily unavailable — Anthropic, Groq, OpenAI, and Ollama all failed.",
    )


# ---------------------------------------------------------------------------
# Image analysis endpoint  (Claude Vision)
# ---------------------------------------------------------------------------
MAX_IMAGE_SIZE = 5 * 1024 * 1024  # 5 MB
ALLOWED_IMAGE_EXTENSIONS: set[str] = {".png", ".jpg", ".jpeg", ".gif", ".webp"}
IMAGE_MAGIC_BYTES: dict[bytes, str] = {
    b"\x89PNG":      "image/png",
    b"\xff\xd8\xff": "image/jpeg",
    b"GIF87a":       "image/gif",
    b"GIF89a":       "image/gif",
    b"RIFF":         "image/webp",   # RIFF....WEBP
}

IMAGE_ANALYSIS_PROMPT = (
    "You are a CTF mentor analyzing a screenshot from a student working on a "
    "binary exploitation challenge. Look at the screenshot carefully and provide "
    "specific actionable next steps in bullet points only. Include exact commands. "
    "Be encouraging."
)


def _validate_image_magic(content: bytes) -> str:
    """Validate image by magic bytes.  Returns MIME type or raises HTTPException."""
    for magic, mime in IMAGE_MAGIC_BYTES.items():
        if content[:len(magic)] == magic:
            # Extra check for WEBP — RIFF header must include WEBP marker
            if magic == b"RIFF" and b"WEBP" not in content[:12]:
                continue
            return mime
    raise HTTPException(
        status_code=400,
        detail="File does not appear to be a valid image (PNG, JPG, GIF, or WEBP).",
    )


@app.post("/analyze-image")
@limiter.limit("10/hour")
async def analyze_image(
    request: Request,
    file: UploadFile = File(...),
    context: str = "",
):
    """
    Analyze a screenshot using AI vision with full fallback chain.

    Fallback order:
    1. Claude Vision (claude-sonnet-4-20250514)
    2. OpenAI GPT-4o-mini Vision
    3. Groq Vision (llama-3.2-11b-vision-preview)
    4. Ollama llava (local, free)
    5. Final fallback error message

    Security invariants:
    • Image is NEVER stored to disk — only held in memory as bytes/base64.
    • Base64 string is discarded after the API call.
    • Magic bytes validated before processing.
    • Rate limited to 10 requests/hour.
    """
    import base64

    # ── Validate extension ────────────────────────────────────────────
    ext = ""
    if file.filename:
        dot = file.filename.rfind(".")
        if dot != -1:
            ext = file.filename[dot:].lower()
    if ext and ext not in ALLOWED_IMAGE_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid image type '{ext}'. Accepted: {', '.join(sorted(ALLOWED_IMAGE_EXTENSIONS))}",
        )

    # ── Read and validate size ────────────────────────────────────────
    content = await file.read()
    if len(content) > MAX_IMAGE_SIZE:
        raise HTTPException(
            status_code=400,
            detail=f"Image too large ({len(content) / 1024 / 1024:.1f} MB). Maximum: 5 MB.",
        )
    if len(content) == 0:
        raise HTTPException(status_code=400, detail="Image file is empty.")

    # ── Validate magic bytes ──────────────────────────────────────────
    mime_type = _validate_image_magic(content)

    # ── Convert to base64 ─────────────────────────────────────────────
    image_b64 = base64.b64encode(content).decode("utf-8")
    # Content bytes no longer needed
    del content

    # ── Build Prompts ─────────────────────────────────────────────────
    if context:
        prompt_text = (
            "Here is the analysis context of the binary I'm working on:\n\n"
            + context[:3000]
            + "\n\nNow here is my screenshot — please analyze it and tell me what to do next:"
        )
    else:
        prompt_text = "I'm working on a CTF binary challenge. Here is my screenshot — please analyze it and tell me what to do next:"

    ai_response = None

    # ── Call Claude Vision ────────────────────────────────────────────
    if ANTHROPIC_API_KEY:
        try:
            client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
            response = client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=1024,
                system=IMAGE_ANALYSIS_PROMPT,
                messages=[{
                    "role": "user",
                    "content": [
                        {"type": "text", "text": prompt_text},
                        {
                            "type": "image",
                            "source": {
                                "type": "base64",
                                "media_type": mime_type,
                                "data": image_b64,
                            }
                        }
                    ]
                }],
            )
            ai_response = response.content[0].text
        except Exception as exc:
            logger.error("Claude Vision call failed: %s", exc)

    # ── Fallback 1: GPT-4o-mini (Vision) ──────────────────────────────
    if not ai_response and OPENAI_API_KEY:
        try:
            client = openai.OpenAI(api_key=OPENAI_API_KEY)
            response = client.chat.completions.create(
                model="gpt-4o-mini",
                max_tokens=1024,
                messages=[
                    {"role": "system", "content": IMAGE_ANALYSIS_PROMPT},
                    {
                        "role": "user",
                        "content": [
                            {"type": "text", "text": prompt_text},
                            {
                                "type": "image_url",
                                "image_url": {"url": f"data:{mime_type};base64,{image_b64}"}
                            }
                        ]
                    }
                ]
            )
            val = response.choices[0].message.content
            if val and val.strip():
                ai_response = val.strip()
        except Exception as exc:
            logger.error("GPT-4o Vision call failed: %s", exc)

    # ── Fallback 2: Groq Vision (llama-3.2-11b-vision-preview) ────────
    if not ai_response and GROQ_API_KEY:
        try:
            client = groq.Groq(api_key=GROQ_API_KEY)
            response = client.chat.completions.create(
                model="llama-3.2-11b-vision-preview",
                max_tokens=1024,
                messages=[
                    {"role": "system", "content": IMAGE_ANALYSIS_PROMPT},
                    {
                        "role": "user",
                        "content": [
                            {"type": "text", "text": prompt_text},
                            {
                                "type": "image_url",
                                "image_url": {"url": f"data:{mime_type};base64,{image_b64}"}
                            }
                        ]
                    }
                ]
            )
            val = response.choices[0].message.content
            if val and val.strip():
                ai_response = val.strip()
        except Exception as exc:
            logger.error("Groq Vision call failed: %s", exc)

    # ── Fallback 3: Ollama llava (local, free) ────────────────────────
    if not ai_response:
        try:
            resp = requests.post(
                f"{OLLAMA_BASE_URL}/api/generate",
                json={
                    "model": "llava",
                    "prompt": IMAGE_ANALYSIS_PROMPT + "\n\n" + prompt_text,
                    "images": [image_b64],
                    "stream": False,
                },
                timeout=120,
            )
            if resp.status_code == 200:
                data = resp.json()
                val = data.get("response", "").strip()
                if val:
                    ai_response = val
        except Exception as exc:
            logger.error("Ollama llava call failed: %s", exc)

    # Ensure base64 is cleared from memory
    image_b64 = ""
    del image_b64

    # ── Final Fallback Message ────────────────────────────────────────
    if not ai_response:
        ai_response = (
            "Image analysis unavailable \u2014 all AI providers failed. "
            "Try describing what you see in the chat instead."
        )

    return {"response": ai_response}


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
