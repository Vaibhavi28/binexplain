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

from fastapi import FastAPI, File, HTTPException, Request, UploadFile
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

OLLAMA_BASE_URL = "http://localhost:11434"
OLLAMA_MODELS = ["llama3.2", "qwen2.5-coder", "qwen2.5"]

ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY") or ""
GROQ_API_KEY = os.environ.get("GROQ_API_KEY") or ""
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY") or ""

# ── Startup debug: confirm API key status ─────────────────────────────
if ANTHROPIC_API_KEY:
    print(f"[BinExplain] ANTHROPIC_API_KEY loaded ✓  (length={len(ANTHROPIC_API_KEY)})")
else:
    print("[BinExplain] WARNING: ANTHROPIC_API_KEY is NOT set — Claude hints will be disabled")

if GROQ_API_KEY:
    print(f"[BinExplain] GROQ_API_KEY loaded ✓  (length={len(GROQ_API_KEY)})")
else:
    print("[BinExplain] WARNING: GROQ_API_KEY is NOT set — Groq fallback will be disabled")

if OPENAI_API_KEY:
    print(f"[BinExplain] OPENAI_API_KEY loaded ✓  (length={len(OPENAI_API_KEY)})")
else:
    print("[BinExplain] WARNING: OPENAI_API_KEY is NOT set — GPT-4o fallback will be disabled")

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
    allow_origins=["*"],          # ← tighten to your frontend origin in production
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
        if not content[:4] == b"PK\x03\x04":
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
# Entropy analysis
# ---------------------------------------------------------------------------
def calculate_entropy(data: bytes) -> float:
    """
    Calculate Shannon entropy of binary data.

    Returns a float between 0.0 and 8.0:
    • < 5.0  → normal binary (code, data sections)
    • 5.0–7.0 → compressed data or dense content
    • > 7.0  → likely packed, encrypted, or compressed
    """
    import math
    if not data:
        return 0.0
    freq = [0] * 256
    for byte in data:
        freq[byte] += 1
    length = len(data)
    entropy = 0.0
    for count in freq:
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)
    return round(entropy, 3)


def _entropy_label(entropy: float) -> str:
    """Return a human-readable label for an entropy value."""
    if entropy < 5.0:
        return "Low"
    elif entropy < 6.5:
        return "Medium"
    elif entropy < 7.0:
        return "High"
    else:
        return "Very High (packed/encrypted)"


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
# YARA-style pattern matching (pure Python — no yara-python dependency)
# ---------------------------------------------------------------------------
_IP_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
_URL_RE = re.compile(r'https?://[^\s\x00]+', re.IGNORECASE)
_FORMAT_STRING_RE = re.compile(r'%[0-9]*[nxspdl]', re.IGNORECASE)

# Rule definitions: (id, label, description)
_YARA_RULES: list[tuple[str, str, str]] = [
    ("shellcode",             "Shellcode / NOP Sled",          "NOP sled or shellcode-like byte patterns detected"),
    ("format_string_vuln",    "Format String Vulnerability",   "printf/sprintf format specifiers with potential user input"),
    ("hardcoded_credentials", "Hardcoded Credentials",         "Embedded passwords, usernames, or API keys"),
    ("network_indicators",    "Network Indicators",            "URLs, IP addresses, or network connection strings"),
    ("crypto_indicators",     "Crypto / Encryption",           "References to cryptographic algorithms or key material"),
    ("anti_debug",            "Anti-Debug Techniques",         "Debugger detection or anti-analysis tricks"),
    ("heap_spray",            "Heap Spray / Mass Allocation",  "Patterns suggesting heap spraying or repeated allocation"),
    ("rop_gadgets",           "ROP Gadget Indicators",         "Return-oriented programming gadget references"),
    ("win_condition",         "Win / Flag Condition",          "Functions or code paths that reveal the flag"),
    ("packed_binary",         "Packed / Encrypted Binary",     "Very high entropy with few readable strings — likely packed"),
]


def detect_yara_patterns(
    strings: list[str],
    content: bytes,
    entropy: float,
    strings_count: int,
) -> list[dict]:
    """
    Pure-Python YARA-style pattern matching.  Scans extracted strings and
    raw binary content against 10 heuristic rules.

    Returns a list of dicts: [{ rule, label, description, matches }]
    Only rules with at least one match are returned.
    """
    results: list[dict] = []
    rule_map = {r[0]: (r[1], r[2]) for r in _YARA_RULES}
    matches_by_rule: dict[str, list[str]] = {r[0]: [] for r in _YARA_RULES}

    # --- Raw bytes scan for shellcode ---
    # NOP sled: 4+ consecutive 0x90 bytes
    if b"\x90\x90\x90\x90" in content:
        matches_by_rule["shellcode"].append("NOP sled (\\x90\\x90\\x90\\x90) found in binary")

    for s in strings:
        s_lower = s.lower()

        # shellcode — string-level hints
        if "shellcode" in s_lower or "nop sled" in s_lower or "\\x90\\x90" in s:
            matches_by_rule["shellcode"].append(s[:80])

        # format_string_vuln — printf-family with format specifiers
        if any(fn in s for fn in ("printf", "sprintf", "fprintf", "snprintf")):
            fmt_matches = _FORMAT_STRING_RE.findall(s)
            if fmt_matches:
                matches_by_rule["format_string_vuln"].append(s[:80])

        # hardcoded_credentials
        cred_patterns = ("password=", "passwd=", "admin:", "root:", "secret=",
                         "api_key=", "apikey=", "token=", "auth=")
        if any(cp in s_lower for cp in cred_patterns):
            matches_by_rule["hardcoded_credentials"].append(s[:80])

        # network_indicators
        if _URL_RE.search(s):
            matches_by_rule["network_indicators"].append(s[:100])
        elif _IP_RE.search(s):
            # Filter out common non-network IPs (version strings like "2.0.0.0")
            ip_match = _IP_RE.search(s)
            if ip_match:
                octets = ip_match.group().split(".")
                if not all(o == "0" for o in octets[1:]):  # skip x.0.0.0 version strings
                    matches_by_rule["network_indicators"].append(s[:100])

        # crypto_indicators
        crypto_kw = ("aes", "rsa", "md5", "sha1", "sha256", "sha512",
                     "encrypt", "decrypt", "cipher", "blowfish", "des3")
        if any(kw in s_lower for kw in crypto_kw):
            matches_by_rule["crypto_indicators"].append(s[:80])

        # anti_debug
        anti_dbg = ("ptrace", "isdebuggerpresent", "debugger", "ntquerysysteminformation",
                    "checkremotedebuggerpresent", "outputdebugstring", "int3")
        if any(kw in s_lower for kw in anti_dbg):
            matches_by_rule["anti_debug"].append(s[:80])

        # heap_spray — multiple malloc/calloc references or large sizes
        if "malloc" in s and any(c.isdigit() for c in s):
            matches_by_rule["heap_spray"].append(s[:80])
        elif "calloc" in s_lower or "heap spray" in s_lower:
            matches_by_rule["heap_spray"].append(s[:80])

        # rop_gadgets
        rop_kw = ("pop rdi", "pop rsi", "pop rdx", "pop rax",
                  "ret;", "gadget", "rop chain", "pop ebp", "pop esp")
        if any(kw in s_lower for kw in rop_kw):
            matches_by_rule["rop_gadgets"].append(s[:80])

        # win_condition
        win_kw = ("win(", "get_flag", "print_flag", "cat flag",
                  "read_flag", "open_flag", "give_shell", "spawn_shell")
        if any(kw in s_lower for kw in win_kw):
            matches_by_rule["win_condition"].append(s[:80])

    # packed_binary — high entropy + very few strings
    if entropy > 7.0 and strings_count < 20:
        matches_by_rule["packed_binary"].append(
            f"Entropy {entropy:.3f}/8.0 with only {strings_count} strings"
        )

    # Build output — only rules with matches
    for rule_id, (label, description) in rule_map.items():
        match_list = matches_by_rule[rule_id]
        if match_list:
            # Deduplicate and cap at 10
            deduped = list(dict.fromkeys(match_list))[:10]
            results.append({
                "rule": rule_id,
                "label": label,
                "description": description,
                "matches": deduped,
                "count": len(deduped),
            })

    return results


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
def get_ai_hints(strings: list[str], patterns: dict[str, list[str]]) -> str:
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

    # ── Fallback 1: try Groq ───────────────────────────────────────────
    groq_result = _try_groq(
        messages=[{"role": "user", "content": user_message}],
        system_prompt=AI_SYSTEM_PROMPT,
    )
    if groq_result:
        return groq_result

    # ── Fallback 2: try OpenAI GPT-4o-mini ────────────────────────────
    openai_result = _try_openai(
        messages=[{"role": "user", "content": user_message}],
        system_prompt=AI_SYSTEM_PROMPT,
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
# Single-file analysis helper
# ---------------------------------------------------------------------------
def _analyze_single_file(
    content: bytes,
    filename: str,
    ext: str,
    detected_type: str = "",
) -> dict:
    """
    Analyze a single binary file's content.  Writes to a temp file, extracts
    strings, detects patterns/flags, and generates AI hints.
    The temp file is ALWAYS deleted after processing.
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
        hints = get_ai_hints(strings, patterns)
        risk = calculate_risk_score(patterns, flags)
        entropy = calculate_entropy(content)
        encodings = detect_encodings(strings)
        yara = detect_yara_patterns(strings, content, entropy, len(strings))

        result = {
            "filename": filename,
            "size_bytes": len(content),
            "extension": ext or "(none)",
            "strings_count": len(strings),
            "strings": strings,
            "patterns": patterns,
            "flags_detected": flags,
            "hints": hints,
            "risk_score": risk,
            "entropy": entropy,
            "entropy_label": _entropy_label(entropy),
            "encodings": encodings,
            "yara_matches": yara,
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
def _analyze_zip(content: bytes, original_filename: str) -> dict:
    """
    Extract a ZIP archive into a temp directory, analyze every binary
    file found inside, and return results for each file.

    Security:
    • Rejects ZIPs > MAX_ZIP_SIZE (10 MB).
    • Rejects ZIPs with > MAX_ZIP_FILES entries (zip-bomb protection).
    • Never executes any extracted file.
    • Always deletes the temp directory in try/finally.
    """
    import io

    try:
        zf = zipfile.ZipFile(io.BytesIO(content))
    except zipfile.BadZipFile:
        raise HTTPException(status_code=400, detail="File is not a valid ZIP archive.")

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
        zf.extractall(tmp_dir)

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
                result = _analyze_single_file(file_content, entry, inner_ext, detected_type)
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
async def analyze(request: Request, file: UploadFile = File(...)):
    """
    Accept a binary file upload, validate it strictly, extract readable
    strings via static analysis, and return the results as JSON.

    Supports:
    • Named binary files (.bin, .elf, .exe, .so, .dll, .out, .o)
    • Extensionless files (auto-detected via magic bytes — ELF, PE, Mach-O)
    • ZIP archives (extracts and analyzes each binary inside)

    The uploaded file is saved to a temporary location and **always**
    deleted after processing — even when an error occurs.
    """
    # ── 1. Validate extension (before reading the full body) ──────────
    ext = _validate_extension(file.filename)

    # ── 2. Read content into memory & validate size ───────────────────
    content = await file.read()
    _validate_size(content, is_zip=(ext == ".zip"))

    # ── 3. Handle ZIP archives ────────────────────────────────────────
    if ext == ".zip":
        _validate_mime(content, ext)
        return _analyze_zip(content, file.filename or "archive.zip")

    # ── 4. Auto-detect extensionless files via magic bytes ────────────
    detected_type = ""
    if ext == "":
        detected_type = _detect_type_from_magic(content)
    else:
        # ── 5. Validate content signature / MIME ──────────────────────
        _validate_mime(content, ext)

    # ── 6. Analyze the single binary ─────────────────────────────────
    return _analyze_single_file(content, file.filename or "unknown", ext, detected_type)


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
    "binary exploitation challenge. The student has already uploaded and analyzed "
    "a binary. Look at their screenshot carefully and provide specific, actionable "
    "next steps in bullet points. Include exact commands. Be encouraging.\n\n"
    "RULES:\n"
    "1. Start with • bullet points — each one specific and actionable.\n"
    "2. Maximum 6 • bullets. Include exact Linux commands where helpful.\n"
    "3. After the bullets, add a 🔗 Kill Chain section if you can infer the exploitation path.\n"
    "4. End with: 🔥 Try this first: <the single most important next step>\n"
    "5. If the screenshot shows an error, help them debug it.\n"
    "6. If it shows a GDB/pwntools session, guide the next debugging step."
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
    Analyze a screenshot using Claude Vision.

    Security invariants:
    • Image is NEVER stored to disk — only held in memory as bytes/base64.
    • Base64 string is discarded after the API call.
    • Only sent to Claude Vision API, nowhere else.
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

    # ── Build Claude Vision message ───────────────────────────────────
    user_content: list[dict] = []

    # Add context about the binary being analyzed
    if context:
        user_content.append({
            "type": "text",
            "text": (
                "Here is the analysis context of the binary I'm working on:\n\n"
                + context[:3000]
                + "\n\nNow here is my screenshot — please analyze it and tell me what to do next:"
            ),
        })
    else:
        user_content.append({
            "type": "text",
            "text": "I'm working on a CTF binary challenge. Here is my screenshot — please analyze it and tell me what to do next:",
        })

    # Add the image
    user_content.append({
        "type": "image",
        "source": {
            "type": "base64",
            "media_type": mime_type,
            "data": image_b64,
        },
    })

    # ── Call Claude Vision ────────────────────────────────────────────
    if not ANTHROPIC_API_KEY:
        # Clean up base64 from memory
        del image_b64
        raise HTTPException(
            status_code=503,
            detail="Image analysis requires an Anthropic API key. Please set ANTHROPIC_API_KEY in your .env file.",
        )

    try:
        client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
        response = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=1024,
            system=IMAGE_ANALYSIS_PROMPT,
            messages=[{"role": "user", "content": user_content}],
        )
        ai_response = response.content[0].text
    except Exception as exc:
        logger.error("Claude Vision call failed: %s", exc)
        del image_b64
        raise HTTPException(
            status_code=503,
            detail=f"Image analysis failed: {str(exc)[:200]}",
        )
    finally:
        # Ensure base64 is cleared from memory
        image_b64 = ""

    return {"response": ai_response}


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
