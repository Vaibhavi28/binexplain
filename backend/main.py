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
"""

import logging
import os
import re
import subprocess
import tempfile
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
ALLOWED_EXTENSIONS: set[str] = {".bin", ".elf", ".exe"}
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
    "1. Your ENTIRE response must be • bullet points. ZERO prose, ZERO paragraphs, ZERO introductions or conclusions.\n"
    "2. NEVER use markdown headers (#), numbered lists (1. 2. 3.), bold (**), italic (*), or any markdown formatting.\n"
    "3. Each • bullet = one specific action + the exact Linux command to run. No bullet without a command.\n"
    "4. Maximum 5 • bullets. Each bullet is 1 sentence, 2 sentences absolute max.\n"
    "5. Your LAST line must be exactly: 🔥 Try this first: <the single most important command to run>\n"
    "6. Do NOT write anything before the first • or after the 🔥 line.\n\n"
    "EXAMPLE (follow this format exactly):\n"
    "• Run `checksec ./binary` to see if NX, PIE, or stack canaries are enabled.\n"
    "• The binary uses `gets()` — test for overflow with `python3 -c 'print(\"A\"*100)' | ./binary`.\n"
    "• List all functions with `objdump -d binary | grep '<' | head -20` to find win/flag functions.\n"
    "• Search for flag strings with `strings binary | grep -i flag`.\n"
    "🔥 Try this first: `checksec ./binary`"
)

CHAT_SYSTEM_PROMPT = (
    "You are a CTF mentor helping a beginner analyze a binary they just uploaded. "
    "The user has already received an initial analysis summary (provided as context).\n\n"
    "ABSOLUTE RULES — you must follow every single one:\n"
    "1. Your ENTIRE response must be • bullet points. ZERO prose, ZERO paragraphs, ZERO introductions or conclusions.\n"
    "2. NEVER use markdown headers (#), numbered lists (1. 2. 3.), bold (**), italic (*), or any markdown formatting.\n"
    "3. Each • bullet = one specific action + the exact Linux command to run where relevant.\n"
    "4. Maximum 5 • bullets. Each bullet is 1 sentence, 2 sentences absolute max.\n"
    "5. Your LAST line must be exactly: 🔥 Try this first: <the single most important command>\n"
    "6. Do NOT write anything before the first • or after the 🔥 line.\n"
    "7. If the user asks something outside binary exploitation / CTF scope, "
    "reply with a single • bullet redirecting them back.\n\n"
    "EXAMPLE (follow this format exactly):\n"
    "• Run `checksec ./binary` to see if NX, PIE, or stack canaries are enabled.\n"
    "• The binary uses `gets()` — test for overflow with `python3 -c 'print(\"A\"*100)' | ./binary`.\n"
    "• Use `gdb ./binary` then `info functions` to find interesting function addresses.\n"
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

        # ── 5. Detect patterns, flags & generate AI hints ─────────────
        patterns = detect_patterns(strings)
        flags = detect_flags(strings)
        hints = get_ai_hints(strings, patterns)

        return {
            "filename": file.filename,
            "size_bytes": len(content),
            "extension": ext,
            "strings_count": len(strings),
            "strings": strings,
            "patterns": patterns,
            "flags_detected": flags,
            "hints": hints,
        }
    finally:
        # ALWAYS delete the temp file — no exceptions.
        if tmp_path and os.path.exists(tmp_path):
            os.unlink(tmp_path)


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
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
