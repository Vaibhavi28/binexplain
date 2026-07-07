<div align="center">

# BinExplain

### Free AI-Powered Binary Analysis for CTF Beginners

[![Live Demo](https://img.shields.io/badge/🚀_Live_Demo-binexplain.com-brightgreen?style=for-the-badge)](https://binexplain.com)
[![License: CC BY-NC-ND 4.0](https://img.shields.io/badge/License-CC_BY--NC--ND_4.0-lightgrey?style=for-the-badge)](LICENSE)
[![Tests](https://img.shields.io/badge/Tests-230+_passing-brightgreen?style=for-the-badge&logo=pytest&logoColor=white)](backend/tests)
[![GitHub Stars](https://img.shields.io/github/stars/Vaibhavi28/binexplain?style=for-the-badge&logo=github&logoColor=white&color=yellow)](https://github.com/Vaibhavi28/binexplain/stargazers)
[![Last Commit](https://img.shields.io/github/last-commit/Vaibhavi28/binexplain?style=for-the-badge&logo=github&logoColor=white)](https://github.com/Vaibhavi28/binexplain/commits/master)

### Tech Stack
[![Python](https://img.shields.io/badge/Python_3.11-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-009688?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React_18-20232A?style=for-the-badge&logo=react&logoColor=61DAFB)](https://reactjs.org)
[![ChromaDB](https://img.shields.io/badge/ChromaDB-RAG_Pipeline-orange?style=for-the-badge)](https://trychroma.com)
[![Google Cloud](https://img.shields.io/badge/GCP-4285F4?style=for-the-badge&logo=googlecloud&logoColor=white)](https://cloud.google.com)

### AI Providers
[![Groq](https://img.shields.io/badge/Groq-F55036?style=for-the-badge)](https://groq.com)
[![NVIDIA](https://img.shields.io/badge/Nemotron_3_Ultra-76B900?style=for-the-badge&logo=nvidia&logoColor=white)](https://openrouter.ai)
[![Gemini](https://img.shields.io/badge/Gemini_2.5_Flash-4285F4?style=for-the-badge&logo=google&logoColor=white)](https://aistudio.google.com)
[![OpenAI](https://img.shields.io/badge/GPT--4o_mini-412991?style=for-the-badge&logo=openai&logoColor=white)](https://openai.com)
[![Anthropic](https://img.shields.io/badge/Claude-D97757?style=for-the-badge&logo=anthropic&logoColor=white)](https://anthropic.com)

**Upload a binary → Instant CTF category, disassembly, ROP gadgets,
pwntools template, parallel AI hints, interactive glossary**

**No installation. No account. Always free for individual use.**

> ⚠️ **License:** Source-available under CC BY-NC-ND 4.0.
> Use the live tool freely. Cloning and redistribution are not permitted.

</div>

---

## What Problem Does This Solve

Every CTF beginner downloads their first binary and has no idea what to
do next. Professional tools cost hundreds of dollars or assume you already
know assembly. No free tool tells you what the analysis MEANS or what to
do next.

BinExplain does something different. It acts like a senior CTF player
sitting next to you. Upload a binary and within seconds you know what
type of challenge it is, how hard it is, what ROP gadgets are available,
and what to do next — with AI hints grounded in 5000+ real CTF writeups.

---

## Features

### Binary Analysis
| Feature | Details |
|---------|---------|
| 🎯 CTF Category Detection | ret2win, ret2libc, heap, format string, ROP chain, shellcode — with confidence level |
| 🎲 Difficulty Predictor | Easy / Medium / Hard based on active protections |
| 🔒 Checksec Integration | NX, PIE, Canary, RELRO, Fortify — explained in plain English |
| 🔗 ROP Gadget Finder | Real gadgets with addresses via Capstone disassembly |
| ⚡ Pwntools Template | Auto-generated with offset, architecture, gadgets pre-filled |
| 📐 Overflow Offset Predictor | Predicted from stack allocation instructions |
| 📚 Libc Version Identifier | Identifies libc + direct link to libc database |
| ⚠️ Format String Detector | Detects printf(buf) pattern |
| 📊 CVSS 3.1 Scoring | Industry standard vulnerability scoring |
| 🌊 Data Flow Analysis | Traces input → buffer → sink with addresses |
| 📜 Function List | All functions from ELF symbol table |
| 📥 Import/Export Table | Full dynamic symbol parsing |
| 🔍 Real Disassembly | main() function via Capstone |
| 🔐 Password ZIP Support | Analyze encrypted CTF archives |
| 🚩 11 Flag Formats | picoCTF, HTB, THM, DUCTF, and more |
| 📦 8+ File Formats | ELF, EXE, BIN, SO, DLL, ZIP + extensionless |

### Source Code Analysis (Full Feature Parity)
| Feature | Details |
|---------|---------|
| 🎯 CTF Category Detection | Same 6 archetypes, source-adapted |
| 📐 Overflow Offset | From buffer declarations — more precise than binary |
| 🌊 Data Flow Analysis | Line-level with actual variable names |
| 💡 Exploit Template | Working pwntools script from source analysis |
| 📋 Quick Commands | Compilation and testing commands for source |

### AI System
| Feature | Details |
|---------|---------|
| 🧠 Parallel AI Inference | Groq + Nemotron simultaneously, responses merged |
| ✅ Quality Gate | Two-pass system ensures non-generic responses |
| 🌐 RAG Knowledge Base | 5000+ real CTF writeups from 8 sources |
| 🏷️ Technique Tagging | 24 technique tags for hybrid vector + semantic retrieval |
| ⚡ CAG Caching | Expert-quality cached responses for common patterns |
| 💬 AI Mentor Chat | Unlimited sessions with automatic summarization |
| 📷 Screenshot Analysis | Upload GDB/terminal screenshots for visual guidance |
| 🔧 Command Explainer | Visual word-by-word command breakdown diagram |
| 🌐 Similar Writeups | RAG finds past challenges matching your binary |
| 📖 Interactive Glossary | Hover over technical terms for plain English explanations |

### UX
| Feature | Details |
|---------|---------|
| ⌨️ Ctrl+V Screenshot Paste | Paste terminal screenshots directly into chat |
| 📷 Camera Support | Take photo of screen for instant AI analysis |
| ⎘ Per-Command Copy | Copy button on every individual command |
| 💡 Install Detection | Shows install command when a tool is not present |
| 📊 Exploit Progress Bar | Visual RECON→ANALYSIS→OFFSET→GADGETS→PAYLOAD→FLAG stages |

---

## AI Architecture

### Parallel Inference

Binary uploaded → Static analysis (2-3 seconds)
↓
┌─────────────────────┐    ┌──────────────────────────────┐
│ Groq llama-3.3-70b  │    │ Nemotron 3 Ultra (550B MoE)  │
│ Fast — 1-3 seconds  │    │ Deep — 8-15 seconds          │
└─────────────────────┘    └──────────────────────────────┘
↓                              ↓
Quick hints shown            Enhanced hints ready
immediately                        ↓
✅ Quality gate filters generic responses
↓
Groq merges both responses


### Sequential Fallback Chain


Groq (llama-3.3-70b)       — Free, fastest
Nemotron 3 Ultra            — Free via OpenRouter, deepest reasoning
Gemini 2.5 Flash            — Free, strong capability
OpenAI GPT-4o-mini          — Paid fallback
Claude                      — Last resort


Note: Ollama is available for local development only (disabled on GCP).

### RAG Pipeline

CTFtime.org ──────┐
Nightmare ────────┤
ir0nstone ────────┤──→ Scraper ──→ ChromaDB ──→ Hybrid Retrieval
how2heap ─────────┤         ↑          ↑
CTF-pwn-tips ─────┤    Technique   Vector +
nobodyisnobody ───┤    Tagging     Tag Overlap
GitHub writeups ──┘    (24 tags)   Scoring
↓
5000+ indexed writeups
balanced across 24 categories


---

## Security Architecture

| Property | Implementation |
|----------|---------------|
| **Zero binary execution** | Static analysis only — never executed |
| **3-layer file validation** | Extension + size + magic bytes |
| **Immediate file deletion** | try/finally — deleted even on crash |
| **No data storage** | Conversation lives only in browser |
| **ZIP bomb protection** | Max 20 files, 10MB per archive |
| **Rate limiting** | Per-IP limits on all expensive endpoints |
| **Input validation** | Pydantic field validators, max lengths |
| **CORS restricted** | Configured domain only, never wildcard |
| **Security headers** | X-Content-Type-Options, X-Frame-Options |
| **230+ automated tests** | Unit, integration, CTF scenarios, chaos |

---

## Quick Start

### Use the Live Tool
👉 **[binexplain.com](https://binexplain.com)** — No installation. Works in any browser.

### Run Locally

```bash
git clone https://github.com/Vaibhavi28/binexplain.git
cd binexplain

# Backend
cd backend
python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env
# Add your API keys to .env
uvicorn main:app --reload

# Frontend (new terminal)
cd ../frontend
npm install
echo "VITE_BACKEND_URL=http://localhost:8000" > .env
npm run dev

# Build knowledge base (first time only)
cd ../backend
python knowledge_base/scraper.py
```

---

## API Keys (All Free Tiers Available)

| Provider | Get Key | Used For | Cost |
|----------|---------|---------|------|
| **Groq** | [console.groq.com](https://console.groq.com) | Primary AI (parallel) | Free |
| **OpenRouter** | [openrouter.ai](https://openrouter.ai) | Nemotron 3 Ultra | Free |
| **Gemini** | [aistudio.google.com](https://aistudio.google.com) | Fallback + Vision | Free |
| OpenAI | [platform.openai.com](https://platform.openai.com) | Fallback | Paid |
| VirusTotal | [virustotal.com](https://virustotal.com) | Optional scan | Free |
| Anthropic | [console.anthropic.com](https://console.anthropic.com) | Last resort | Paid |

---

## Roadmap

v1  ✅  Web app — live at binexplain.com
v2  🔄  CLI tool (pip install binexplain)
v2  🔄  Dynamic analysis sandbox (strace, ltrace, GDB automation)
v3  📋  MCP server for AI assistant integration
v3  📋  Browser extension for CTFtime/HackTheBox
v4  📋  Automated exploit generation via symbolic execution


---

## Project Stats

Backend:        Python 3.11, FastAPI, 5000+ lines
Frontend:       React 18, Vite, 3000+ lines
Tests:          230+ passing (unit + integration + CTF scenarios + chaos)
Knowledge Base: 5000+ real CTF writeups across 24 technique categories
AI Providers:   5 providers, parallel inference, quality gate, RAG + CAG
Development:    Months of active development and iteration


---

## Contributing

Source-available under CC BY-NC-ND 4.0. See [CONTRIBUTING.md](CONTRIBUTING.md).
Bug reports and feature requests welcome via GitHub Issues.

---

## License

**CC BY-NC-ND 4.0** — Use the live tool and view the code freely.
Redistribution, forking, and commercial use are not permitted.
See [LICENSE](LICENSE).

---

## Disclaimer

BinExplain performs **static analysis only**. Uploaded files are deleted
immediately after analysis. No binaries are ever executed.
Only analyze files you own or have explicit permission to analyze.

---

<div align="center">

**© 2026 Vaibhavi Sanjay Kathepuri — CC BY-NC-ND 4.0**

Built with ❤️ for the CTF community

⭐ **If BinExplain helped you solve a challenge, please star this repo!** ⭐

[binexplain.com](https://binexplain.com) · [GitHub](https://github.com/Vaibhavi28/binexplain)

</div>
