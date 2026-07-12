<div align="center">

# BinExplain

### Free AI-Powered Binary Analysis for CTF Beginners

[![Live Demo](https://img.shields.io/badge/🚀_Live_Demo-binexplain.com-brightgreen?style=for-the-badge)](https://binexplain.com)
[![License: CC BY-NC-ND 4.0](https://img.shields.io/badge/License-CC_BY--NC--ND_4.0-lightgrey?style=for-the-badge)](LICENSE)
[![Tests](https://img.shields.io/badge/Tests-235_passing-brightgreen?style=for-the-badge&logo=pytest&logoColor=white)](backend/tests)
[![GitHub Stars](https://img.shields.io/github/stars/Vaibhavi28/binexplain?style=for-the-badge&logo=github&logoColor=white&color=yellow)](https://github.com/Vaibhavi28/binexplain/stargazers)
[![Last Commit](https://img.shields.io/github/last-commit/Vaibhavi28/binexplain?style=for-the-badge&logo=github&logoColor=white)](https://github.com/Vaibhavi28/binexplain/commits/master)

---

### Tech Stack

![Python](https://img.shields.io/badge/Python_3.11-3776AB?style=for-the-badge&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-009688?style=for-the-badge&logo=fastapi&logoColor=white)
![React](https://img.shields.io/badge/React_18-20232A?style=for-the-badge&logo=react&logoColor=61DAFB)
![ChromaDB](https://img.shields.io/badge/ChromaDB-RAG_Pipeline-orange?style=for-the-badge)
![GCP](https://img.shields.io/badge/GCP-4285F4?style=for-the-badge&logo=googlecloud&logoColor=white)

### AI Providers

![Groq](https://img.shields.io/badge/Groq-F55036?style=for-the-badge)
![NVIDIA](https://img.shields.io/badge/Nemotron_Ultra-76B900?style=for-the-badge&logo=nvidia&logoColor=white)
![Gemini](https://img.shields.io/badge/Gemini_2.5_Flash-4285F4?style=for-the-badge&logo=google&logoColor=white)
![OpenAI](https://img.shields.io/badge/GPT--4o_mini-412991?style=for-the-badge&logo=openai&logoColor=white)
![Anthropic](https://img.shields.io/badge/Claude-D97757?style=for-the-badge&logo=anthropic&logoColor=white)

---

**Upload a binary → Instant CTF category, disassembly, ROP gadgets, pwntools template, parallel AI hints**

**No installation. No account. Always free for individual use.**

[🚀 **Try it at binexplain.com**](https://binexplain.com) · [⭐ Star on GitHub](https://github.com/Vaibhavi28/binexplain) · [🐛 Report a Bug](https://github.com/Vaibhavi28/binexplain/issues)

> ⚠️ **License Notice:** Source-available under CC BY-NC-ND 4.0.
> You may use the live tool and view the code freely.
> Cloning, forking, and redistribution are **not** permitted.
> See [LICENSE](LICENSE) for full terms.

</div>

---

## Detection Accuracy

Category detection is evaluated automatically on every commit against
labeled binaries compiled from [shellphish/how2heap](https://github.com/shellphish/how2heap).

See [full evaluation report](backend/evaluation/results/evaluation_report.md).

<!-- METRICS_BADGE_START -->
*Run CI to generate live metrics*
<!-- METRICS_BADGE_END -->

---

## What Problem Does This Solve

Every CTF beginner downloads their first binary and has no idea what to do next. Professional tools like Ghidra cost hundreds of dollars or assume expert knowledge. No free tool explains what the analysis **means** or tells you what to do next.

**BinExplain acts like a senior CTF player sitting next to you.**

---

## Features

### Binary Analysis

| Feature | Details |
|---------|---------|
| 🎯 **CTF Category Detection** | ret2win, ret2libc, heap, format string, ROP chain, shellcode — with confidence level |
| 🎲 **Difficulty Predictor** | Easy / Medium / Hard based on active protections |
| 🔒 **Checksec Integration** | NX, PIE, Canary, RELRO, Fortify — explained in plain English |
| 🔗 **ROP Gadget Finder** | Real gadgets with addresses via Capstone disassembly |
| ⚡ **Pwntools Template** | Auto-generated with offset, architecture, and gadgets pre-filled |
| 📐 **Overflow Offset Predictor** | Predicted from stack allocation instructions in disassembly |
| 📚 **Libc Version Identifier** | Identifies libc version + direct link to libc database |
| ⚠️ **Format String Detector** | Detects printf(buf) pattern |
| 📊 **CVSS 3.1 Scoring** | Industry standard vulnerability scoring |
| 🌊 **Data Flow Analysis** | Traces input → buffer → sink with addresses |
| 📜 **Function List** | All functions from ELF symbol table |
| 📥 **Import/Export Table** | Full dynamic symbol parsing |
| 🔍 **Real Disassembly** | main() function via Capstone |
| 🔐 **Password ZIP Support** | Analyze encrypted CTF archives |
| 🚩 **11 Flag Formats** | picoCTF, HTB, THM, DUCTF, and more |
| 📦 **8+ File Formats** | ELF, EXE, BIN, SO, DLL, ZIP and extensionless |

### Source Code Analysis

| Feature | Details |
|---------|---------|
| 🎯 **CTF Category Detection** | Same 6 archetypes, adapted for source code |
| 📐 **Overflow Offset** | Read from buffer declarations — more precise than binary |
| 🌊 **Data Flow Analysis** | Line-level with actual variable names |
| 💡 **Exploit Template** | Working pwntools script from source analysis |
| 📋 **Quick Commands** | Compilation and testing commands |

### AI System

| Feature | Details |
|---------|---------|
| 🧠 **Parallel AI Inference** | Groq + Nemotron called simultaneously, responses merged |
| ✅ **Quality Gate** | Filters generic responses, retries with next provider |
| 🌐 **RAG Knowledge Base** | 2229 real CTF writeups from 13 curated sources |
| 🏷️ **Technique Tagging** | 22 technique tags for hybrid vector + semantic retrieval |
| ⚡ **CAG Caching** | Common patterns served instantly without LLM calls |
| 💬 **Unlimited Chat** | Auto-summarization keeps sessions going without token limits |
| 📷 **Screenshot Analysis** | Paste terminal screenshots directly with Ctrl+V |
| 🔧 **Visual Command Explainer** | Word-by-word command breakdown diagram |
| 📖 **Interactive Glossary** | Hover over technical terms for plain English explanations |

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
Groq merges both into one answer

### Sequential Fallback Chain

Groq (llama-3.3-70b)       — Free, fastest
Nemotron 3 Ultra            — Free via OpenRouter, deepest reasoning
Gemini 2.5 Flash            — Free, strong capability
OpenAI GPT-4o-mini          — Paid fallback
Claude                      — Last resort


### RAG Pipeline
CTFtime ──────┐
Nightmare ────┤
ir0nstone ────┤──→ Scraper ──→ ChromaDB ──→ Hybrid Retrieval
how2heap ─────┤         ↑          ↑
CTF-pwn-tips ─┤    Technique   Vector +
nobodyisnobody┤    Tagging     Tag Overlap
GitHub repos ─┘    (22 tags)   Scoring
↓
2229 indexed writeups

---

## Security Architecture

| Property | Implementation |
|----------|---------------|
| **Zero binary execution** | Static analysis only — uploaded files never executed |
| **3-layer file validation** | Extension + size + magic bytes |
| **Immediate file deletion** | try/finally — deleted even on crash |
| **No data storage** | Conversation lives only in browser |
| **ZIP bomb protection** | Max 20 files, 10MB per archive |
| **Rate limiting** | Per-IP limits on all expensive endpoints |
| **Input validation** | Pydantic field validators with length caps |
| **CORS restricted** | Configured domain only, never wildcard |
| **Security headers** | X-Content-Type-Options, X-Frame-Options |
| **235 automated tests** | Unit, integration, CTF scenarios, chaos testing |

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
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# Add your API keys to .env
uvicorn main:app --reload

# Frontend (new terminal)
cd ../frontend
npm install
echo "VITE_BACKEND_URL=http://localhost:8000" > .env
npm run dev

# Build knowledge base (first time — takes 30-60 minutes)
cd ../backend
python knowledge_base/scraper.py
```

---

## API Keys

| Provider | Get Key | Used For | Cost |
|----------|---------|---------|------|
| **Groq** | [console.groq.com](https://console.groq.com) | Primary AI (parallel) | Free |
| **OpenRouter** | [openrouter.ai](https://openrouter.ai) | Nemotron 3 Ultra | Free |
| **Gemini** | [aistudio.google.com](https://aistudio.google.com) | Fallback + Vision | Free |
| OpenAI | [platform.openai.com](https://platform.openai.com) | Paid fallback | Paid |
| VirusTotal | [virustotal.com](https://virustotal.com) | Optional scan | Free |
| Anthropic | [console.anthropic.com](https://console.anthropic.com) | Last resort | Paid |

> Full functionality available with only free-tier keys (Groq + OpenRouter + Gemini).

---

## Project Stats
Backend:        Python 3.11, FastAPI
Frontend:       React 18, Vite
Tests:          235 passing
Knowledge Base: 2229 real CTF writeups across 22 technique categories
AI Providers:   5 providers, parallel inference, quality gate, RAG + CAG
Development:    Months of active development and iteration

---

## Roadmap
v1  ✅  Web app — live at binexplain.com
v2  🔄  CLI tool (pip install binexplain)
v2  🔄  Dynamic analysis sandbox
v3  📋  MCP server for AI assistant integration
v3  📋  Browser extension for CTFtime and HackTheBox

---

## Contributing

Source-available under CC BY-NC-ND 4.0.
Bug reports and feature requests welcome via [GitHub Issues](https://github.com/Vaibhavi28/binexplain/issues).
See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

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

[binexplain.com](https://binexplain.com) · [GitHub Issues](https://github.com/Vaibhavi28/binexplain/issues) · [hello@binexplain.com](mailto:hello@binexplain.com)

</div>
