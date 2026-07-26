<div align="center">

# BinExplain

### Free AI-Powered Binary Analysis for CTF Beginners

[![Live Demo](https://img.shields.io/badge/🚀_Live_Demo-binexplain.com-brightgreen?style=for-the-badge)](https://binexplain.com)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg?style=for-the-badge)](LICENSE)
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

> 📜 **License Notice:** Open source under Apache License 2.0.
> The source code is freely available under Apache 2.0 terms.
> Note: The "BinExplain" name and branding are protected rights reserved for the official project (see [NOTICE](NOTICE)).
> See [LICENSE](LICENSE) and [NOTICE](NOTICE) for details.

</div>

---

## What Problem Does This Solve

Every CTF beginner downloads their first binary and has no idea what to do next. Professional tools like Ghidra assume expert knowledge. No free tool explains what the analysis **means** or tells you what to do next.

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
| 🧠 **Parallel AI Inference** | Groq + Nemotron called simultaneously via asyncio, responses merged |
| ✅ **Quality Gate** | Two-pass filter rejects generic responses, retries with next provider |
| 🌐 **RAG Knowledge Base** | 6,400+ real CTF writeups from 8 curated sources |
| 🏷️ **Technique Tagging** | 24 technique tags for hybrid vector + tag-overlap retrieval |
| ⚡ **CAG Caching** | Common patterns served instantly — 80%+ cache hit rate |
| 💬 **Unlimited Chat** | Auto-summarization every 10 messages — no context loss |
| 📷 **Screenshot Analysis** | Paste terminal screenshots directly with Ctrl+V |
| 🔧 **Visual Command Explainer** | Word-by-word command breakdown with inline diagram |
| 📖 **Interactive Glossary** | Hover over technical terms for plain English explanations |

### Learn Page

| Feature | Details |
|---------|---------|
| 📚 **Zero-Knowledge Explainer** | Teaches binary analysis from absolute beginner level |
| 🏗️ **ELF Structure Diagram** | Interactive clickable sections — .text, stack, heap, GOT/PLT |
| 🔒 **Protections Toggle Map** | Live toggle NX/PIE/Canary/RELRO — see which attacks survive |
| 🌳 **Exploitation Flowchart** | Decision tree: answer 5 questions, arrive at your technique |
| 🎬 **Animated Technique Dives** | 6 animated memory diagrams — one per exploitation category |
| 🌍 **Real World CVE Map** | Each technique mapped to real CVEs with full attack story |
| 🔗 **Relationship Map** | Function → vulnerability → technique → mitigation, all connected |
| 🧪 **Try It Yourself** | Pre-loaded demo binaries — click Analyze, see results instantly |

---

## AI Architecture

### Parallel Inference

```
Binary uploaded → Static analysis (2-3 seconds)
        ↓
┌─────────────────────┐    ┌──────────────────────────────┐
│ Groq llama-3.3-70b  │    │ Nemotron 3 Ultra (550B MoE)  │
│ Fast — 1-3 seconds  │    │ Deep — 8-15 seconds          │
└─────────────────────┘    └──────────────────────────────┘
         ↓                              ↓
   Quick hints shown            Deep hints ready
   immediately                        ↓
                        ✅ Quality gate — rejects generic responses
                                      ↓
                          Groq merges both into one answer
```

### Sequential Fallback Chain

```
1. Groq (llama-3.3-70b)    — Free, fastest
2. Nemotron 3 Ultra         — Free via OpenRouter, 550B MoE
3. Gemini 2.5 Flash         — Free, strong capability
4. OpenAI GPT-4o-mini       — Paid fallback
5. Claude                   — Last resort
```

### RAG Pipeline

```
CTFtime ──────┐
Nightmare ────┤
ir0nstone ────┤
how2heap ─────┤──→ Scraper → quality filter → ChromaDB → Hybrid Retrieval
CTF-pwn-tips ─┤              deduplication              vector similarity
nobodyisnobody┤              credential filter        + technique tag overlap
GitHub repos ──┤              24 category targets               ↓
Medium articles┘                                    6,400+ indexed writeups
```

---

## Security Architecture

| Property | Implementation |
|----------|---------------|
| **Zero binary execution** | Static analysis only — uploaded files never executed |
| **3-layer file validation** | Extension + size + magic bytes |
| **Immediate file deletion** | try/finally — deleted even on crash |
| **No data storage** | Conversation lives only in browser |
| **ZIP bomb protection** | Max 20 files, 10MB per archive |
| **Rate limiting** | Per-IP limits on analyze, chat, explain-command |
| **Input validation** | Pydantic field validators with length caps |
| **CORS restricted** | Configured domain only, never wildcard |
| **Security headers** | X-Content-Type-Options, X-Frame-Options, Referrer-Policy |
| **235+ automated tests** | Unit, integration, CTF scenarios, chaos testing |

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
| **Groq** | [console.groq.com](https://console.groq.com) | Primary AI — parallel inference | Free |
| **OpenRouter** | [openrouter.ai](https://openrouter.ai) | Nemotron 3 Ultra | Free |
| **Gemini** | [aistudio.google.com](https://aistudio.google.com) | Fallback + Vision | Free |
| OpenAI | [platform.openai.com](https://platform.openai.com) | Paid fallback | Paid |
| VirusTotal | [virustotal.com](https://virustotal.com) | Optional malware scan | Free |
| Anthropic | [console.anthropic.com](https://console.anthropic.com) | Last resort fallback | Paid |

> Full functionality available with only free-tier keys (Groq + OpenRouter + Gemini).

---

## Project Stats

| | |
|--|--|
| **Backend** | Python 3.11, FastAPI, 6,400+ line main.py |
| **Frontend** | React 18, Vite, anime.js |
| **Tests** | 235+ passing (unit, integration, CTF scenarios, chaos) |
| **Knowledge Base** | 6,400+ real CTF writeups across 24 technique categories |
| **AI Providers** | 5 providers, parallel inference, quality gate, RAG + CAG |
| **Development** | Months of active development and iteration |

---

## Roadmap

| Status | Version | Feature |
|--------|---------|---------|
| ✅ | v1 | Web app — live at binexplain.com |
| ✅ | v1 | Interactive Learn page with 6 animated technique dives |
| ✅ | v1 | Pre-loaded demo binaries for all 6 CTF categories |
| 🔄 | v2 | CLI tool — `pip install binexplain` |
| 🔄 | v2 | Dynamic analysis sandbox (strace, ltrace automation) |
| 📋 | v3 | MCP server for AI assistant integration |
| 📋 | v3 | Browser extension for CTFtime and HackTheBox |

---

## Contributing

Open source under Apache License 2.0.
Bug reports and feature requests welcome via [GitHub Issues](https://github.com/Vaibhavi28/binexplain/issues).
See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

---

## License

**Apache License 2.0** — Open source code license.
Per the [NOTICE](NOTICE) file, the "BinExplain" name, logos, and branding are protected identifiers reserved for the official project instance at binexplain.com.
See [LICENSE](LICENSE) and [NOTICE](NOTICE).

---

## Disclaimer

BinExplain performs **static analysis only**. Uploaded files are deleted
immediately after analysis. No binaries are ever executed.
Only analyze files you own or have explicit permission to analyze.

---

<div align="center">

**© 2026 Vaibhavi Sanjay Kathepuri — Licensed under Apache License 2.0**

Built with ❤️ for the CTF community

⭐ **If BinExplain helped you solve a challenge, please star this repo** ⭐

[binexplain.com](https://binexplain.com) · [GitHub Issues](https://github.com/Vaibhavi28/binexplain/issues) · [hello@binexplain.com](mailto:hello@binexplain.com)

</div>