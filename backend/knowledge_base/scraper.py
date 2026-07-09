import os
import re
import sys
import urllib.parse
import requests
import time
import random
import glob
from collections import Counter
from bs4 import BeautifulSoup
import json
from pathlib import Path

CHECKPOINT_FILE = Path(os.path.dirname(os.path.abspath(__file__))) / "scraper_checkpoint.json"

def load_checkpoint() -> dict:
    if CHECKPOINT_FILE.exists():
        try:
            data = json.loads(CHECKPOINT_FILE.read_text(encoding="utf-8"))
            print(f"[Checkpoint] Resuming from checkpoint")
            return data
        except Exception:
            pass
    return {
        "ctftime_last_page": 0,
        "github_queries_done": [],
        "medium_pages_done": [],
        "sources_completed": [],
    }

def save_checkpoint(data: dict):
    CHECKPOINT_FILE.write_text(
        json.dumps(data, indent=2), encoding="utf-8"
    )

SLEEP_GITHUB = 1.0   # Keep GitHub API sleeps at 1 second between pages (to avoid rate limits)
SLEEP_WEB    = 0.3   # Regular websites, no API — be polite

from dotenv import load_dotenv
dotenv_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "..", ".env"
)
if os.path.exists(dotenv_path):
    load_dotenv(dotenv_path=dotenv_path)
else:
    load_dotenv()

GITHUB_HEADERS = {
    "Authorization": f"token {os.getenv('GITHUB_TOKEN', '') or os.getenv('GITHUB_Token', '')}",
    "Accept": "application/vnd.github.v3+json",
}

SCRAPER_HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; research scraper)",
    "Authorization": f"token {os.getenv('GITHUB_TOKEN', '') or os.getenv('GITHUB_Token', '')}",
}


files_saved_this_run = 0

CATEGORY_KEYWORDS = {
    "ret2win": [
        "ret2win", "win function", "win()", "flag()", "print_flag",
        "backdoor", "hidden function", "jump to win", "call win",
        "win address", "overflow to win function"
    ],
    "ret2libc": [
        "ret2libc", "return to libc", "system(", "/bin/sh",
        "libc base", "libc leak", "puts leak", "printf leak",
        "libc offset", "execve", "/bin/bash", "ret2plt",
        "plt stub", "got leak", "got overwrite"
    ],
    "format_string": [
        "format string", "fmtstr_payload", "format string bug",
        "printf bug", "format string exploit", "arbitrary write printf",
        "format specifier", "printf vulnerability", "%p leak",
        "printf(buf)", "printf(user"
    ],
    "heap_exploitation": [
        "heap overflow", "use after free", "use-after-free", "uaf",
        "double free", "double-free", "tcache poison", "tcache dup",
        "fastbin dup", "house of", "heap spray", "chunk overlap",
        "unsorted bin", "off by one heap", "null byte poison",
        "heap vulnerability", "malloc hook", "free hook"
    ],
    "shellcode": [
        "shellcode injection", "execute shellcode", "inject shellcode",
        "mprotect exploit", "nx bypass shellcode", "shellcraft",
        "asm shellcode", "jmp esp", "jmp rsp", "shellcode execution"
    ],
    "rop_chain": [
        "rop chain", "return oriented programming", "gadget chain",
        "pop rdi ret", "pop rsi ret", "ret2csu", "stack pivot",
        "rop gadget", "ropper", "ROPgadget tool", "sigreturn rop",
        "srop exploit", "one gadget", "rop exploit"
    ],
}

MINIMUM_KEYWORD_MATCHES = 2

def detect_category_from_text(text: str) -> str:
    text_lower = text.lower()
    scores = {}
    for category, keywords in CATEGORY_KEYWORDS.items():
        score = sum(1 for kw in keywords if kw.lower() in text_lower)
        if score >= MINIMUM_KEYWORD_MATCHES:
            scores[category] = score
    if not scores:
        return "unknown"
    return max(scores, key=scores.get)


# Hard pwn-specific signals — at least ONE must be present to save a writeup.
# These do NOT appear in web/crypto/misc CTF writeups.
STRONG_PWN_SIGNALS = [
    'pwntools', 'from pwn import', 'p64(', 'p32(',
    'buffer overflow', 'gets(', 'ret2', 'rop chain',
    'gadget', 'shellcode', '/bin/sh', 'one_gadget',
    'libc base', 'heap exploit', 'use after free',
    'format string', 'scanf(', 'stack smash', 'canary',
    'tcache', 'fastbin', 'malloc(', 'free(',
    'checksec', 'pie base', 'got overwrite', 'plt stub',
    'sigreturn', 'stack pivot', 'off by one', 'null byte',
]

# Per-category targeted GitHub search queries.
# Used by scrape_targeted_by_category() to hunt for specific missing content.
CATEGORY_SEARCH_QUERIES = {
    "ret2win":           ["ctf pwn ret2win binary exploit", "ret2win pwntools writeup", "ctf binary ret2win flag function", "ret2win buffer overflow solution", "ret2win exploit walkthrough", "ret2win ctf challenge solution"],
    "ret2libc":          ["ctf pwn ret2libc writeup pwntools", "ret2libc libc leak binary exploit", "system /bin/sh ret2libc ctf", "ret2libc puts leak exploit", "ret2libc printf leak writeup", "return to libc exploit tutorial"],
    "format_string":     ["ctf pwn format string exploit writeup", "printf format string pwntools ctf", "fmtstr_payload got overwrite writeup", "format string arbitrary write exploit", "printf vulnerability ctf solution", "format string leak stack ctf"],
    "heap_exploitation": ["ctf pwn heap exploitation writeup", "heap exploit malloc free tcache", "glibc heap ctf challenge writeup", "heap overflow exploit writeup", "heap feng shui ctf exploit", "heap metadata corruption exploit"],
    "rop_chain":         ["ctf pwn rop chain gadget writeup", "ROPgadget binary exploit ctf", "return oriented programming pwntools", "rop chain exploit tutorial binary", "rop gadget chain ctf solution", "ropper rop exploit writeup"],
    "shellcode":         ["ctf pwn shellcode injection writeup", "shellcode mprotect nx bypass ctf", "shellcraft pwntools ctf exploit", "custom shellcode exploit ctf", "shellcode encoder ctf writeup", "alphanumeric shellcode exploit"],
    "ret2plt":           ["ctf pwn ret2plt plt stub writeup", "return to plt ctf binary exploit", "ret2plt got leak pwntools", "plt stub exploit binary ctf", "calling plt functions exploit", "ret2plt binary exploitation"],
    "got_overwrite":     ["ctf pwn got overwrite exploit writeup", "global offset table hijack ctf", "got overwrite format string pwntools", "got hijack binary exploit ctf", "overwriting got entry exploit", "got table corruption ctf"],
    "ret2csu":           ["ctf pwn ret2csu exploit writeup", "__libc_csu_init gadget ctf", "ret2csu universal gadget binary exploit", "csu init gadgets exploit", "universal rop gadget csu", "ret2csu rop exploit tutorial"],
    "srop":              ["ctf pwn srop sigreturn exploit", "sigreturn oriented programming writeup", "sigreturn frame pwntools ctf", "srop exploit tutorial binary", "sigreturn syscall exploit ctf", "srop frame crafting exploit"],
    "fastbin_dup":       ["ctf pwn fastbin dup exploit writeup", "fastbin duplicate attack ctf", "fastbin corruption heap exploit", "fastbin double free exploit", "fastbin attack heap ctf", "glibc fastbin dup writeup"],
    "tcache_poisoning":  ["ctf pwn tcache poisoning exploit", "tcache dup attack writeup", "tcache corruption pwntools ctf", "tcache bin poisoning exploit", "glibc tcache attack ctf", "tcache double free exploit"],
    "use_after_free":    ["ctf pwn use after free exploit", "uaf vulnerability binary exploit writeup", "use after free heap ctf pwntools", "uaf exploit heap corruption", "dangling pointer exploit ctf", "use after free binary exploitation"],
    "one_gadget":        ["ctf pwn one_gadget exploit writeup", "one gadget libc binary exploit", "execve one gadget pwntools ctf", "one gadget rce exploit ctf", "magic gadget libc exploit", "one shot gadget exploit"],
    "canary_bypass":     ["ctf pwn stack canary bypass writeup", "canary leak binary exploit pwntools", "stack cookie bypass ctf", "brute force canary exploit", "canary leak format string ctf", "stack guard bypass exploit"],
    "pie_bypass":        ["ctf pwn pie bypass aslr writeup", "pie base leak binary exploit ctf", "aslr pie bypass pwntools", "position independent code leak", "pie leak exploit binary", "aslr bypass leak ctf"],
    "off_by_one":        ["ctf pwn off by one exploit writeup", "null byte overflow heap exploit", "off by one heap binary exploit ctf", "off by one null byte poison", "obo heap exploit ctf", "single byte overflow exploit"],
    "stack_pivot":       ["ctf pwn stack pivot exploit writeup", "leave ret stack migration ctf", "stack pivot rop binary exploit", "xchg rsp gadget exploit", "stack migration exploit ctf", "pivot stack rop chain"],
    "integer_overflow":  ["ctf pwn integer overflow exploit writeup", "signed integer overflow binary ctf", "int overflow vulnerability exploit", "integer wraparound exploit ctf", "arithmetic overflow binary exploit", "size_t overflow exploit"],
    "seccomp_bypass":    ["ctf pwn seccomp bypass exploit writeup", "syscall filter bypass ctf binary", "seccomp sandbox escape exploit", "seccomp bpf bypass exploit", "orw open read write exploit ctf", "sandbox escape binary exploit"],
    "house_of_force":    ["ctf pwn house of force exploit writeup", "top chunk overflow heap ctf", "house of force wilderness exploit", "top chunk size overwrite", "house of force heap exploit", "wilderness overwrite exploit"],
    "house_of_spirit":   ["ctf pwn house of spirit exploit writeup", "fake chunk heap exploit ctf", "house of spirit fastbin attack", "crafting fake chunk exploit", "house of spirit heap ctf", "fake free chunk exploit"],
    "house_of_orange":   ["ctf pwn house of orange exploit writeup", "unsorted bin house of orange ctf", "house of orange heap ctf exploit", "file stream oriented exploit", "house of orange io exploit", "house of orange vtable"],
    "unsorted_bin_attack": ["ctf pwn unsorted bin attack exploit", "unsortedbin attack heap ctf", "unsorted bin corruption writeup", "unsorted bin leak exploit", "unsorted bin attack libc leak", "main arena leak exploit"],
}

try:
    from knowledge_base.technique_tags import extract_technique_tags
except ImportError:
    try:
        from technique_tags import extract_technique_tags
    except ImportError:
        from backend.knowledge_base.technique_tags import extract_technique_tags

# Reconfigure stdout to use UTF-8 on Windows to prevent encoding errors when printing to console
try:
    sys.stdout.reconfigure(encoding='utf-8')
except Exception:
    pass

def contains_credentials(text: str) -> bool:
    patterns = [
        r'AKIA[0-9A-Z]{16}',
        r'aws_secret_access_key\s*=\s*[A-Za-z0-9/+=]{40}',
        r'(?i)secret[_-]?access[_-]?key["\']?\s*[:=]\s*["\']?[A-Za-z0-9/+=]{20,}',
        r'(?i)aws_session_token\s*=\s*[A-Za-z0-9/+=]{100,}',
    ]
    return any(re.search(p, text) for p in patterns)

quality_stats = {
    "accepted": 0,
    "rejected_quality": 0,
    "rejected_duplicate": 0,
    "rejected_credentials": 0,
    "rejected_short": 0,
}

def calculate_writeup_quality(content: str) -> tuple:
    word_count = len(content.split())
    if word_count < 300:
        return False, 0.0, f"Too short ({word_count} words)"

    content_lower = content.lower()
    score = 0.0
    signals_found = []

    # Technical depth signals
    technical_signals = [
        ("pwntools", 0.15),
        ("from pwn import", 0.15),
        ("p64(", 0.15),
        ("p32(", 0.15),
        ("offset", 0.10),
        ("overflow", 0.10),
        ("payload", 0.10),
        ("exploit", 0.08),
        ("gadget", 0.12),
        ("rop", 0.10),
        ("ret2", 0.10),
        ("checksec", 0.08),
        ("gdb", 0.08),
        ("malloc", 0.08),
        ("free(", 0.08),
        ("system(", 0.08),
        ("0x", 0.05),
        ("disassembly", 0.08),
        ("binary", 0.05),
        ("flag{", 0.05),
    ]

    for signal, weight in technical_signals:
        if signal in content_lower:
            score += weight
            signals_found.append(signal)

    # Penalty for very generic content
    generic_penalties = [
        ("this challenge was easy", -0.20),
        ("i solved it", -0.10),
        ("great challenge", -0.15),
        ("fun ctf", -0.10),
        ("scoreboard", -0.30),
        ("team standings", -0.30),
    ]
    for phrase, penalty in generic_penalties:
        if phrase in content_lower:
            score += penalty

    score = min(max(score, 0.0), 1.0)
    MINIMUM_SCORE = 0.25   # raised from 0.10 — quality over count
    is_quality = score >= MINIMUM_SCORE
    reason = f"Score {score:.2f}, signals: {', '.join(signals_found[:5])}"
    return is_quality, score, reason

def is_duplicate_content(content: str, walkthrough_dir: str) -> bool:
    import os
    content_fingerprint = content[:300].lower().strip()
    for root, dirs, files in os.walk(walkthrough_dir):
        for fname in files:
            if not fname.endswith('.txt'):
                continue
            fpath = os.path.join(root, fname)
            try:
                with open(fpath, encoding='utf-8', errors='ignore') as f:
                    existing = f.read(400).lower()
                existing_fp = existing[:300].strip()
                # Check similarity via shared prefix
                if len(content_fingerprint) > 50 and len(existing_fp) > 50:
                    if content_fingerprint[:100] in existing_fp or \
                       existing_fp[:100] in content_fingerprint:
                        return True
            except Exception:
                pass
    return False

WALKTHROUGHS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "walkthroughs")
WALKTHROUGH_DIR = WALKTHROUGHS_DIR

CATEGORY_TARGETS = {
    "ret2win":            141,
    "ret2libc":           354,
    "format_string":      258,
    "rop_chain":          172,
    "heap_exploitation":  441,
    "shellcode":           98,
    "ret2plt":              0,
    "got_overwrite":        7,
    "ret2csu":             20,
    "srop":                 5,
    "fastbin_dup":          5,
    "tcache_poisoning":     8,
    "use_after_free":      19,
    "one_gadget":          14,
    "canary_bypass":        3,
    "pie_bypass":           4,
    "off_by_one":           2,
    "stack_pivot":          8,
    "integer_overflow":     8,
    "seccomp_bypass":       6,
    "house_of_force":       2,
    "house_of_spirit":     15,
    "house_of_orange":      3,
    "unsorted_bin_attack":  4,
    "unknown":            632,
}

MAX_TOTAL_WRITEUPS = 2229


def get_current_category_counts(walkthrough_dir: str) -> dict:
    counts = {cat: 0 for cat in CATEGORY_TARGETS}
    counts['others'] = 0
    if not os.path.exists(walkthrough_dir):
        return counts
    for item in os.listdir(walkthrough_dir):
        item_path = os.path.join(walkthrough_dir, item)
        if not os.path.isdir(item_path):
            continue
        cat = item.lower().strip()
        count = len([
            f for f in os.listdir(item_path)
            if f.endswith('.txt')
        ])
        if cat in counts:
            counts[cat] = count
        else:
            counts['others'] = counts.get('others', 0) + count
    return counts

def get_total_writeup_count(walkthrough_dir: str) -> int:
    total = 0
    if not os.path.exists(walkthrough_dir):
        return 0
    for item in os.listdir(walkthrough_dir):
        item_path = os.path.join(walkthrough_dir, item)
        if os.path.isdir(item_path):
            total += len([
                f for f in os.listdir(item_path)
                if f.endswith('.txt')
            ])
    return total

def category_needs_more(category: str, current_counts: dict) -> bool:
    if category == "others":
        return False
    target = CATEGORY_TARGETS.get(category, 100)
    current = current_counts.get(category, 0)
    return current < target

def print_category_progress(current_counts: dict):
    print('\n[Scraper] Category Coverage:')
    print(f'{"Category":<25} {"Current":>8} {"Target":>8} {"Pct":>6}')
    print('-' * 52)
    for cat, target in CATEGORY_TARGETS.items():
        current = current_counts.get(cat, 0)
        pct = (current / target * 100) if target > 0 else 0
        status = 'FULL' if current >= target else f'{pct:.0f}%'
        print(f'{cat:<25} {current:>8} {target:>8} {status:>6}')
    if 'others' in current_counts:
        print(f'{"others":<25} {current_counts["others"]:>8} {"N/A":>8} {"N/A":>6}')
    total = get_total_writeup_count(WALKTHROUGHS_DIR)
    total_target = sum(CATEGORY_TARGETS.values())
    print(f'\nTotal: {total} / {total_target}')

def scrape_github_search_bulk(checkpoint: dict) -> int:
    queries_done = checkpoint.get("github_queries_done", [])
    
    search_queries = [
        "ctf writeup pwn ret2win binary exploitation site:github.com",
        "ctf writeup format string printf exploit pwntools",
        "ctf writeup heap exploitation malloc tcache",
        "ctf writeup rop chain gadget binary pwn",
        "ctf writeup buffer overflow ret2libc shell",
        "ctf writeup shellcode injection mprotect",
        "binary exploitation writeup picoctf pwn",
        "hackthebox pwn writeup binary exploitation",
        "pwn challenge writeup pwntools exploit",
        "buffer overflow ctf writeup solution",
        "binary exploitation tutorial pwn walkthrough",
        "ctf pwn writeup 2024 binary",
        "ctf pwn writeup 2023 exploit",
        "ctf pwn writeup 2022 pwntools",
        "gdb exploit development ctf writeup",
        "libc exploit ctf writeup solution",
        "stack overflow binary ctf writeup",
        "heap challenge ctf writeup solution",
        "elf binary analysis exploit writeup",
        "pwntools exploit script ctf writeup",
        "return oriented programming ctf writeup",
        "format string vulnerability ctf writeup",
        "use after free ctf writeup exploit",
        "binary reverse engineering exploit writeup",
    ]
    
    saved = 0
    current_counts = get_current_category_counts(WALKTHROUGH_DIR)
    
    for query in search_queries:
        if query in queries_done:
            print(f"[GitHub] Skipping already-done query: {query[:40]}")
            continue
        
        print(f"[GitHub Search] Query: {query[:50]}...")
        for page in range(1, 6):  # 5 pages per query = 250 results max per query
            url = "https://api.github.com/search/repositories"
            params = {
                "q": query,
                "sort": "stars",
                "order": "desc",
                "per_page": 30,
                "page": page,
            }
            try:
                resp = requests.get(url, headers=GITHUB_HEADERS,
                                   params=params, timeout=15)
                if resp.status_code == 403:
                    print("[GitHub Search] Rate limited. Sleeping 60s...")
                    time.sleep(60)
                    continue
                if resp.status_code != 200:
                    break
                repos = resp.json().get("items", [])
                if not repos:
                    break

                for repo in repos:
                    if sum(current_counts.values()) >= MAX_TOTAL_WRITEUPS:
                        print(f"[GitHub Search] Reached max {MAX_TOTAL_WRITEUPS}. Done.")
                        return saved

                    # Try to get README.md
                    raw_url = (
                        f"https://raw.githubusercontent.com/"
                        f"{repo['full_name']}/{repo.get('default_branch','main')}/README.md"
                    )
                    try:
                        readme = requests.get(raw_url, timeout=10)
                        if readme.status_code != 200 or len(readme.text) < 300:
                            continue

                        content = readme.text
                        if contains_credentials(content):
                            continue

                        is_quality, score, _ = calculate_writeup_quality(content)
                        if not is_quality:
                            continue

                        # Detect category
                        detected_cat = detect_category_from_text(content)

                        if not category_needs_more(detected_cat, current_counts):
                            continue

                        if is_duplicate_content(content, WALKTHROUGH_DIR):
                            continue

                        # Save
                        slug = repo['full_name'].replace('/', '_')[:50]
                        filename = f"github_bulk_{detected_cat}_{slug}.txt"
                        save_path = os.path.join(
                            WALKTHROUGH_DIR, detected_cat, filename
                        )
                        os.makedirs(os.path.dirname(save_path), exist_ok=True)

                        header = f"""SOURCE: github_bulk
URL: {repo['html_url']}
CHALLENGE: {repo['name']}
CATEGORY: {detected_cat}
QUALITY_SCORE: {score:.2f}
---
"""
                        with open(save_path, 'w', encoding='utf-8') as f:
                            f.write(header + content[:3000])

                        current_counts[detected_cat] = current_counts.get(detected_cat, 0) + 1
                        saved += 1
                        print(f"[GitHub Search] Saved: {filename} ({detected_cat})")

                        global files_saved_this_run
                        files_saved_this_run += 1
                        if files_saved_this_run % 50 == 0:
                            current_total = sum(get_current_category_counts(WALKTHROUGH_DIR).values())
                            print(f"\n[Scraper] Progress: {current_total}/{MAX_TOTAL_WRITEUPS} total files")
                            print_category_progress(get_current_category_counts(WALKTHROUGH_DIR))

                    except Exception:
                        pass
                    time.sleep(0.2)

                time.sleep(1)  # Between pages

            except Exception as e:
                print(f"[GitHub Search] Error: {e}")
                time.sleep(5)
        
        queries_done.append(query)
        checkpoint["github_queries_done"] = queries_done
        save_checkpoint(checkpoint)
        print(f"[GitHub] Query done. Checkpoint saved.")
        
        time.sleep(1)
    
    return  saved


def scrape_medium_ctf_writeups(checkpoint: dict) -> int:
    import requests, time, os
    from pathlib import Path

    pages_done = checkpoint.get("medium_pages_done", [])
    
    medium_feeds = [
        "https://medium.com/feed/tag/ctf",
        "https://medium.com/feed/tag/binary-exploitation",
        "https://medium.com/feed/tag/cybersecurity",
        "https://medium.com/feed/tag/reverse-engineering",
        "https://medium.com/feed/tag/penetration-testing",
    ]
    
    saved = 0
    current_counts = get_current_category_counts(WALKTHROUGH_DIR)
    scraper = get_scraper()
    
    for feed_url in medium_feeds:
        if feed_url in pages_done:
            continue
        try:
            print(f"[Medium] Fetching RSS: {feed_url}")
            resp = requests.get(feed_url, timeout=20, headers={
                "User-Agent": "Mozilla/5.0 (compatible; research scraper)"
            })
            if resp.status_code != 200:
                print(f"[Medium] RSS failed: {resp.status_code}")
                pages_done.append(feed_url)
                continue
            
            import xml.etree.ElementTree as ET
            root = ET.fromstring(resp.text)
            channel = root.find("channel")
            if channel is None:
                pages_done.append(feed_url)
                continue
            
            items = channel.findall("item")
            print(f"[Medium] Found {len(items)} articles in feed")
            
            for item in items:
                if sum(current_counts.values()) >= MAX_TOTAL_WRITEUPS:
                    return saved
                    
                title_el = item.find("title")
                link_el = item.find("link")
                desc_el = item.find("description")
                
                if title_el is None or link_el is None:
                    continue
                    
                title = title_el.text or ""
                link = link_el.text or ""
                description = desc_el.text or "" if desc_el is not None else ""
                
                combined = (title + " " + description).lower()
                ctf_keywords = [
                    "ctf", "binary exploitation", "pwn", "buffer overflow",
                    "format string", "heap", "ret2", "shellcode", "rop",
                    "pwntools", "reverse engineering", "capture the flag"
                ]
                if not any(kw in combined for kw in ctf_keywords):
                    continue
                
                try:
                    article_resp = requests.get(link, timeout=15, headers={
                        "User-Agent": "Mozilla/5.0 (compatible; research scraper)"
                    })
                    if article_resp.status_code != 200:
                        continue
                    
                    from html.parser import HTMLParser
                    
                    class TextExtractor(HTMLParser):
                        def __init__(self):
                            super().__init__()
                            self.text_parts = []
                            self.in_article = False
                            self.skip_tags = {"script", "style", "nav", "header", "footer"}
                            self.current_tag = ""
                            
                        def handle_starttag(self, tag, attrs):
                            self.current_tag = tag
                            attrs_dict = dict(attrs)
                            if "article" in attrs_dict.get("class", "") or tag == "article":
                                self.in_article = True
                                
                        def handle_data(self, data):
                            if self.current_tag not in self.skip_tags:
                                cleaned = data.strip()
                                if cleaned and len(cleaned) > 20:
                                    self.text_parts.append(cleaned)
                    
                    extractor = TextExtractor()
                    extractor.feed(article_resp.text)
                    content = "\n".join(extractor.text_parts)
                    
                    if len(content) < 300:
                        continue
                    
                    if contains_credentials(content):
                        continue
                    
                    is_quality, score, reason = calculate_writeup_quality(content)
                    if not is_quality:
                        continue
                    
                    if is_duplicate_content(content, WALKTHROUGH_DIR):
                        continue
                    
                    detected_cat = detect_category_from_text(content)
                    
                    if not category_needs_more(detected_cat, current_counts):
                        continue
                    
                    import hashlib
                    url_hash = hashlib.md5(link.encode()).hexdigest()[:8]
                    safe_title = "".join(c for c in title[:40] if c.isalnum() or c in "_ ")
                    safe_title = safe_title.replace(" ", "_").lower()
                    filename = f"medium_{safe_title}_{url_hash}.txt"
                    
                    save_dir = os.path.join(WALKTHROUGH_DIR, detected_cat)
                    os.makedirs(save_dir, exist_ok=True)
                    save_path = os.path.join(save_dir, filename)
                    
                    header = f"""SOURCE: medium
URL: {link}
CHALLENGE: {title}
CATEGORY: {detected_cat}
QUALITY_SCORE: {score:.2f}
---
"""
                    with open(save_path, "w", encoding="utf-8") as f:
                        f.write(header + content[:4000])
                    
                    current_counts[detected_cat] = current_counts.get(detected_cat, 0) + 1
                    saved += 1
                    print(f"[Medium] Saved: {filename} ({detected_cat}, score={score:.2f})")
                    
                    time.sleep(0.5)
                    
                except Exception as e:
                    print(f"[Medium] Article error: {e}")
                    continue
            
            pages_done.append(feed_url)
            checkpoint["medium_pages_done"] = pages_done
            save_checkpoint(checkpoint)
            time.sleep(1)
            
        except Exception as e:
            print(f"[Medium] Feed error {feed_url}: {e}")
            pages_done.append(feed_url)
    
    print(f"[Medium] Done. Saved {saved} articles.")
    return saved


def scrape_ctf_writeup_repos(checkpoint: dict) -> int:
    import requests, time, os, hashlib
    
    repos_done = checkpoint.get("ctf_repos_done", [])
    
    # These are well-known CTF writeup mega-repositories on GitHub
    # Each contains dozens to hundreds of individual writeup files
    mega_repos = [
        ("ctfs", "firmianay"),
        ("CTF-Writeups", "csivitu"),
        ("ctf-writeups", "perfectblue"),
        ("writeups", "ret2basic"),
        ("CTF", "VoidHack"),
        ("ctf-writeups", "Naetw"),
        ("CTF-writeups", "bigpick1976"),
        ("pwntools-tutorial", "Gallopsled"),
        ("how2heap", "shellphish"),
        ("CTF-Pwn-Solutions", "0x4ndy"),
        ("pwn-challs", "guyinatuxedo"),
        ("ctf", "osirislab"),
        ("writeups", "kileak"),
        ("ctf-writeups", "hyperreality"),
        ("CTFwriteups", "zst01"),
        # Wave 2 — additional high-quality CTF writeup repos
        ("nightmare", "guyinatuxedo"),
        ("ctf-writeups", "smokeleeteveryday"),
        ("CTF", "str0nkus"),
        ("CTFs", "m3ssap0"),
        ("ctf-writeups", "sixstars"),
        ("ctf-write-ups", "sajjadium"),
        ("ctf-writeups", "Dvd848"),
        ("CTF-Writeups", "0xM4hm0ud"),
        ("pwn-notes", "ir0nstone"),
        ("ctf-writeups", "p4-team"),
        ("ctf-solutions", "Tecnicas-pwn"),
        ("pwndbg", "pwndbg"),
        ("ctf", "r3kapig"),
        ("CTF-Writeups", "nobodyisnobody"),
        ("writeups", "nusgreyhats"),
        ("ctf-writeups", "nnamon"),
        ("ctf-writeups", "kylma"),
        ("heap-exploitation", "dhavalkapil"),
        ("ctf-writeups", "pwning"),
        ("ctf-solutions", "flawwan"),
        # Wave 3 — pwn-specialist teams + curricula
        ("ctf_writeup", "balsn"),
        ("writeups", "DiceGang"),
        ("ctf-writeups", "splitline"),
        ("MBE", "RPISEC"),
        ("CTF-Wiki", "CTF-Wiki"),
        ("ctf-writeups", "Water-Paddler"),
        ("pwn-writeups", "theoremoon"),
    ]
    
    GITHUB_HEADERS = {
        "Authorization": f"token {os.getenv('GITHUB_TOKEN', '') or os.getenv('GITHUB_Token', '')}",
        "Accept": "application/vnd.github.v3+json",
    }
    
    saved = 0
    current_counts = get_current_category_counts(WALKTHROUGH_DIR)
    
    for repo_name, owner in mega_repos:
        repo_key = f"{owner}/{repo_name}"
        if repo_key in repos_done:
            print(f"[RepoScraper] Skipping already-done: {repo_key}")
            continue
            
        if sum(current_counts.values()) >= MAX_TOTAL_WRITEUPS:
            break
        
        print(f"[RepoScraper] Scraping {repo_key}...")
        
        # Get all .md files recursively from the repo
        api_url = f"https://api.github.com/repos/{owner}/{repo_name}/git/trees/HEAD?recursive=1"
        try:
            resp = requests.get(api_url, headers=GITHUB_HEADERS, timeout=20)
            if resp.status_code == 404:
                repos_done.append(repo_key)
                continue
            if resp.status_code == 403:
                print("[RepoScraper] Rate limited. Sleeping 60s...")
                time.sleep(60)
                continue
            if resp.status_code != 200:
                repos_done.append(repo_key)
                continue
                
            tree = resp.json().get("tree", [])
            md_files = [
                f for f in tree
                if f.get("type") == "blob" and
                f.get("path", "").endswith(".md") and
                any(kw in f.get("path", "").lower() for kw in
                    ["pwn", "bin", "exploit", "overflow", "rop",
                     "heap", "format", "shellcode", "ret2"])
            ]
            
            print(f"[RepoScraper] Found {len(md_files)} relevant .md files in {repo_key}")
            
            for file_info in md_files[:50]:  # Max 50 files per repo
                if sum(current_counts.values()) >= MAX_TOTAL_WRITEUPS:
                    break
                    
                raw_url = (
                    f"https://raw.githubusercontent.com/"
                    f"{owner}/{repo_name}/HEAD/{file_info['path']}"
                )
                try:
                    content_resp = requests.get(raw_url, timeout=15)
                    if content_resp.status_code != 200:
                        continue
                    
                    content = content_resp.text
                    
                    if len(content) < 200:
                        continue
                    if contains_credentials(content):
                        continue
                    
                    is_quality, score, _ = calculate_writeup_quality(content)
                    if not is_quality:
                        continue
                    
                    if is_duplicate_content(content, WALKTHROUGH_DIR):
                        continue
                    
                    detected_cat = detect_category_from_text(content)
                    
                    if not category_needs_more(detected_cat, current_counts):
                        continue
                    
                    url_hash = hashlib.md5(raw_url.encode()).hexdigest()[:8]
                    safe_path = file_info["path"].replace("/", "_")[:40]
                    filename = f"gitrepo_{owner}_{safe_path}_{url_hash}.txt"
                    
                    save_dir = os.path.join(WALKTHROUGH_DIR, detected_cat)
                    os.makedirs(save_dir, exist_ok=True)
                    save_path = os.path.join(save_dir, filename)
                    
                    header = f"""SOURCE: github_repo
URL: https://github.com/{owner}/{repo_name}/blob/HEAD/{file_info['path']}
CHALLENGE: {file_info['path'].split('/')[-1].replace('.md', '')}
CATEGORY: {detected_cat}
QUALITY_SCORE: {score:.2f}
---
"""
                    with open(save_path, "w", encoding="utf-8") as f:
                        f.write(header + content[:4000])
                    
                    current_counts[detected_cat] = current_counts.get(detected_cat, 0) + 1
                    saved += 1
                    print(f"[RepoScraper] Saved: {filename} ({detected_cat})")
                    time.sleep(0.2)
                    
                except Exception as e:
                    print(f"[RepoScraper] File error: {e}")
                    continue
            
            repos_done.append(repo_key)
            checkpoint["ctf_repos_done"] = repos_done
            save_checkpoint(checkpoint)
            time.sleep(1)
            
        except Exception as e:
            print(f"[RepoScraper] Repo error {repo_key}: {e}")
            repos_done.append(repo_key)
            time.sleep(2)
    
    print(f"[RepoScraper] Done. Saved {saved} files.")
    return saved


def scrape_by_category(checkpoint: dict) -> int:
    """Uses CATEGORY_SEARCH_QUERIES to target every underfilled category via GitHub search."""
    import hashlib
    
    queries_done = checkpoint.get("category_queries_done", [])
    current_counts = get_current_category_counts(WALKTHROUGH_DIR)
    saved = 0
    
    for category, queries in CATEGORY_SEARCH_QUERIES.items():
        if not category_needs_more(category, current_counts):
            continue
            
        for query in queries:
            if query in queries_done:
                continue
                
            if sum(current_counts.values()) >= MAX_TOTAL_WRITEUPS:
                return saved
            
            print(f"[ByCategory] {category}: {query[:50]}")
            
            for page in range(1, 6):
                url = "https://api.github.com/search/repositories"
                params = {
                    "q": query,
                    "sort": "stars",
                    "order": "desc",
                    "per_page": 30,
                    "page": page,
                }
                try:
                    resp = requests.get(url, headers=GITHUB_HEADERS,
                                       params=params, timeout=15)
                    if resp.status_code == 403:
                        print("[ByCategory] Rate limited. Sleeping 60s...")
                        time.sleep(60)
                        break
                    if resp.status_code != 200:
                        break
                        
                    repos = resp.json().get("items", [])
                    if not repos:
                        break
                    
                    for repo in repos:
                        if sum(current_counts.values()) >= MAX_TOTAL_WRITEUPS:
                            return saved
                        
                        # Try README
                        raw_url = (
                            f"https://raw.githubusercontent.com/"
                            f"{repo['full_name']}/"
                            f"{repo.get('default_branch', 'main')}/README.md"
                        )
                        try:
                            readme = requests.get(raw_url, timeout=10)
                            if readme.status_code != 200 or len(readme.text) < 300:
                                continue
                            
                            content = readme.text
                            if contains_credentials(content):
                                continue
                            
                            is_quality, score, _ = calculate_writeup_quality(content)
                            if not is_quality:
                                continue
                            
                            if is_duplicate_content(content, WALKTHROUGH_DIR):
                                continue
                            
                            detected_cat = detect_category_from_text(content)
                            if not category_needs_more(detected_cat, current_counts):
                                continue
                            
                            url_hash = hashlib.md5(raw_url.encode()).hexdigest()[:8]
                            slug = repo['name'][:30]
                            filename = f"catquery_{detected_cat}_{slug}_{url_hash}.txt"
                            save_dir = os.path.join(WALKTHROUGH_DIR, detected_cat)
                            os.makedirs(save_dir, exist_ok=True)
                            
                            header = f"""SOURCE: category_search
URL: {repo['html_url']}
CHALLENGE: {repo['name']}
CATEGORY: {detected_cat}
QUALITY_SCORE: {score:.2f}
---
"""
                            with open(os.path.join(save_dir, filename),
                                     "w", encoding="utf-8") as f:
                                f.write(header + content[:4000])
                            
                            current_counts[detected_cat] = (
                                current_counts.get(detected_cat, 0) + 1
                            )
                            saved += 1
                            print(f"[ByCategory] Saved: {filename} ({detected_cat})")
                            
                        except Exception:
                            pass
                        time.sleep(0.3)
                    
                    time.sleep(1)
                    
                except Exception as e:
                    print(f"[ByCategory] Error: {e}")
                    time.sleep(3)
            
            queries_done.append(query)
            checkpoint["category_queries_done"] = queries_done
            save_checkpoint(checkpoint)
    
    print(f"[ByCategory] Done. Saved {saved} files.")
    return saved


def scrape_github_topics(checkpoint: dict) -> int:
    """Search GitHub by topic tags instead of keyword queries — surfaces
    repos tagged but not matched by scrape_github_search_bulk()."""
    import hashlib
    topics_done = checkpoint.get("github_topics_done", [])
    topics = [
        "pwn", "binary-exploitation", "ctf-writeups", "heap-exploitation",
        "rop-chain", "format-string", "reverse-engineering", "exploit-development",
    ]
    saved = 0
    current_counts = get_current_category_counts(WALKTHROUGH_DIR)

    for topic in topics:
        if topic in topics_done:
            print(f"[Topics] Skipping already-done topic: {topic}")
            continue
        print(f"[Topics] Searching topic:{topic}")
        for page in range(1, 6):
            if sum(current_counts.values()) >= MAX_TOTAL_WRITEUPS:
                return saved
            url = "https://api.github.com/search/repositories"
            params = {"q": f"topic:{topic}", "sort": "stars", "order": "desc",
                      "per_page": 30, "page": page}
            try:
                resp = requests.get(url, headers=GITHUB_HEADERS, params=params, timeout=15)
                if resp.status_code == 403:
                    print("[Topics] Rate limited. Sleeping 60s...")
                    time.sleep(60)
                    continue
                if resp.status_code != 200:
                    break
                repos = resp.json().get("items", [])
                if not repos:
                    break
                for repo in repos:
                    if sum(current_counts.values()) >= MAX_TOTAL_WRITEUPS:
                        return saved
                    raw_url = (f"https://raw.githubusercontent.com/{repo['full_name']}/"
                               f"{repo.get('default_branch','main')}/README.md")
                    try:
                        readme = requests.get(raw_url, timeout=10)
                        if readme.status_code != 200 or len(readme.text) < 300:
                            continue
                        content = readme.text
                        if contains_credentials(content):
                            continue
                        is_quality, score, _ = calculate_writeup_quality(content)
                        if not is_quality:
                            continue
                        detected_cat = detect_category_from_text(content)
                        if not category_needs_more(detected_cat, current_counts):
                            continue
                        if is_duplicate_content(content, WALKTHROUGH_DIR):
                            continue
                        url_hash = hashlib.md5(raw_url.encode()).hexdigest()[:8]
                        slug = repo['full_name'].replace('/', '_')[:40]
                        filename = f"topic_{detected_cat}_{slug}_{url_hash}.txt"
                        save_dir = os.path.join(WALKTHROUGH_DIR, detected_cat)
                        os.makedirs(save_dir, exist_ok=True)
                        header = f"""SOURCE: github_topic
URL: {repo['html_url']}
CHALLENGE: {repo['name']}
CATEGORY: {detected_cat}
QUALITY_SCORE: {score:.2f}
---
"""
                        with open(os.path.join(save_dir, filename), 'w', encoding='utf-8') as f:
                            f.write(header + content[:3000])
                        current_counts[detected_cat] = current_counts.get(detected_cat, 0) + 1
                        saved += 1
                        print(f"[Topics] Saved: {filename} ({detected_cat})")
                    except Exception:
                        pass
                    time.sleep(0.2)
                time.sleep(1)
            except Exception as e:
                print(f"[Topics] Error: {e}")
                time.sleep(5)
        topics_done.append(topic)
        checkpoint["github_topics_done"] = topics_done
        save_checkpoint(checkpoint)
    return saved


def scrape_pwnable_kr_writeups() -> int:
    import requests, time, os
    print("\n[Scraper] Scraping pwnable.kr writeups from GitHub...")
    query = "pwnable.kr writeup exploit"
    url = "https://api.github.com/search/repositories"
    params = {
        "q": query,
        "sort": "stars",
        "order": "desc",
        "per_page": 10,
    }
    saved = 0
    scraper = get_scraper()
    
    try:
        resp = requests.get(url, headers=GITHUB_HEADERS, params=params, timeout=15)
        if resp.status_code != 200:
            print(f"[pwnable.kr] GitHub search failed: {resp.status_code}")
            return 0
        repos = resp.json().get("items", [])
        for repo in repos:
            owner = repo["owner"]["login"]
            repo_name = repo["name"]
            branch = repo.get("default_branch", "master")
            
            print(f"[pwnable.kr] Scraping repository: {owner}/{repo_name}...")
            tree_url = f"https://api.github.com/repos/{owner}/{repo_name}/git/trees/{branch}?recursive=1"
            time.sleep(1)
            tree_resp = requests.get(tree_url, headers=GITHUB_HEADERS, timeout=15)
            if tree_resp.status_code != 200:
                continue
            tree = tree_resp.json().get("tree", [])
            for item in tree:
                path = item.get("path", "")
                if item.get("type") == "blob" and (path.endswith(".md") or path.endswith(".txt")):
                    filename_lower = os.path.basename(path).lower()
                    if any(x in filename_lower for x in ["readme", "license", "summary"]):
                        continue
                    
                    raw_url = f"https://raw.githubusercontent.com/{owner}/{repo_name}/{branch}/{path}"
                    if raw_url in scraper.scraped_urls:
                        continue
                    
                    time.sleep(0.5)
                    raw_r = requests.get(raw_url, headers=scraper.headers, timeout=10)
                    if raw_r.status_code == 200:
                        scraper.scraped_urls.add(raw_url)
                        scraper._save_scraped_urls()
                        content = raw_r.text
                        
                        if len(content) < 150 or contains_credentials(content):
                            continue
                        
                        is_quality, score, _ = calculate_writeup_quality(content)
                        if not is_quality:
                            continue
                            
                        if is_duplicate_content(content, WALKTHROUGH_DIR):
                            continue
                        
                        detected_cat = detect_category_from_text(content)
                        
                        slug = f"{owner}_{repo_name}_{os.path.splitext(os.path.basename(path))[0]}"
                        safe_slug = "".join(c for c in slug if c.isalnum() or c in "_-").lower()
                        filename = f"pwnablekr_{safe_slug}.txt"
                        save_dir = os.path.join(WALKTHROUGH_DIR, "pwnablekr")
                        os.makedirs(save_dir, exist_ok=True)
                        save_path = os.path.join(save_dir, filename)
                        
                        header = f"""SOURCE: pwnable_kr
URL: {raw_url}
CHALLENGE: {os.path.basename(path)}
CATEGORY: {detected_cat}
QUALITY_SCORE: {score:.2f}
---
"""
                        with open(save_path, "w", encoding="utf-8") as f:
                            f.write(header + content[:4000])
                        
                        saved += 1
                        print(f"[pwnable.kr] Saved: {filename} ({detected_cat})")
    except Exception as e:
        print(f"[pwnable.kr] Error: {e}")
    return saved


def scrape_pwnable_tw() -> int:
    import requests, time, os
    print("\n[Scraper] Scraping pwnable.tw writeups from GitHub...")
    query = "pwnable.tw writeup exploit"
    url = "https://api.github.com/search/repositories"
    params = {
        "q": query,
        "sort": "stars",
        "order": "desc",
        "per_page": 10,
    }
    saved = 0
    scraper = get_scraper()
    
    try:
        resp = requests.get(url, headers=GITHUB_HEADERS, params=params, timeout=15)
        if resp.status_code != 200:
            print(f"[pwnable.tw] GitHub search failed: {resp.status_code}")
            return 0
        repos = resp.json().get("items", [])
        for repo in repos:
            owner = repo["owner"]["login"]
            repo_name = repo["name"]
            branch = repo.get("default_branch", "master")
            
            print(f"[pwnable.tw] Scraping repository: {owner}/{repo_name}...")
            tree_url = f"https://api.github.com/repos/{owner}/{repo_name}/git/trees/{branch}?recursive=1"
            time.sleep(1)
            tree_resp = requests.get(tree_url, headers=GITHUB_HEADERS, timeout=15)
            if tree_resp.status_code != 200:
                continue
            tree = tree_resp.json().get("tree", [])
            for item in tree:
                path = item.get("path", "")
                if item.get("type") == "blob" and (path.endswith(".md") or path.endswith(".txt")):
                    filename_lower = os.path.basename(path).lower()
                    if any(x in filename_lower for x in ["readme", "license", "summary"]):
                        continue
                    
                    raw_url = f"https://raw.githubusercontent.com/{owner}/{repo_name}/{branch}/{path}"
                    if raw_url in scraper.scraped_urls:
                        continue
                    
                    time.sleep(0.5)
                    raw_r = requests.get(raw_url, headers=scraper.headers, timeout=10)
                    if raw_r.status_code == 200:
                        scraper.scraped_urls.add(raw_url)
                        scraper._save_scraped_urls()
                        content = raw_r.text
                        
                        if len(content) < 150 or contains_credentials(content):
                            continue
                        
                        is_quality, score, _ = calculate_writeup_quality(content)
                        if not is_quality:
                            continue
                            
                        if is_duplicate_content(content, WALKTHROUGH_DIR):
                            continue
                        
                        detected_cat = detect_category_from_text(content)
                        
                        slug = f"{owner}_{repo_name}_{os.path.splitext(os.path.basename(path))[0]}"
                        safe_slug = "".join(c for c in slug if c.isalnum() or c in "_-").lower()
                        filename = f"pwnabletw_{safe_slug}.txt"
                        save_dir = os.path.join(WALKTHROUGH_DIR, "pwnabletw")
                        os.makedirs(save_dir, exist_ok=True)
                        save_path = os.path.join(save_dir, filename)
                        
                        header = f"""SOURCE: pwnable_tw
URL: {raw_url}
CHALLENGE: {os.path.basename(path)}
CATEGORY: {detected_cat}
QUALITY_SCORE: {score:.2f}
---
"""
                        with open(save_path, "w", encoding="utf-8") as f:
                            f.write(header + content[:4000])
                        
                        saved += 1
                        print(f"[pwnable.tw] Saved: {filename} ({detected_cat})")
    except Exception as e:
        print(f"[pwnable.tw] Error: {e}")
    return saved


def scrape_pwn_ctf_archives(checkpoint: dict) -> int:
    """Targets writeups from pwn-dense competitions specifically."""
    import hashlib
    queries_done = checkpoint.get("pwn_archive_queries_done", [])
    queries = [
        "hxp ctf writeup pwn exploit",
        "corctf writeup pwn binary exploit",
        "0ctf tctf writeup pwn exploit",
        "real world ctf writeup pwn kernel heap",
        "seccon writeup pwn binary exploit",
        "zer0pts ctf writeup pwn exploit",
        "tokyowesterns ctf writeup pwn exploit",
    ]
    saved = 0
    current_counts = get_current_category_counts(WALKTHROUGH_DIR)
    for query in queries:
        if query in queries_done:
            continue
        print(f"[PwnArchives] Query: {query}")
        for page in range(1, 4):
            if sum(current_counts.values()) >= MAX_TOTAL_WRITEUPS:
                return saved
            url = "https://api.github.com/search/repositories"
            params = {"q": query, "sort": "stars", "order": "desc", "per_page": 30, "page": page}
            try:
                resp = requests.get(url, headers=GITHUB_HEADERS, params=params, timeout=15)
                if resp.status_code == 403:
                    time.sleep(60)
                    continue
                if resp.status_code != 200:
                    break
                repos = resp.json().get("items", [])
                if not repos:
                    break
                for repo in repos:
                    if sum(current_counts.values()) >= MAX_TOTAL_WRITEUPS:
                        return saved
                    raw_url = (f"https://raw.githubusercontent.com/{repo['full_name']}/"
                               f"{repo.get('default_branch','main')}/README.md")
                    try:
                        readme = requests.get(raw_url, timeout=10)
                        if readme.status_code != 200 or len(readme.text) < 300:
                            continue
                        content = readme.text
                        if contains_credentials(content):
                            continue
                        is_quality, score, _ = calculate_writeup_quality(content)
                        if not is_quality:
                            continue
                        detected_cat = detect_category_from_text(content)
                        if not category_needs_more(detected_cat, current_counts):
                            continue
                        if is_duplicate_content(content, WALKTHROUGH_DIR):
                            continue
                        url_hash = hashlib.md5(raw_url.encode()).hexdigest()[:8]
                        slug = repo['full_name'].replace('/', '_')[:40]
                        filename = f"pwnarchive_{detected_cat}_{slug}_{url_hash}.txt"
                        save_dir = os.path.join(WALKTHROUGH_DIR, detected_cat)
                        os.makedirs(save_dir, exist_ok=True)
                        header = f"""SOURCE: pwn_archive
URL: {repo['html_url']}
CHALLENGE: {repo['name']}
CATEGORY: {detected_cat}
QUALITY_SCORE: {score:.2f}
---
"""
                        with open(os.path.join(save_dir, filename), 'w', encoding='utf-8') as f:
                            f.write(header + content[:3000])
                        current_counts[detected_cat] = current_counts.get(detected_cat, 0) + 1
                        saved += 1
                        print(f"[PwnArchives] Saved: {filename} ({detected_cat})")
                    except Exception:
                        pass
                    time.sleep(0.2)
                time.sleep(1)
            except Exception as e:
                print(f"[PwnArchives] Error: {e}")
                time.sleep(5)
        queries_done.append(query)
        checkpoint["pwn_archive_queries_done"] = queries_done
        save_checkpoint(checkpoint)
    return saved


def scrape_exploit_education() -> int:
    import requests, time, os
    from bs4 import BeautifulSoup
    print("\n[Scraper] Scraping exploit.education...")
    base_urls = [
        "https://exploit.education/phoenix/",
        "https://exploit.education/fusion/",
        "https://exploit.education/nebula/",
    ]
    saved = 0
    scraper = get_scraper()
    
    for base_url in base_urls:
        try:
            time.sleep(0.5)
            resp = requests.get(base_url, headers=SCRAPER_HEADERS, timeout=15)
            if resp.status_code != 200:
                print(f"[Exploit Education] Failed to fetch index {base_url}: {resp.status_code}")
                continue
            
            soup = BeautifulSoup(resp.text, 'lxml')
            links = []
            for a in soup.find_all('a', href=True):
                href = a['href']
                full_url = urllib.parse.urljoin(base_url, href)
                if full_url.startswith(base_url) and len(full_url) > len(base_url):
                    if full_url not in links:
                        links.append(full_url)
            
            print(f"[Exploit Education] Found {len(links)} links for {base_url}")
            for link in links:
                if link in scraper.scraped_urls:
                    continue
                
                try:
                    time.sleep(0.5)
                    r = requests.get(link, headers=SCRAPER_HEADERS, timeout=10)
                    if r.status_code != 200:
                        continue
                    
                    sub_soup = BeautifulSoup(r.text, 'lxml')
                    title_el = sub_soup.find('h1') or sub_soup.find('title')
                    challenge_title = title_el.text.strip() if title_el else link.rstrip('/').split('/')[-1]
                    
                    text = scraper.extract_page_content(sub_soup, 'exploit_education')
                    if len(text.split()) < 100:
                        continue
                    
                    if contains_credentials(text):
                        continue
                        
                    detected_cat = detect_category_from_text(text)
                    if detected_cat == 'unknown':
                        pred_cat = scraper.predict_category_from_meta(challenge_title, link)
                        if pred_cat != 'others':
                            detected_cat = pred_cat
                        else:
                            detected_cat = 'rop_chain'
                    
                    import hashlib
                    url_hash = hashlib.md5(link.encode()).hexdigest()[:8]
                    safe_title = "".join(c for c in challenge_title[:40] if c.isalnum() or c in "_ ")
                    safe_title = safe_title.replace(" ", "_").lower()
                    filename = f"exploitedu_{safe_title}_{url_hash}.txt"
                    
                    save_dir = os.path.join(WALKTHROUGH_DIR, "exploit_education")
                    os.makedirs(save_dir, exist_ok=True)
                    save_path = os.path.join(save_dir, filename)
                    
                    header = f"""SOURCE: exploit_education
URL: {link}
CHALLENGE: {challenge_title}
CATEGORY: {detected_cat}
QUALITY_SCORE: 1.00
---
"""
                    with open(save_path, "w", encoding="utf-8") as f:
                        f.write(header + text[:4000])
                    
                    scraper.scraped_urls.add(link)
                    scraper._save_scraped_urls()
                    saved += 1
                    print(f"[Exploit Education] Saved: {filename} ({detected_cat})")
                except Exception as e:
                    print(f"[Exploit Education] Error on page {link}: {e}")
        except Exception as e:
            print(f"[Exploit Education] Error on index {base_url}: {e}")
            
    return saved


def scrape_ropemporium() -> int:
    import requests, time, os
    from bs4 import BeautifulSoup
    print("\n[Scraper] Scraping ropemporium...")
    challenges = ["ret2win", "split", "callme", "write4", "badchars", "fluff", "pivot", "ret2csu"]
    saved = 0
    scraper = get_scraper()
    
    for chal in challenges:
        url = f"https://ropemporium.com/challenge/{chal}.html"
        if url in scraper.scraped_urls:
            continue
        
        try:
            time.sleep(0.5)
            resp = requests.get(url, headers=SCRAPER_HEADERS, timeout=15)
            if resp.status_code != 200:
                print(f"[ROP Emporium] Failed to fetch {url}: {resp.status_code}")
                continue
            
            soup = BeautifulSoup(resp.text, 'lxml')
            title_el = soup.find('h1') or soup.find('title')
            title = title_el.text.strip() if title_el else chal
            
            text = scraper.extract_page_content(soup, 'ropemporium')
            if len(text.split()) < 100:
                continue
                
            if chal == "ret2win":
                category = "ret2win"
            elif chal == "ret2csu":
                category = "ret2csu"
            else:
                category = "rop_chain"
                
            filename = f"ropemporium_{chal}.txt"
            save_dir = os.path.join(WALKTHROUGH_DIR, "ropemporium")
            os.makedirs(save_dir, exist_ok=True)
            save_path = os.path.join(save_dir, filename)
            
            header = f"""SOURCE: ropemporium
URL: {url}
CHALLENGE: {title}
CATEGORY: {category}
QUALITY_SCORE: 1.00
---
"""
            with open(save_path, "w", encoding="utf-8") as f:
                f.write(header + text[:4000])
            
            scraper.scraped_urls.add(url)
            scraper._save_scraped_urls()
            saved += 1
            print(f"[ROP Emporium] Saved: {filename} ({category})")
        except Exception as e:
            print(f"[ROP Emporium] Error on {chal}: {e}")
            
    return saved


def scrape_how2heap() -> int:
    print("\n[Scraper] Scraping how2heap...")
    api_url = "https://api.github.com/repos/shellphish/how2heap/contents/"
    scraper = get_scraper()
    saved = 0
    try:
        time.sleep(0.5)
        r = requests.get(api_url, headers=GITHUB_HEADERS, timeout=15)
        if r.status_code != 200:
            print(f"Failed to list how2heap contents: {r.status_code}")
            return 0
        items = r.json()
        c_files = [item["name"] for item in items if item["name"].endswith(".c")]
        print(f"Found {len(c_files)} how2heap .c files. Scraping them...")
        for fname in c_files:
            challenge_name = fname.replace(".c", "")
            raw_url = f"https://raw.githubusercontent.com/shellphish/how2heap/master/{fname}"
            
            if raw_url in scraper.scraped_urls:
                print(f"[Scraper] Already scraped: {raw_url}. Skipping.")
                continue

            time.sleep(0.5)
            raw_r = requests.get(raw_url, headers=scraper.headers, timeout=10)
            if raw_r.status_code == 200:
                text = raw_r.text
                lines = text.splitlines()
                comment_lines = []
                for line in lines:
                    trimmed = line.strip()
                    if trimmed.startswith("//"):
                        comment_lines.append(trimmed[2:].strip())
                
                comment_content = "\n".join(comment_lines)
                if not comment_content.strip():
                    comment_content = text
                    
                scraper.save_writeup(
                    source="how2heap",
                    url=raw_url,
                    challenge=challenge_name,
                    event="how2heap",
                    team="N/A",
                    text=comment_content
                )
                saved += 1
    except Exception as e:
        print(f"Error scraping how2heap: {e}")
    return saved


def scrape_ctf_pwn_tips() -> int:
    print("\n[Scraper] Scraping CTF-pwn-tips...")
    readme_url = "https://raw.githubusercontent.com/Naetw/CTF-pwn-tips/master/README.md"
    scraper = get_scraper()
    saved = 0
    try:
        time.sleep(SLEEP_WEB)
        r = requests.get(readme_url, headers=scraper.headers, timeout=10)
        if r.status_code != 200:
            print(f"Failed to fetch CTF-pwn-tips README: {r.status_code}")
            return 0
        content = r.text
        sections = re.split(r'\n##\s+', content)
        print(f"Found {len(sections)} sections in README. Processing...")
        keywords = ["overflow", "format", "heap", "rop", "got", "plt", "canary", "pie", "shellcode", "ret2"]
        for sec in sections:
            if not sec.strip():
                continue
            lines = sec.strip().splitlines()
            title = lines[0].strip()
            sec_text = "\n".join(lines[1:])
            
            sec_lower = sec.lower()
            if any(kw in sec_lower for kw in keywords):
                challenge_name = title.replace("#", "").strip()
                anchor_name = title.lower().replace(" ", "-").replace("/", "").replace("'", "")
                url = f"https://github.com/Naetw/CTF-pwn-tips#{anchor_name}"
                
                scraper.save_writeup(
                    source="ctf_pwn_tips",
                    url=url,
                    challenge=challenge_name,
                    event="CTF-pwn-tips",
                    team="N/A",
                    text=sec_text
                )
                saved += 1
    except Exception as e:
        print(f"Error scraping ctf_pwn_tips: {e}")
    return saved


def scrape_nobodyisnobody(checkpoint: dict) -> int:
    if "nobodyisnobody" in checkpoint.get("sources_completed", []):
        print("[nobodyisnobody] Already completed — skipping")
        return 0
        
    print("\n[Scraper] Scraping nobodyisnobody...")
    base_url = "https://nobodyisnobody.github.io"
    scraper = get_scraper()
    saved = 0
    try:
        time.sleep(SLEEP_WEB)
        r = requests.get(base_url, headers=scraper.headers, timeout=15)
        if r.status_code != 200:
            print(f"Failed to fetch nobodyisnobody main page: {r.status_code}")
            return 0
        soup = BeautifulSoup(r.text, 'lxml')
        links = []
        keywords = ["heap", "pwn", "exploit", "overflow", "rop", "format"]
        for a in soup.find_all('a', href=True):
            href = a['href']
            full_url = urllib.parse.urljoin(base_url, href)
            if "nobodyisnobody.github.io" in full_url and any(kw in full_url.lower() for kw in keywords):
                if full_url not in links:
                    links.append(full_url)
        
        links = links[:30]
        print(f"Found {len(links)} matching nobodyisnobody links. Scraping them...")
        for url in links:
            if url in scraper.scraped_urls:
                print(f"[Scraper] Already scraped: {url}. Skipping.")
                continue

            time.sleep(SLEEP_WEB)
            res = requests.get(url, headers=scraper.headers, timeout=10)
            if res.status_code == 200:
                sub_soup = BeautifulSoup(res.text, 'lxml')
                title_el = sub_soup.find('h1') or sub_soup.find('title')
                challenge_name = title_el.text.strip() if title_el else url.rstrip('/').split('/')[-1]
                challenge_name = challenge_name.replace("nobodyisnobody", "").strip()
                
                text = scraper.extract_page_content(sub_soup, 'nobodyisnobody')
                if len(text.split()) < 150:
                    continue
                
                scraper.save_writeup(
                    source="nobodyisnobody",
                    url=url,
                    challenge=challenge_name,
                    event="nobodyisnobody Blog",
                    team="N/A",
                    text=text
                )
                saved += 1
                
        checkpoint.setdefault("sources_completed", []).append("nobodyisnobody")
        save_checkpoint(checkpoint)
    except Exception as e:
        print(f"Error scraping nobodyisnobody: {e}")
    return saved


def scrape_ir0nstone_extended() -> int:
    print("\n[Scraper] Scraping ir0nstone_extended...")
    target_urls = [
        "https://ir0nstone.gitbook.io/notes/types/stack/return-oriented-programming/ret2csu",
        "https://ir0nstone.gitbook.io/notes/types/stack/return-oriented-programming/srop",
        "https://ir0nstone.gitbook.io/notes/types/heap/use-after-free",
        "https://ir0nstone.gitbook.io/notes/types/heap/tcache-poisoning",
        "https://ir0nstone.gitbook.io/notes/types/heap/fastbin-dup",
        "https://ir0nstone.gitbook.io/notes/types/stack/got-overwrite",
    ]
    scraper = get_scraper()
    saved = 0
    for url in target_urls:
        challenge_name = url.rstrip('/').split('/')[-1]
        if url in scraper.scraped_urls:
            print(f"[Scraper] Already scraped: {url}. Skipping.")
            continue

        try:
            time.sleep(SLEEP_WEB)
            res = requests.get(url, headers=scraper.headers, timeout=10)
            if res.status_code == 200:
                soup = BeautifulSoup(res.text, 'lxml')
                text = scraper.extract_page_content(soup, 'ironstone')
                if len(text.split()) < 150:
                    continue
                
                scraper.save_writeup(
                    source="ir0nstone",
                    url=url,
                    challenge=challenge_name.replace('-', ' ').title(),
                    event="ir0nstone's GitBook",
                    team="N/A",
                    text=text
                )
                saved += 1
        except Exception as e:
            print(f"Error scraping ir0nstone page {url}: {e}")
    return saved


class WriteupScraper:
    def __init__(self):
        import os
        from dotenv import load_dotenv

        # Explicitly load from backend/.env regardless of working directory
        dotenv_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "..", ".env"
        )
        if os.path.exists(dotenv_path):
            load_dotenv(dotenv_path=dotenv_path)
            print(f"[Scraper] Loaded .env from: {dotenv_path}")
        else:
            load_dotenv()
            print(f"[Scraper] Fallback: loaded .env from default location")

        github_token = os.getenv("GITHUB_TOKEN", "")
        self.headers = {
            "User-Agent": "BinExplain/1.0 Educational Tool",
            **({"Authorization": f"token {github_token}"} if github_token else {})
        }

        if github_token:
            print(f"[Scraper] GitHub API token loaded — rate limit: 5000 req/hour")
        else:
            print(f"[Scraper] WARNING: No GITHUB_TOKEN found — rate limit: 60 req/hour")
        self.base_dir = os.path.dirname(os.path.abspath(__file__))
        self.walkthroughs_dir = os.path.join(self.base_dir, "walkthroughs")
        self.saved_count = 0
        self.scraped_urls_file = os.path.join(self.base_dir, "scraped_urls.json")
        self.scraped_urls = self._load_scraped_urls()
        self.content_hashes_file = os.path.join(
            self.base_dir, "content_hashes.json"
        )
        self.content_hashes = self._load_content_hashes()
        self.counts = get_current_category_counts(self.walkthroughs_dir)
        self._cached_total = None

    def get_current_total(self) -> int:
        if self._cached_total is None:
            self._cached_total = get_total_writeup_count(self.walkthroughs_dir)
        return self._cached_total

    def _load_scraped_urls(self) -> set:
        if os.path.exists(self.scraped_urls_file):
            try:
                import json
                with open(self.scraped_urls_file, 'r', encoding='utf-8') as f:
                    return set(json.load(f))
            except Exception:
                return set()
        return set()

    def _save_scraped_urls(self):
        import json
        try:
            with open(self.scraped_urls_file, 'w', encoding='utf-8') as f:
                json.dump(list(self.scraped_urls), f)
        except Exception as e:
            print(f"[Scraper] Warning: could not save scraped URLs: {e}")

    def _load_content_hashes(self) -> set:
        if os.path.exists(self.content_hashes_file):
            try:
                import json
                with open(self.content_hashes_file, 'r', encoding='utf-8') as f:
                    return set(json.load(f))
            except Exception:
                return set()
        return set()

    def _save_content_hashes(self):
        import json
        try:
            with open(self.content_hashes_file, 'w', encoding='utf-8') as f:
                json.dump(list(self.content_hashes), f)
        except Exception as e:
            print(f"[Scraper] Warning: could not save content hashes: {e}")

    def _is_duplicate_content(self, text: str) -> bool:
        import hashlib
        content_hash = hashlib.md5(
            text[:500].strip().encode('utf-8')
        ).hexdigest()
        if content_hash in self.content_hashes:
            return True
        self.content_hashes.add(content_hash)
        self._save_content_hashes()
        return False

    def sanitize_filename(self, name):
        sanitized = re.sub(r'[^a-zA-Z0-9_\-\s]', '', name)
        sanitized = re.sub(r'[\s\-]+', '_', sanitized)
        return sanitized.strip('_').lower()

    def predict_category_from_meta(self, title: str, url: str) -> str:
        s = f"{title} {url}".lower()
        if "tcache" in s: return "tcache_poisoning"
        if "fastbin" in s: return "fastbin_dup"
        if "house_of_force" in s or "house-of-force" in s: return "house_of_force"
        if "house_of_spirit" in s or "house-of-spirit" in s: return "house_of_spirit"
        if "house_of_orange" in s or "house-of-orange" in s: return "house_of_orange"
        if "unsorted_bin" in s or "unsortedbin" in s: return "unsorted_bin_attack"
        if "uaf" in s or "use.after.free" in s: return "use_after_free"
        if "double.free" in s: return "use_after_free"
        if "ret2plt" in s or "ret2-plt" in s: return "ret2plt"
        if "got" in s and ("overwrite" in s or "hijack" in s): return "got_overwrite"
        if "ret2csu" in s or "csu" in s: return "ret2csu"
        if "srop" in s or "sigreturn" in s: return "srop"
        if "stack.pivot" in s or "pivot" in s: return "stack_pivot"
        if "one.gadget" in s or "onegadget" in s: return "one_gadget"
        if "canary" in s: return "canary_bypass"
        if "pie" in s and ("bypass" in s or "leak" in s): return "pie_bypass"
        if "off.by.one" in s or "obo" in s: return "off_by_one"
        if "integer.overflow" in s or "int.overflow" in s: return "integer_overflow"
        if "seccomp" in s: return "seccomp_bypass"
        if "ret2win" in s or "win_func" in s: return "ret2win"
        if "ret2libc" in s or "libc" in s: return "ret2libc"
        if "format" in s or "fmt" in s or "printf" in s: return "format_string"
        if "heap" in s or "malloc" in s or "free" in s or "chunk" in s: return "heap_exploitation"
        if "rop" in s or "gadget" in s: return "rop_chain"
        if "shellcode" in s or "shell" in s: return "shellcode"
        return "others"

    def detect_category(self, text: str) -> str:
        return detect_category_from_text(text)

    def detect_difficulty(self, text):
        text_lower = text.lower()
        if "easy" in text_lower:
            return "Easy"
        elif "medium" in text_lower:
            return "Medium"
        elif "hard" in text_lower:
            return "Hard"
        return "Unknown"

    def detect_protections(self, text):
        text_lower = text.lower()
        protections = []
        if "nx" in text_lower:
            protections.append("NX")
        if "pie" in text_lower:
            protections.append("PIE")
        if "canary" in text_lower:
            protections.append("Canary")
        if "relro" in text_lower:
            protections.append("RELRO")
        if "fortify" in text_lower:
            protections.append("Fortify")
        return ", ".join(protections) if protections else "None"

    def detect_key_functions(self, text):
        text_lower = text.lower()
        funcs = []
        for func in ["gets", "printf", "scanf", "malloc", "free", "system", "execve", "read", "fgets"]:
            if func in text_lower:
                funcs.append(func)
        return ", ".join(funcs) if funcs else "None"

    def get_key_technique(self, category, key_functions, text):
        sentences = re.split(r'(?<=[.!?])\s+', text)
        for s in sentences:
            s_clean = s.strip().replace('\n', ' ')
            if 20 < len(s_clean) < 150:
                s_lower = s_clean.lower()
                if any(w in s_lower for w in ["exploit", "vulnerability", "overflow", "bypass"]):
                    if any(w in s_lower for w in ["use", "using", "leak", "get", "overwrite", "run", "call", "solve"]):
                        return s_clean
        funcs_str = f" leveraging {', '.join(key_functions)}" if key_functions else ""
        return f"The writeup describes a {category} vulnerability{funcs_str} to hijack the control flow."

    def extract_page_content(self, soup, source):
        if source == 'ctftime':
            wells = soup.find_all('div', class_='well')
            valid_wells = [w for w in wells if not ("original writeup" in w.get_text().lower() and len(w.get_text().strip()) < 150)]
            if not valid_wells:
                valid_wells = wells
            if valid_wells:
                longest_well = max(valid_wells, key=lambda w: len(w.get_text()))
                return longest_well.get_text().strip()
            return ""
        else:
            content_el = soup.find('main') or soup.find('article') or soup.find('section') or soup.find('div', class_='page-inner') or soup.find('div', class_='book-body')
            if content_el:
                return content_el.get_text().strip()
            return soup.get_text().strip()


    def save_writeup(self, source, url, challenge, event, team, text):
        # Always mark URL as processed to prevent re-fetching rejected pages
        self.scraped_urls.add(url)
        self._save_scraped_urls()

        # Credential guard — never write files containing real-looking secrets
        if contains_credentials(text):
            quality_stats["rejected_credentials"] += 1
            print(f'[Scraper] Skipping writeup with detected credentials: {challenge}')
            return

        category = self.detect_category(text)
        difficulty = self.detect_difficulty(text)
        protections = self.detect_protections(text)
        key_functions = self.detect_key_functions(text)
        
        kf_list = [f.strip() for f in key_functions.split(",")] if key_functions != "None" else []
        key_technique = self.get_key_technique(category, kf_list, text)
        
        tags = extract_technique_tags(text)
        tags_str = ",".join(tags)

        # Get quality score for the metadata header
        _, quality_score, _ = calculate_writeup_quality(text)

        content = f"""---
SOURCE: {source}
URL: {url}
CHALLENGE: {challenge}
EVENT: {event}
TEAM: {team}
CATEGORY: {category}
DIFFICULTY: {difficulty}
PROTECTIONS: {protections}
KEY_FUNCTIONS: {key_functions}
KEY_TECHNIQUE: {key_technique}
TECHNIQUE_TAGS: {tags_str}
QUALITY_SCORE: {quality_score:.2f}
---
{text}"""

        import hashlib
        url_hash = hashlib.md5(url.encode('utf-8')).hexdigest()[:8]
        sanitized_title = self.sanitize_filename(challenge)
        filename = f"{source}_{sanitized_title}_{url_hash}.txt"

        # Normalize category to known list
        KNOWN_CATEGORIES = [
            "ret2win", "ret2libc", "format_string", "rop_chain",
            "heap_exploitation", "shellcode", "ret2plt", "got_overwrite",
            "ret2csu", "srop", "fastbin_dup", "tcache_poisoning",
            "use_after_free", "one_gadget", "canary_bypass", "pie_bypass",
            "off_by_one", "stack_pivot", "integer_overflow", "seccomp_bypass",
            "house_of_force", "house_of_spirit", "house_of_orange",
            "unsorted_bin_attack"
        ]

        category_clean = category.lower().strip() if category else 'others'
        if category_clean not in KNOWN_CATEGORIES:
            category_clean = 'others'

        if category_clean == 'others':
            # Require at least one STRONG pwn-specific signal.
            # Generic words like "binary" or "exploit" are NOT enough —
            # web/crypto writeups also use those words.
            text_lower = text.lower()
            has_strong_signal = any(
                sig.lower() in text_lower for sig in STRONG_PWN_SIGNALS
            )
            if has_strong_signal:
                # Reclassify with scorer — strong signal means it IS a pwn writeup
                rescored = detect_category_from_text(text)
                category_clean = rescored
                print(f'[Scraper] Reclassified to {category_clean} via strong signal')
            else:
                print(f'[Scraper] Skipping: no strong pwn signal found')
                return

        target_dir = os.path.join(self.walkthroughs_dir, category_clean)
        os.makedirs(target_dir, exist_ok=True)
        filepath = os.path.join(target_dir, filename)
        
        # 1. Credential check (already exists — verify it is still there)
        if contains_credentials(content):
            quality_stats["rejected_credentials"] += 1
            print(f'[Scraper] Skipping: credentials detected')
            return

        # 2. Quality check
        is_quality, quality_score, quality_reason = calculate_writeup_quality(content)
        if not is_quality:
            if "Too short" in quality_reason:
                quality_stats["rejected_short"] += 1
            else:
                quality_stats["rejected_quality"] += 1
            print(f'[Scraper] Skipping low quality: {quality_reason}')
            return

        # 3. Deduplication check
        if is_duplicate_content(content, self.walkthroughs_dir):
            quality_stats["rejected_duplicate"] += 1
            print(f'[Scraper] Skipping duplicate content')
            return

        if self._is_duplicate_content(text):
            quality_stats["rejected_duplicate"] += 1
            print(f"[Scraper] Duplicate content detected: {challenge}. Skipping.")
            return

        # 4. All checks passed — save the file
        quality_stats["accepted"] += 1
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
            
        print(f"Scraped: {filename}")
        self.saved_count += 1
        self.counts[category_clean] = self.counts.get(category_clean, 0) + 1
        self._cached_total = self.get_current_total() + 1

        global files_saved_this_run
        files_saved_this_run += 1
        if files_saved_this_run % 50 == 0:
            current_total = sum(get_current_category_counts(self.walkthroughs_dir).values())
            print(f"\n[Scraper] Progress: {current_total}/{MAX_TOTAL_WRITEUPS} total files")
            print_category_progress(get_current_category_counts(self.walkthroughs_dir))

    def scrape_github_repo(self, owner, repo, branch="master", path_filter=""):
        # Let's check if the repo is relevant to pwn/CTF
        repo_lower = repo.lower()
        if not any(kw in repo_lower for kw in ["pwn", "ctf", "exploit", "writeup", "note", "security", "cookbook", "college"]):
            print(f"Skipping unrelated repository: {owner}/{repo}")
            return

        if self.get_current_total() >= MAX_TOTAL_WRITEUPS:
            return

        print(f"\n[Scraper] Scraping GitHub repository: {owner}/{repo} (trying branch: {branch})...")
        url = f"https://api.github.com/repos/{owner}/{repo}/git/trees/{branch}?recursive=1"
        try:
            time.sleep(SLEEP_GITHUB)
            r = requests.get(url, headers=GITHUB_HEADERS, timeout=15)
            
            # Automatic fallback between master and main branches
            if r.status_code == 404 and branch == "master":
                print(f"Branch master not found, trying main...")
                time.sleep(SLEEP_GITHUB)
                branch = "main"
                url = f"https://api.github.com/repos/{owner}/{repo}/git/trees/{branch}?recursive=1"
                r = requests.get(url, headers=GITHUB_HEADERS, timeout=15)
            elif r.status_code == 404 and branch == "main":
                print(f"Branch main not found, trying master...")
                time.sleep(SLEEP_GITHUB)
                branch = "master"
                url = f"https://api.github.com/repos/{owner}/{repo}/git/trees/{branch}?recursive=1"
                r = requests.get(url, headers=GITHUB_HEADERS, timeout=15)
                
            if r.status_code != 200:
                print(f"Failed to fetch tree for {owner}/{repo}: status {r.status_code}")
                return
            tree_data = r.json()
            tree = tree_data.get("tree", [])
            
            candidates = []
            for item in tree:
                path = item.get("path", "")
                if item.get("type") == "blob" and (path.endswith(".md") or path.endswith(".txt")):
                    filename_lower = os.path.basename(path).lower()
                    if any(x in filename_lower for x in ["readme", "license", "summary", "changelog", "scoreboard", "flag", "solve", "points", "standing", "index.html"]):
                        continue
                    path_lower = "/" + path.lower().replace("\\", "/") + "/"
                    if any(x in path_lower for x in ["/forensics/", "/web/", "/crypto/", "/osint/", "/misc/", "/reverse/", "/rev/", "/hardware/"]):
                        continue
                    if path_filter and path_filter.lower() not in path.lower():
                        continue
                    candidates.append(path)
                    
            print(f"Found {len(candidates)} file candidates in {owner}/{repo}.")
            random.seed(42)
            random.shuffle(candidates)
            
            for path in candidates:
                if self.get_current_total() >= MAX_TOTAL_WRITEUPS:
                    print(f"[Scraper] Total cap reached: {self.get_current_total()}/{MAX_TOTAL_WRITEUPS}. Stopping.")
                    break
                
                raw_url = f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{path}"
                if raw_url in self.scraped_urls:
                    print(f"[Scraper] Already scraped: {raw_url}. Skipping.")
                    continue
                    
                current_counts = get_current_category_counts(self.walkthroughs_dir)
                pred_cat = self.predict_category_from_meta(os.path.basename(path), path)
                if pred_cat != "others" and not category_needs_more(pred_cat, current_counts):
                    continue
                    
                time.sleep(SLEEP_GITHUB)
                raw_r = requests.get(raw_url, headers=self.headers, timeout=10)
                if raw_r.status_code == 200:
                    self.scraped_urls.add(raw_url)
                    self._save_scraped_urls()
                    text = raw_r.text.strip()
                    if len(text) < 150:
                        continue
                    cat = self.detect_category(text)
                    if not category_needs_more(cat, current_counts):
                        continue
                        
                    challenge_name = os.path.splitext(os.path.basename(path))[0]
                    self.save_writeup(
                        source=f"github_{repo}",
                        url=raw_url,
                        challenge=challenge_name,
                        event=f"GitHub - {owner}/{repo}",
                        team="N/A",
                        text=text
                    )
        except Exception as e:
            print(f"Error scraping repo {owner}/{repo}: {e}")


_shared_scraper = None
def get_scraper():
    global _shared_scraper
    if _shared_scraper is None:
        _shared_scraper = WriteupScraper()
    return _shared_scraper

def reclassify_unknowns(walkthrough_dir: str):
    import os
    import shutil
    reclassified = 0
    
    KNOWN_CATEGORIES = [
        "ret2win", "ret2libc", "format_string", "rop_chain",
        "heap_exploitation", "shellcode", "ret2plt", "got_overwrite",
        "ret2csu", "srop", "fastbin_dup", "tcache_poisoning",
        "use_after_free", "one_gadget", "canary_bypass", "pie_bypass",
        "off_by_one", "stack_pivot", "integer_overflow", "seccomp_bypass",
        "house_of_force", "house_of_spirit", "house_of_orange",
        "unsorted_bin_attack", "unknown"
    ]
    
    for root, dirs, files in os.walk(walkthrough_dir):
        if root == walkthrough_dir:
            continue
        folder_name = os.path.basename(root).lower().strip()
        
        for fname in files:
            if not fname.endswith('.txt'):
                continue
            fpath = os.path.join(root, fname)
            try:
                with open(fpath, encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                has_non_standard_header = False
                header_cat = "unknown"
                for line in content.splitlines()[:15]:
                    if line.startswith("CATEGORY:"):
                        curr_cat = line.split(":", 1)[1].strip().lower()
                        if curr_cat not in KNOWN_CATEGORIES or curr_cat in ['others', 'other']:
                            has_non_standard_header = True
                            header_cat = curr_cat
                            break
                
                in_non_standard_folder = folder_name not in KNOWN_CATEGORIES
                
                if not (has_non_standard_header or in_non_standard_folder):
                    continue
                
                new_cat = detect_category_from_text(content)
                if new_cat not in KNOWN_CATEGORIES or new_cat in ['unknown', 'others', 'other']:
                    for line in content.splitlines()[:15]:
                        if line.startswith("CATEGORY:"):
                            parsed = line.split(":", 1)[1].strip().lower()
                            if parsed in KNOWN_CATEGORIES and parsed not in ['unknown', 'others', 'other']:
                                new_cat = parsed
                                break
                
                if new_cat not in KNOWN_CATEGORIES or new_cat in ['others', 'other']:
                    new_cat = 'unknown'
                
                updated_content = content
                for cat_to_replace in [header_cat, folder_name, 'others', 'other']:
                    updated_content = updated_content.replace(
                        f'CATEGORY: {cat_to_replace}',
                        f'CATEGORY: {new_cat}'
                    )
                    updated_content = updated_content.replace(
                        f'KEY_TECHNIQUE: The writeup describes a {cat_to_replace}',
                        f'KEY_TECHNIQUE: The writeup describes a {new_cat}'
                    )
                
                target_dir = os.path.join(walkthrough_dir, new_cat)
                os.makedirs(target_dir, exist_ok=True)
                target_path = os.path.join(target_dir, fname)
                
                with open(target_path, 'w', encoding='utf-8') as f:
                    f.write(updated_content)
                
                if os.path.abspath(fpath) != os.path.abspath(target_path):
                    os.remove(fpath)
                    
                reclassified += 1
                print(f"[Reclass] Moved {fname} from {folder_name} to {new_cat}")
            except Exception as e:
                print(f"[Reclass] Error on {fname}: {e}")
                
    for item in os.listdir(walkthrough_dir):
        item_path = os.path.join(walkthrough_dir, item)
        if os.path.isdir(item_path):
            folder_lower = item.lower().strip()
            if folder_lower not in KNOWN_CATEGORIES:
                try:
                    shutil.rmtree(item_path)
                    print(f"[Reclass] Removed legacy folder: {item_path}")
                except Exception as e:
                    print(f"[Reclass] Error removing folder {item_path}: {e}")
                    
    print(f"[Scraper] Reclassified {reclassified} files")
    return reclassified


def main():
    checkpoint = load_checkpoint()
    
    # Mark CTFtime as permanently exhausted — it returns empty pages
    checkpoint["ctftime_exhausted"] = True
    if "ctftime" not in checkpoint.get("sources_completed", []):
        checkpoint.setdefault("sources_completed", []).append("ctftime")
    save_checkpoint(checkpoint)
        
    current_counts = get_current_category_counts(WALKTHROUGH_DIR)
    total = sum(current_counts.values())
    
    print(f"[Scraper] Starting. Current total: {total}/{MAX_TOTAL_WRITEUPS}")
    print_category_progress(current_counts)
    
    outer_loop = 0
    
    while total < MAX_TOTAL_WRITEUPS:
        outer_loop += 1
        print(f"\n[Scraper] === Outer loop {outer_loop} (no cap — running until {MAX_TOTAL_WRITEUPS} reached) ===")
        print(f"[Scraper] Current total: {total}/{MAX_TOTAL_WRITEUPS}")
        
        # One-time sources - only run if not completed
        one_time_sources = {
            "how2heap": lambda: scrape_how2heap(),
            "ir0nstone": lambda: scrape_ir0nstone_extended(),
            "ctf_pwn_tips": lambda: scrape_ctf_pwn_tips(),
            "ropemporium": lambda: scrape_ropemporium(),
            "exploit_education": lambda: scrape_exploit_education(),
            "nobodyisnobody": lambda: scrape_nobodyisnobody(checkpoint),
            "pwnable_kr": lambda: scrape_pwnable_kr_writeups(),
            "pwnable_tw": lambda: scrape_pwnable_tw(),
        }
        
        for source_name, source_fn in one_time_sources.items():
            if source_name not in checkpoint.get("sources_completed", []):
                try:
                    source_fn()
                    checkpoint.setdefault("sources_completed", []).append(source_name)
                    save_checkpoint(checkpoint)
                except Exception as e:
                    print(f"[Scraper] {source_name} error: {e}")
        
        # High-volume sources - always retry until target reached
        scrape_github_search_bulk(checkpoint)
        scrape_ctf_writeup_repos(checkpoint)
        scrape_medium_ctf_writeups(checkpoint)
        scrape_by_category(checkpoint)
        scrape_github_topics(checkpoint)
        scrape_pwn_ctf_archives(checkpoint)
        
        # Reclassify unknowns after each loop
        reclassify_unknowns(WALKTHROUGH_DIR)
        
        current_counts = get_current_category_counts(WALKTHROUGH_DIR)
        total = sum(current_counts.values())
        print(f"\n[Scraper] After loop {outer_loop}: {total}/{MAX_TOTAL_WRITEUPS}")
        print_category_progress(current_counts)
        
        if total >= MAX_TOTAL_WRITEUPS:
            print("[Scraper] Target reached!")
            break
        
        remaining = MAX_TOTAL_WRITEUPS - total
        print(f"[Scraper] Still need {remaining} more writeups. Continuing...")
        time.sleep(2)
    
    print(f"\n[Scraper] FINAL TOTAL: {sum(get_current_category_counts(WALKTHROUGH_DIR).values())}")
    print_category_progress(get_current_category_counts(WALKTHROUGH_DIR))


if __name__ == "__main__":
    main()
