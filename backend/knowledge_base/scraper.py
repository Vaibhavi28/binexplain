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

SLEEP_GITHUB = 0.1   # 5000 req/hour with token, safe at 0.1s
SLEEP_WEB    = 0.3   # Regular websites, no API — be polite

try:
    from knowledge_base.technique_tags import extract_technique_tags
except ImportError:
    try:
        from technique_tags import extract_technique_tags
    except ImportError:
        from backend.knowledge_base.technique_tags import extract_technique_tags

# Reconfigure stdout to use UTF-8 on Windows to prevent encoding errors when printing to console
sys.stdout.reconfigure(encoding='utf-8')

import re as _re

def contains_credentials(text: str) -> bool:
    patterns = [
        r'AKIA[0-9A-Z]{16}',
        r'aws_secret_access_key\s*=\s*[A-Za-z0-9/+=]{40}',
        r'(?i)secret[_-]?access[_-]?key["\']?\s*[:=]\s*["\']?[A-Za-z0-9/+=]{20,}',
        r'(?i)aws_session_token\s*=\s*[A-Za-z0-9/+=]{100,}',
    ]
    return any(_re.search(p, text) for p in patterns)

quality_stats = {
    "accepted": 0,
    "rejected_quality": 0,
    "rejected_duplicate": 0,
    "rejected_credentials": 0,
    "rejected_short": 0,
}

def calculate_writeup_quality(content: str) -> tuple:
    word_count = len(content.split())
    if word_count < 150:
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
    MINIMUM_SCORE = 0.20
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

CATEGORY_TARGETS = {
    "ret2win":            300,
    "ret2libc":           300,
    "format_string":      250,
    "rop_chain":          400,
    "heap_exploitation":  600,
    "shellcode":          150,
    "ret2plt":            200,
    "got_overwrite":      200,
    "ret2csu":            150,
    "srop":               100,
    "fastbin_dup":        150,
    "tcache_poisoning":   200,
    "use_after_free":     200,
    "one_gadget":         150,
    "canary_bypass":      100,
    "pie_bypass":         150,
    "off_by_one":         150,
    "stack_pivot":        100,
    "integer_overflow":   100,
    "seccomp_bypass":      80,
    "house_of_force":      80,
    "house_of_spirit":     80,
    "house_of_orange":     80,
    "unsorted_bin_attack": 80,
    "unknown":            300,
}

MAX_TOTAL_WRITEUPS = 5200

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
        t = text.lower()

        # Heap subcategories — check before generic heap
        if "tcache poison" in t or "tcache dup" in t or "tcache attack" in t:
            return "tcache_poisoning"
        if "fastbin dup" in t or "fastbin duplicate" in t or "fast bin attack" in t:
            return "fastbin_dup"
        if "house of force" in t or "top chunk overflow" in t:
            return "house_of_force"
        if "house of spirit" in t or "fake chunk" in t:
            return "house_of_spirit"
        if "house of orange" in t:
            return "house_of_orange"
        if "unsorted bin attack" in t or "unsortedbin attack" in t:
            return "unsorted_bin_attack"
        if "use after free" in t or "use-after-free" in t or " uaf " in t:
            return "use_after_free"
        if "double free" in t or "double-free" in t:
            return "use_after_free"

        # Stack techniques — specific before generic
        if "ret2plt" in t or "return to plt" in t or "plt stub" in t:
            return "ret2plt"
        if "got overwrite" in t or "got hijack" in t or "global offset table" in t:
            return "got_overwrite"
        if "ret2csu" in t or "__libc_csu_init" in t or "csu gadget" in t:
            return "ret2csu"
        if "sigreturn" in t or "srop" in t or "sigframe" in t:
            return "srop"
        if "stack pivot" in t or "stack migration" in t or "leave ret" in t:
            return "stack_pivot"
        if "one_gadget" in t or "one gadget" in t or "magic gadget" in t:
            return "one_gadget"
        if "canary bypass" in t or "canary leak" in t or "stack cookie" in t:
            return "canary_bypass"
        if "pie bypass" in t or "pie leak" in t or "pie base" in t or "aslr bypass" in t:
            return "pie_bypass"
        if "off by one" in t or "off-by-one" in t or "null byte overflow" in t:
            return "off_by_one"
        if "integer overflow" in t or "signed unsigned" in t or "int overflow" in t:
            return "integer_overflow"
        if "seccomp" in t or "syscall filter" in t or "sandbox bypass" in t:
            return "seccomp_bypass"

        # Generic categories last
        if "ret2win" in t or "win function" in t or "flag function" in t:
            return "ret2win"
        if "ret2libc" in t or ("system(" in t and "overflow" in t) or ("/bin/sh" in t and "overflow" in t):
            return "ret2libc"
        if "format string" in t or "%p" in t or "%n" in t or "printf exploit" in t:
            return "format_string"
        if "heap" in t or "tcache" in t or "malloc" in t or "free(" in t or "chunk" in t:
            return "heap_exploitation"
        if "rop" in t or "rop chain" in t or "gadget" in t or "ropgadget" in t:
            return "rop_chain"
        if "shellcode" in t or "msfvenom" in t or "shellcraft" in t:
            return "shellcode"

        return "others"

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
            print(f'[Scraper] Skipping: not related to defined categories')
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
            r = requests.get(url, headers=self.headers, timeout=15)
            
            # Automatic fallback between master and main branches
            if r.status_code == 404 and branch == "master":
                print(f"Branch master not found, trying main...")
                time.sleep(SLEEP_GITHUB)
                branch = "main"
                url = f"https://api.github.com/repos/{owner}/{repo}/git/trees/{branch}?recursive=1"
                r = requests.get(url, headers=self.headers, timeout=15)
            elif r.status_code == 404 and branch == "main":
                print(f"Branch main not found, trying master...")
                time.sleep(SLEEP_GITHUB)
                branch = "master"
                url = f"https://api.github.com/repos/{owner}/{repo}/git/trees/{branch}?recursive=1"
                r = requests.get(url, headers=self.headers, timeout=15)
                
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

    def scrape_hacktricks(self):
        if self.get_current_total() >= MAX_TOTAL_WRITEUPS:
            return

        print("\n[Scraper] Scraping HackTricks...")
        main_url = "https://book.hacktricks.xyz/reversing-and-exploiting/linux-exploiting-basic-esp/"
        try:
            time.sleep(SLEEP_WEB)
            r = requests.get(main_url, headers=self.headers, timeout=15)
            if r.status_code != 200:
                print(f"Failed to fetch HackTricks index: status {r.status_code}")
                return
            soup = BeautifulSoup(r.text, 'lxml')
            links = []
            for a in soup.find_all('a', href=True):
                href = a['href']
                if "/reversing-and-exploiting/linux-exploiting-basic-esp/" in href or "/exploiting-tools/" in href:
                    full_url = urllib.parse.urljoin(main_url, href)
                    if full_url not in links:
                        links.append(full_url)
                        
            print(f"Found {len(links)} HackTricks sub-links. Scraping them...")
            for url in links:
                if url in self.scraped_urls:
                    print(f"[Scraper] Already scraped: {url}. Skipping.")
                    continue
                    
                if self.get_current_total() >= MAX_TOTAL_WRITEUPS:
                    print(f"[Scraper] Total cap reached: {self.get_current_total()}/{MAX_TOTAL_WRITEUPS}. Stopping.")
                    break
                    
                current_counts = get_current_category_counts(self.walkthroughs_dir)
                pred_cat = self.predict_category_from_meta("", url)
                if pred_cat != "others" and not category_needs_more(pred_cat, current_counts):
                    continue
                    
                time.sleep(SLEEP_WEB)
                res = requests.get(url, headers=self.headers, timeout=10)
                if res.status_code == 200:
                    sub_soup = BeautifulSoup(res.text, 'lxml')
                    text = self.extract_page_content(sub_soup, 'hacktricks')
                    if len(text.split()) < 150:
                        continue
                    cat = self.detect_category(text)
                    if not category_needs_more(cat, current_counts):
                        continue
                        
                    challenge_name = url.rstrip('/').split('/')[-1].replace('-', '_')
                    self.save_writeup(
                        source="hacktricks",
                        url=url,
                        challenge=challenge_name,
                        event="HackTricks",
                        team="N/A",
                        text=text
                    )
        except Exception as e:
            print(f"Error scraping HackTricks: {e}")

    def scrape_github_search(self):
        if self.get_current_total() >= MAX_TOTAL_WRITEUPS:
            return

        print("\n[Scraper] Searching GitHub for ctf-writeups and pwn-writeups...")
        queries = ["ctf-writeups", "pwn-writeups", "ctf-pwn", "pwn-writeup", "binary-exploitation-writeups", "heap-exploitation-writeups", "how2heap", "pwnable-writeups", "pwnable-kr", "pwnable-tw", "protostar-writeups", "exploit-education", "buffer-overflow-writeups"]
        for q in queries:
            if self.get_current_total() >= MAX_TOTAL_WRITEUPS:
                print(f"[Scraper] Total cap reached. Stopping.")
                break
            search_url = f"https://api.github.com/search/repositories?q={q}+stars:%3E=5&sort=stars&order=desc"
            try:
                time.sleep(SLEEP_GITHUB)
                r = requests.get(search_url, headers=self.headers, timeout=15)
                if r.status_code != 200:
                    print(f"GitHub search failed: {r.status_code}")
                    continue
                repos = r.json().get("items", [])[:25]
                for repo_item in repos:
                    owner = repo_item["owner"]["login"]
                    repo_name = repo_item["name"]
                    branch = repo_item.get("default_branch", "master")
                    self.scrape_github_repo(owner, repo_name, branch)
            except Exception as e:
                print(f"Error searching GitHub for {q}: {e}")

    def scrape_how2heap(self):
        print("\n[Scraper] Scraping how2heap...")
        api_url = "https://api.github.com/repos/shellphish/how2heap/contents/"
        try:
            time.sleep(SLEEP_GITHUB)
            r = requests.get(api_url, headers=self.headers, timeout=15)
            if r.status_code != 200:
                print(f"Failed to list how2heap contents: {r.status_code}")
                return
            items = r.json()
            c_files = [item["name"] for item in items if item["name"].endswith(".c")]
            print(f"Found {len(c_files)} how2heap .c files. Scraping them...")
            for fname in c_files:
                challenge_name = fname.replace(".c", "")
                raw_url = f"https://raw.githubusercontent.com/shellphish/how2heap/master/{fname}"
                
                if raw_url in self.scraped_urls:
                    print(f"[Scraper] Already scraped: {raw_url}. Skipping.")
                    continue

                time.sleep(SLEEP_GITHUB)
                raw_r = requests.get(raw_url, headers=self.headers, timeout=10)
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
                        
                    self.save_writeup(
                        source="how2heap",
                        url=raw_url,
                        challenge=challenge_name,
                        event="how2heap",
                        team="N/A",
                        text=comment_content
                    )
        except Exception as e:
            print(f"Error scraping how2heap: {e}")

    def scrape_ctf_pwn_tips(self):
        print("\n[Scraper] Scraping CTF-pwn-tips...")
        readme_url = "https://raw.githubusercontent.com/Naetw/CTF-pwn-tips/master/README.md"
        try:
            time.sleep(SLEEP_WEB)
            r = requests.get(readme_url, headers=self.headers, timeout=10)
            if r.status_code != 200:
                print(f"Failed to fetch CTF-pwn-tips README: {r.status_code}")
                return
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
                    
                    self.save_writeup(
                        source="ctf_pwn_tips",
                        url=url,
                        challenge=challenge_name,
                        event="CTF-pwn-tips",
                        team="N/A",
                        text=sec_text
                    )
        except Exception as e:
            print(f"Error scraping ctf_pwn_tips: {e}")

    def scrape_nobodyisnobody(self):
        print("\n[Scraper] Scraping nobodyisnobody...")
        base_url = "https://nobodyisnobody.github.io"
        try:
            time.sleep(SLEEP_WEB)
            r = requests.get(base_url, headers=self.headers, timeout=15)
            if r.status_code != 200:
                print(f"Failed to fetch nobodyisnobody main page: {r.status_code}")
                return
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
                if url in self.scraped_urls:
                    print(f"[Scraper] Already scraped: {url}. Skipping.")
                    continue

                time.sleep(SLEEP_WEB)
                res = requests.get(url, headers=self.headers, timeout=10)
                if res.status_code == 200:
                    sub_soup = BeautifulSoup(res.text, 'lxml')
                    title_el = sub_soup.find('h1') or sub_soup.find('title')
                    challenge_name = title_el.text.strip() if title_el else url.rstrip('/').split('/')[-1]
                    challenge_name = challenge_name.replace("nobodyisnobody", "").strip()
                    
                    text = self.extract_page_content(sub_soup, 'nobodyisnobody')
                    if len(text.split()) < 150:
                        continue
                    
                    self.save_writeup(
                        source="nobodyisnobody",
                        url=url,
                        challenge=challenge_name,
                        event="nobodyisnobody Blog",
                        team="N/A",
                        text=text
                    )
        except Exception as e:
            print(f"Error scraping nobodyisnobody: {e}")

    def scrape_ir0nstone_extended(self):
        print("\n[Scraper] Scraping ir0nstone_extended...")
        target_urls = [
            "https://ir0nstone.gitbook.io/notes/types/stack/return-oriented-programming/ret2csu",
            "https://ir0nstone.gitbook.io/notes/types/stack/return-oriented-programming/srop",
            "https://ir0nstone.gitbook.io/notes/types/heap/use-after-free",
            "https://ir0nstone.gitbook.io/notes/types/heap/tcache-poisoning",
            "https://ir0nstone.gitbook.io/notes/types/heap/fastbin-dup",
            "https://ir0nstone.gitbook.io/notes/types/stack/got-overwrite",
        ]
        for url in target_urls:
            challenge_name = url.rstrip('/').split('/')[-1]
            if url in self.scraped_urls:
                print(f"[Scraper] Already scraped: {url}. Skipping.")
                continue

            try:
                time.sleep(SLEEP_WEB)
                res = requests.get(url, headers=self.headers, timeout=10)
                if res.status_code == 200:
                    soup = BeautifulSoup(res.text, 'lxml')
                    text = self.extract_page_content(soup, 'ironstone')
                    if len(text.split()) < 150:
                        continue
                    
                    self.save_writeup(
                        source="ir0nstone",
                        url=url,
                        challenge=challenge_name.replace('-', ' ').title(),
                        event="ir0nstone's GitBook",
                        team="N/A",
                        text=text
                    )
            except Exception as e:
                print(f"Error scraping ir0nstone page {url}: {e}")

    def run(self):
        print("STEP A: Creating walkthroughs directory...")
        os.makedirs(self.walkthroughs_dir, exist_ok=True)

        current_counts = get_current_category_counts(self.walkthroughs_dir)
        print_category_progress(current_counts)

        # ── 1. scrape_how2heap ─────────────────────────────────────────
        if self.get_current_total() < MAX_TOTAL_WRITEUPS:
            self.scrape_how2heap()
            current_counts = get_current_category_counts(self.walkthroughs_dir)

        # ── 2. scrape_ctf_pwn_tips ─────────────────────────────────────
        if self.get_current_total() < MAX_TOTAL_WRITEUPS:
            self.scrape_ctf_pwn_tips()
            current_counts = get_current_category_counts(self.walkthroughs_dir)

        # ── 3. scrape_nobodyisnobody ───────────────────────────────────
        if self.get_current_total() < MAX_TOTAL_WRITEUPS:
            self.scrape_nobodyisnobody()
            current_counts = get_current_category_counts(self.walkthroughs_dir)

        # ── 4. scrape_ir0nstone_extended ───────────────────────────────
        if self.get_current_total() < MAX_TOTAL_WRITEUPS:
            self.scrape_ir0nstone_extended()
            current_counts = get_current_category_counts(self.walkthroughs_dir)

        # ── 5. CTFtime.org writeups ────────────────────────────────────
        if self.get_current_total() < MAX_TOTAL_WRITEUPS:
            print("\nSTEP B: Scraping CTFtime.org...")
            ctftime_links = []
            page = 1
            while len(ctftime_links) < 40 and page <= 5:
                url = f"https://ctftime.org/writeups?page={page}"
                try:
                    time.sleep(SLEEP_WEB)
                    r = requests.get(url, headers=self.headers, timeout=10)
                    if r.status_code == 200:
                        soup = BeautifulSoup(r.text, 'lxml')
                        for a in soup.find_all('a', href=True):
                            href = a['href']
                            if '/writeup/' in href:
                                full_url = urllib.parse.urljoin("https://ctftime.org", href)
                                if full_url not in ctftime_links:
                                    ctftime_links.append(full_url)
                    else:
                        print(f"Failed to fetch CTFtime writeups list: status {r.status_code}")
                except Exception as e:
                    print(f"Error fetching CTFtime list page {page}: {e}")
                page += 1

            print(f"Found {len(ctftime_links)} writeup links. Scraping them...")
            for url in ctftime_links:
                if url in self.scraped_urls:
                    print(f"[Scraper] Already scraped: {url}. Skipping.")
                    continue

                if self.get_current_total() >= MAX_TOTAL_WRITEUPS:
                    print(f'[Scraper] Reached maximum {MAX_TOTAL_WRITEUPS} writeups. Stopping.')
                    break

                pred_cat = self.predict_category_from_meta("", url)
                if pred_cat != "others" and not category_needs_more(pred_cat, current_counts):
                    continue

                try:
                    time.sleep(SLEEP_WEB)
                    r = requests.get(url, headers=self.headers, timeout=10)
                    if r.status_code == 200:
                        soup = BeautifulSoup(r.text, 'lxml')
                        parts = [p.strip() for p in soup.title.text.split('/')]
                        if len(parts) >= 3:
                            event_name = parts[1]
                            challenge_name = parts[2]
                        else:
                            h2 = soup.find('h2')
                            challenge_name = h2.text.strip() if h2 else "Unknown Challenge"
                            event_name = "Unknown Event"

                        team_name = "Unknown Team"
                        for a in soup.find_all('a', href=True):
                            if '/team/' in a['href']:
                                team_name = a.text.strip()
                                break
                                
                        writeup_text = self.extract_page_content(soup, 'ctftime')
                        if not writeup_text:
                            continue
                            
                        keywords = ["overflow", "format string", "heap", "ROP", "shellcode", "pwntools", "pwn", "binary", "exploit", "gets(", "printf(", "malloc(", "free("]
                        if any(kw in writeup_text for kw in keywords):
                            cat = self.detect_category(writeup_text)
                            if not category_needs_more(cat, current_counts):
                                continue
                            self.save_writeup(
                                source="ctftime",
                                url=url,
                                challenge=challenge_name,
                                event=event_name,
                                team=team_name,
                                text=writeup_text
                            )
                            # Normalize category for counts dictionary key
                            cat_clean = cat if cat in current_counts else 'others'
                            current_counts[cat_clean] = current_counts.get(cat_clean, 0) + 1
                except Exception as e:
                    print(f"Error scraping CTFtime writeup at {url}: {e}")

        # ── 6. CTF-Wiki ───────────────────────────────────────────────
        if self.get_current_total() < MAX_TOTAL_WRITEUPS:
            print("\nSTEP C: Scraping CTF-Wiki...")
            ctfwiki_targets = [
                {"url": "https://ctf-wiki.org/pwn/linux/user-mode/stackoverflow/x86-64/basic-rop/", "fallback": "https://ctf-wiki.org/pwn/linux/user-mode/stackoverflow/x86/basic-rop/", "topic": "basic_rop"},
                {"url": "https://ctf-wiki.org/pwn/linux/user-mode/stackoverflow/x86-64/ret2libc/", "fallback": "https://ctf-wiki.org/pwn/linux/user-mode/stackoverflow/x86/basic-rop/", "topic": "ret2libc"},
                {"url": "https://ctf-wiki.org/pwn/linux/user-mode/format-string/exploit-printf/", "fallback": "https://ctf-wiki.org/pwn/linux/user-mode/fmtstr/fmtstr-exploit/", "topic": "exploit_printf"},
                {"url": "https://ctf-wiki.org/pwn/linux/user-mode/heap/ptmalloc2/use-after-free/", "fallback": "https://ctf-wiki.org/pwn/linux/user-mode/heap/ptmalloc2/use-after-free/", "topic": "use_after_free"}
            ]
            for target in ctfwiki_targets:
                pred_cat = self.predict_category_from_meta(target["topic"], target["url"])
                if pred_cat != "others" and not category_needs_more(pred_cat, current_counts):
                    continue

                try:
                    time.sleep(SLEEP_WEB)
                    r = requests.get(target["url"], headers=self.headers, timeout=10)
                    active_url = target["url"]
                    if r.status_code != 200 and target["fallback"]:
                        time.sleep(SLEEP_WEB)
                        r = requests.get(target["fallback"], headers=self.headers, timeout=10)
                        active_url = target["fallback"]
                        
                    if r.status_code == 200:
                        soup = BeautifulSoup(r.text, 'lxml')
                        text = self.extract_page_content(soup, 'ctfwiki')
                        cat = self.detect_category(text)
                        if not category_needs_more(cat, current_counts):
                            continue
                        self.save_writeup(
                            source="ctfwiki",
                            url=active_url,
                            challenge=target["topic"].replace('_', ' ').title(),
                            event="Overlay/Wiki",
                            team="N/A",
                            text=text
                        )
                        cat_clean = cat if cat in current_counts else 'others'
                        current_counts[cat_clean] = current_counts.get(cat_clean, 0) + 1
                except Exception as e:
                    print(f"Error scraping CTF-Wiki for {target['topic']}: {e}")

        # ── 7. ir0nstone's GitBook ────────────────────────────────────
        total = get_total_writeup_count(self.walkthroughs_dir)
        if total < MAX_TOTAL_WRITEUPS:
            print("\nSTEP D: Scraping ir0nstone's GitBook...")
            ironstone_targets = [
                {"url": "https://ir0nstone.gitbook.io/notes/types/stack/return-oriented-programming", "fallback": "https://ir0nstone.gitbook.io/notes/binexp/stack/return-oriented-programming", "topic": "return_oriented_programming"},
                {"url": "https://ir0nstone.gitbook.io/notes/types/stack/ret2libc", "fallback": "https://ir0nstone.gitbook.io/notes/binexp/stack/return-oriented-programming/ret2libc", "topic": "ret2libc"},
                {"url": "https://ir0nstone.gitbook.io/notes/types/stack/format-string-exploits", "fallback": "https://ir0nstone.gitbook.io/notes/binexp/stack/format-string", "topic": "format_string_exploits"},
                {"url": "https://ir0nstone.gitbook.io/notes/types/heap/use-after-free", "fallback": "https://ir0nstone.gitbook.io/notes/binexp/heap/use-after-free", "topic": "use_after_free"}
            ]
            for target in ironstone_targets:
                pred_cat = self.predict_category_from_meta(target["topic"], target["url"])
                if pred_cat != "others" and not category_needs_more(pred_cat, current_counts):
                    continue

                try:
                    time.sleep(SLEEP_WEB)
                    r = requests.get(target["url"], headers=self.headers, timeout=10)
                    active_url = target["url"]
                    if r.status_code != 200 and target["fallback"]:
                        time.sleep(SLEEP_WEB)
                        r = requests.get(target["fallback"], headers=self.headers, timeout=10)
                        active_url = target["fallback"]
                        
                    if r.status_code == 200:
                        soup = BeautifulSoup(r.text, 'lxml')
                        text = self.extract_page_content(soup, 'ironstone')
                        cat = self.detect_category(text)
                        if not category_needs_more(cat, current_counts):
                            continue
                        self.save_writeup(
                            source="ironstone",
                            url=active_url,
                            challenge=target["topic"].replace('_', ' ').title(),
                            event="ir0nstone's GitBook",
                            team="N/A",
                            text=text
                        )
                        cat_clean = cat if cat in current_counts else 'others'
                        current_counts[cat_clean] = current_counts.get(cat_clean, 0) + 1
                except Exception as e:
                    print(f"Error scraping ir0nstone GitBook for {target['topic']}: {e}")

        # ── 8. guyinatuxedo (nightmare) ───────────────────────────────
        if self.get_current_total() < MAX_TOTAL_WRITEUPS:
            print("\nSTEP E: Scraping guyinatuxedo (nightmare)...")
            try:
                base_url = "https://guyinatuxedo.github.io/"
                time.sleep(SLEEP_WEB)
                r = requests.get(base_url, headers=self.headers, timeout=10)
                if r.status_code == 200:
                    soup = BeautifulSoup(r.text, 'lxml')
                    nightmare_links = []
                    for a in soup.find_all('a', href=True):
                        href = a['href']
                        if re.match(r'^\d{2}-[^/]+/[^/]+/index\.html$', href):
                            if not any(x in href for x in ['intro_assembly', 'intro_tooling']):
                                full_url = urllib.parse.urljoin(base_url, href)
                                if full_url not in nightmare_links:
                                    nightmare_links.append(full_url)
                                    
                    print(f"Found {len(nightmare_links)} guyinatuxedo challenge links. Scraping them...")
                    for url in nightmare_links:
                        if url in self.scraped_urls:
                            print(f"[Scraper] Already scraped: {url}. Skipping.")
                            continue

                        if self.get_current_total() >= MAX_TOTAL_WRITEUPS:
                            print(f"[Scraper] Total cap reached: {self.get_current_total()}/{MAX_TOTAL_WRITEUPS}. Stopping.")
                            break
                        pred_cat = self.predict_category_from_meta("", url)
                        if pred_cat != "others" and not category_needs_more(pred_cat, current_counts):
                            continue

                        try:
                            time.sleep(SLEEP_WEB)
                            res = requests.get(url, headers=self.headers, timeout=10)
                            if res.status_code == 200:
                                sub_soup = BeautifulSoup(res.text, 'lxml')
                                url_parts = url.rstrip('/').split('/')
                                challenge_name = url_parts[-2] if len(url_parts) >= 2 else "Unknown"
                                
                                text = self.extract_page_content(sub_soup, 'nightmare')
                                cat = self.detect_category(text)
                                if not category_needs_more(cat, current_counts):
                                    continue
                                self.save_writeup(
                                    source="nightmare",
                                    url=url,
                                    challenge=challenge_name,
                                    event="Nightmare",
                                    team="N/A",
                                    text=text
                                )
                                cat_clean = cat if cat in current_counts else 'others'
                                current_counts[cat_clean] = current_counts.get(cat_clean, 0) + 1
                        except Exception as e:
                            print(f"Error scraping guyinatuxedo page {url}: {e}")
            except Exception as e:
                print(f"Error scraping guyinatuxedo: {e}")

        # ── 9. pwn.college writeups ───────────────────────────────────
        if self.get_current_total() < MAX_TOTAL_WRITEUPS:
            self.scrape_github_repo("w181496", "pwn.college-writeups")
            current_counts = get_current_category_counts(self.walkthroughs_dir)

        if self.get_current_total() < MAX_TOTAL_WRITEUPS:
            self.scrape_github_repo("AidenHils", "pwn-college")
            current_counts = get_current_category_counts(self.walkthroughs_dir)

        if self.get_current_total() < MAX_TOTAL_WRITEUPS:
            self.scrape_github_repo("xct", "pwn.college")
            current_counts = get_current_category_counts(self.walkthroughs_dir)

        # ── 10. LiveOverflow repositories ──────────────────────────────
        if self.get_current_total() < MAX_TOTAL_WRITEUPS:
            self.scrape_github_repo("LiveOverflow", "LiveOverflow-CTF")
            current_counts = get_current_category_counts(self.walkthroughs_dir)

        if self.get_current_total() < MAX_TOTAL_WRITEUPS:
            self.scrape_github_repo("liveoverflow", "lo-exploit-dev")
            current_counts = get_current_category_counts(self.walkthroughs_dir)

        # ── 11. HackTricks ─────────────────────────────────────────────
        if self.get_current_total() < MAX_TOTAL_WRITEUPS:
            self.scrape_hacktricks()
            current_counts = get_current_category_counts(self.walkthroughs_dir)

        # ── 12. other specific high quality repositories ───────────────
        if self.get_current_total() < MAX_TOTAL_WRITEUPS:
            self.scrape_github_repo("ctfs", "writeups")
            current_counts = get_current_category_counts(self.walkthroughs_dir)

        if self.get_current_total() < MAX_TOTAL_WRITEUPS:
            self.scrape_github_repo("Dvd848", "CTFs")
            current_counts = get_current_category_counts(self.walkthroughs_dir)

        if self.get_current_total() < MAX_TOTAL_WRITEUPS:
            self.scrape_github_repo("M4x", "ctf-writeups")
            current_counts = get_current_category_counts(self.walkthroughs_dir)

        if self.get_current_total() < MAX_TOTAL_WRITEUPS:
            self.scrape_github_repo("ir0nstone", "ir0nstone.github.io")
            current_counts = get_current_category_counts(self.walkthroughs_dir)

        # ── 13. GitHub Code Search ─────────────────────────────────────
        if self.get_current_total() < MAX_TOTAL_WRITEUPS:
            self.scrape_github_search()
            current_counts = get_current_category_counts(self.walkthroughs_dir)

        final_counts = get_current_category_counts(self.walkthroughs_dir)
        print_category_progress(final_counts)

        print(f'\n[Scraper] Quality Filter Summary:')
        print(f'  Accepted:            {quality_stats["accepted"]}')
        print(f'  Rejected (quality):  {quality_stats["rejected_quality"]}')
        print(f'  Rejected (dupe):     {quality_stats["rejected_duplicate"]}')
        print(f'  Rejected (creds):    {quality_stats["rejected_credentials"]}')
        acceptance_rate = (quality_stats["accepted"] /
            max(1, sum(quality_stats.values())) * 100)
        print(f'  Acceptance Rate:     {acceptance_rate:.1f}%')


if __name__ == "__main__":
    scraper = WriteupScraper()
    scraper.run()
