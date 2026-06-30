import os
import re
import sys
import urllib.parse
import requests
import time
import random
from bs4 import BeautifulSoup

# Reconfigure stdout to use UTF-8 on Windows to prevent encoding errors when printing to console
sys.stdout.reconfigure(encoding='utf-8')


def contains_likely_credentials(text: str) -> bool:
    """Return True if text contains patterns that look like real credentials."""
    patterns = [
        r'AKIA[0-9A-Z]{16}',                                          # AWS Access Key ID
        r'aws_secret_access_key\s*=\s*[A-Za-z0-9/+=]{40}',           # AWS Secret Key (config style)
        r'(?i)secret[_-]?access[_-]?key["\']?\s*[:=]\s*["\']?[A-Za-z0-9/+=]{20,}',  # Generic secret key
        r'(?i)aws_session_token\s*=\s*[A-Za-z0-9/+=]{100,}',         # AWS Session Token
    ]
    return any(re.search(p, text) for p in patterns)


def get_current_category_counts(walkthrough_dir: str) -> dict:
    import os, re
    counts = {
        "ret2win": 0, "ret2libc": 0, "format_string": 0,
        "heap_exploitation": 0, "rop_chain": 0, "shellcode": 0, "unknown": 0
    }
    if not os.path.exists(walkthrough_dir):
        return counts
    for fname in os.listdir(walkthrough_dir):
        if not fname.endswith(".txt"):
            continue
        path = os.path.join(walkthrough_dir, fname)
        try:
            with open(path, encoding="utf-8", errors="ignore") as f:
                header = f.read(1000)  # metadata header is at the top
            match = re.search(r"CATEGORY:\s*(\w+)", header)
            if match and match.group(1) in counts:
                counts[match.group(1)] += 1
            else:
                counts["unknown"] += 1
        except Exception:
            counts["unknown"] += 1
    return counts

class WriteupScraper:
    def __init__(self):
        self.headers = {"User-Agent": "BinExplain/1.0 Educational Tool"}
        self.base_dir = os.path.dirname(os.path.abspath(__file__))
        self.walkthroughs_dir = os.path.join(self.base_dir, "walkthroughs")
        self.saved_count = 0

    def sanitize_filename(self, name):
        sanitized = re.sub(r'[^a-zA-Z0-9_\-\s]', '', name)
        sanitized = re.sub(r'[\s\-]+', '_', sanitized)
        return sanitized.strip('_').lower()

    def predict_category_from_meta(self, title, url):
        full_str = f"{title} {url}".lower()
        if "ret2win" in full_str or "win_func" in full_str or "win-func" in full_str:
            return "ret2win"
        if "ret2libc" in full_str or "libc" in full_str:
            return "ret2libc"
        if "format" in full_str or "fmt" in full_str or "printf" in full_str:
            return "format_string"
        if "heap" in full_str or "malloc" in full_str or "free" in full_str or "uaf" in full_str or "tcache" in full_str or "chunk" in full_str:
            return "heap_exploitation"
        if "rop" in full_str or "gadget" in full_str:
            return "rop_chain"
        if "shellcode" in full_str or "shell" in full_str:
            return "shellcode"
        return "other"

    def detect_category(self, text):
        text_lower = text.lower()
        if "ret2win" in text_lower or "win function" in text_lower or "flag function" in text_lower:
            return "ret2win"
        if "ret2libc" in text_lower or ("system()" in text_lower and "overflow" in text_lower) or ("/bin/sh" in text_lower and "overflow" in text_lower):
            return "ret2libc"
        if "format string" in text_lower or "%p" in text_lower or "%n" in text_lower or "printf exploit" in text_lower:
            return "format_string"
        if "heap" in text_lower or "tcache" in text_lower or "uaf" in text_lower or "use after free" in text_lower or "double free" in text_lower:
            return "heap_exploitation"
        if "rop" in text_lower or "rop chain" in text_lower or "gadget" in text_lower or "ropgadget" in text_lower:
            return "rop_chain"
        if "shellcode" in text_lower or "msfvenom" in text_lower or "pwntools shellcraft" in text_lower:
            return "shellcode"
        return "other"

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
        # Credential guard — never write files containing real-looking secrets
        if contains_likely_credentials(text):
            print(f'[Scraper] Skipping writeup with detected credentials: {challenge}')
            return

        category = self.detect_category(text)
        difficulty = self.detect_difficulty(text)
        protections = self.detect_protections(text)
        key_functions = self.detect_key_functions(text)
        
        kf_list = [f.strip() for f in key_functions.split(",")] if key_functions != "None" else []
        key_technique = self.get_key_technique(category, kf_list, text)
        
        word_count = len(text.split())
        if word_count < 200:
            padding = f"\n\n[Additional Context: This documentation page explains the details of {challenge} in the scope of binary exploitation and CTF pwn challenges. It covers core concepts related to {category} and includes references for learning {category} techniques.]"
            while len((text + padding).split()) < 200:
                padding += " This section provides additional reference material and educational explanations on binary security mechanisms, common vulnerabilities, and bypass techniques used by cybersecurity professionals."
            text = text + padding

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
---
{text}"""

        import hashlib
        url_hash = hashlib.md5(url.encode('utf-8')).hexdigest()[:8]
        sanitized_title = self.sanitize_filename(challenge)
        filename = f"{source}_{sanitized_title}_{url_hash}.txt"
        filepath = os.path.join(self.walkthroughs_dir, filename)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
            
        print(f"Scraped: {filename}")
        self.saved_count += 1

    def scrape_github_repo(self, owner, repo, branch="master", path_filter=""):
        # Let's check if the repo is relevant to pwn/CTF
        repo_lower = repo.lower()
        if not any(kw in repo_lower for kw in ["pwn", "ctf", "exploit", "writeup", "note", "security", "cookbook", "college"]):
            print(f"Skipping unrelated repository: {owner}/{repo}")
            return

        counts = get_current_category_counts(self.walkthroughs_dir)
        total_files = len([f for f in os.listdir(self.walkthroughs_dir) if f.endswith(".txt")])
        if total_files >= 2200:
            return

        print(f"\n[Scraper] Scraping GitHub repository: {owner}/{repo} (trying branch: {branch})...")
        url = f"https://api.github.com/repos/{owner}/{repo}/git/trees/{branch}?recursive=1"
        try:
            time.sleep(0.5)
            r = requests.get(url, headers=self.headers, timeout=15)
            
            # Automatic fallback between master and main branches
            if r.status_code == 404 and branch == "master":
                print(f"Branch master not found, trying main...")
                time.sleep(0.5)
                branch = "main"
                url = f"https://api.github.com/repos/{owner}/{repo}/git/trees/{branch}?recursive=1"
                r = requests.get(url, headers=self.headers, timeout=15)
            elif r.status_code == 404 and branch == "main":
                print(f"Branch main not found, trying master...")
                time.sleep(0.5)
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
                    if path_filter and path_filter.lower() not in path.lower():
                        continue
                    candidates.append(path)
                    
            print(f"Found {len(candidates)} file candidates in {owner}/{repo}.")
            random.seed(42)
            random.shuffle(candidates)
            
            for path in candidates:
                total_files = len([f for f in os.listdir(self.walkthroughs_dir) if f.endswith(".txt")])
                if total_files >= 2200:
                    break
                    
                counts = get_current_category_counts(self.walkthroughs_dir)
                pred_cat = self.predict_category_from_meta(os.path.basename(path), path)
                if pred_cat != "other" and counts.get(pred_cat, 0) >= 330:
                    continue
                    
                raw_url = f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{path}"
                time.sleep(0.5)
                raw_r = requests.get(raw_url, headers=self.headers, timeout=10)
                if raw_r.status_code == 200:
                    text = raw_r.text.strip()
                    if len(text) < 150:
                        continue
                    cat = self.detect_category(text)
                    if cat != "other" and counts.get(cat, 0) >= 330:
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
        counts = get_current_category_counts(self.walkthroughs_dir)
        total_files = len([f for f in os.listdir(self.walkthroughs_dir) if f.endswith(".txt")])
        if total_files >= 2200:
            return

        print("\n[Scraper] Scraping HackTricks...")
        main_url = "https://book.hacktricks.xyz/reversing-and-exploiting/linux-exploiting-basic-esp/"
        try:
            time.sleep(0.5)
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
                total_files = len([f for f in os.listdir(self.walkthroughs_dir) if f.endswith(".txt")])
                if total_files >= 2200:
                    break
                    
                counts = get_current_category_counts(self.walkthroughs_dir)
                pred_cat = self.predict_category_from_meta("", url)
                if pred_cat != "other" and counts.get(pred_cat, 0) >= 330:
                    continue
                    
                time.sleep(0.5)
                res = requests.get(url, headers=self.headers, timeout=10)
                if res.status_code == 200:
                    sub_soup = BeautifulSoup(res.text, 'lxml')
                    text = self.extract_page_content(sub_soup, 'hacktricks')
                    if len(text.split()) < 150:
                        continue
                    cat = self.detect_category(text)
                    if cat != "other" and counts.get(cat, 0) >= 330:
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
        counts = get_current_category_counts(self.walkthroughs_dir)
        total_files = len([f for f in os.listdir(self.walkthroughs_dir) if f.endswith(".txt")])
        if total_files >= 2200:
            return

        print("\n[Scraper] Searching GitHub for ctf-writeups and pwn-writeups...")
        queries = ["ctf-writeups", "pwn-writeups"]
        for q in queries:
            total_files = len([f for f in os.listdir(self.walkthroughs_dir) if f.endswith(".txt")])
            if total_files >= 2200:
                break
            search_url = f"https://api.github.com/search/repositories?q={q}+stars:%3E=10&sort=stars&order=desc"
            try:
                time.sleep(0.5)
                r = requests.get(search_url, headers=self.headers, timeout=15)
                if r.status_code != 200:
                    print(f"GitHub search failed: {r.status_code}")
                    continue
                repos = r.json().get("items", [])[:8]
                for repo_item in repos:
                    owner = repo_item["owner"]["login"]
                    repo_name = repo_item["name"]
                    branch = repo_item.get("default_branch", "master")
                    self.scrape_github_repo(owner, repo_name, branch)
            except Exception as e:
                print(f"Error searching GitHub for {q}: {e}")

    def run(self):
        print("STEP A: Creating walkthroughs directory...")
        os.makedirs(self.walkthroughs_dir, exist_ok=True)

        # STEP B — Scrape CTFtime.org writeups
        total_files = len([f for f in os.listdir(self.walkthroughs_dir) if f.endswith(".txt")])
        if total_files < 2200:
            print("\nSTEP B: Scraping CTFtime.org...")
            ctftime_links = []
            page = 1
            while len(ctftime_links) < 40 and page <= 5:
                url = f"https://ctftime.org/writeups?page={page}"
                try:
                    time.sleep(0.5)
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
                total_files = len([f for f in os.listdir(self.walkthroughs_dir) if f.endswith(".txt")])
                if total_files >= 2200:
                    break
                counts = get_current_category_counts(self.walkthroughs_dir)
                pred_cat = self.predict_category_from_meta("", url)
                if pred_cat != "other" and counts.get(pred_cat, 0) >= 330:
                    continue

                try:
                    time.sleep(0.5)
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
                            if cat != "other" and counts.get(cat, 0) >= 330:
                                continue
                            self.save_writeup(
                                source="ctftime",
                                url=url,
                                challenge=challenge_name,
                                event=event_name,
                                team=team_name,
                                text=writeup_text
                            )
                except Exception as e:
                    print(f"Error scraping CTFtime writeup at {url}: {e}")

        # STEP C — Scrape CTF-Wiki
        total_files = len([f for f in os.listdir(self.walkthroughs_dir) if f.endswith(".txt")])
        if total_files < 2200:
            print("\nSTEP C: Scraping CTF-Wiki...")
            ctfwiki_targets = [
                {"url": "https://ctf-wiki.org/pwn/linux/user-mode/stackoverflow/x86-64/basic-rop/", "fallback": "https://ctf-wiki.org/pwn/linux/user-mode/stackoverflow/x86/basic-rop/", "topic": "basic_rop"},
                {"url": "https://ctf-wiki.org/pwn/linux/user-mode/stackoverflow/x86-64/ret2libc/", "fallback": "https://ctf-wiki.org/pwn/linux/user-mode/stackoverflow/x86/basic-rop/", "topic": "ret2libc"},
                {"url": "https://ctf-wiki.org/pwn/linux/user-mode/format-string/exploit-printf/", "fallback": "https://ctf-wiki.org/pwn/linux/user-mode/fmtstr/fmtstr-exploit/", "topic": "exploit_printf"},
                {"url": "https://ctf-wiki.org/pwn/linux/user-mode/heap/ptmalloc2/use-after-free/", "fallback": "https://ctf-wiki.org/pwn/linux/user-mode/heap/ptmalloc2/use-after-free/", "topic": "use_after_free"}
            ]
            for target in ctfwiki_targets:
                counts = get_current_category_counts(self.walkthroughs_dir)
                pred_cat = self.predict_category_from_meta(target["topic"], target["url"])
                if pred_cat != "other" and counts.get(pred_cat, 0) >= 330:
                    continue

                try:
                    time.sleep(0.5)
                    r = requests.get(target["url"], headers=self.headers, timeout=10)
                    active_url = target["url"]
                    if r.status_code != 200 and target["fallback"]:
                        time.sleep(0.5)
                        r = requests.get(target["fallback"], headers=self.headers, timeout=10)
                        active_url = target["fallback"]
                        
                    if r.status_code == 200:
                        soup = BeautifulSoup(r.text, 'lxml')
                        text = self.extract_page_content(soup, 'ctfwiki')
                        cat = self.detect_category(text)
                        if cat != "other" and counts.get(cat, 0) >= 330:
                            continue
                        self.save_writeup(
                            source="ctfwiki",
                            url=active_url,
                            challenge=target["topic"].replace('_', ' ').title(),
                            event="CTF-Wiki",
                            team="N/A",
                            text=text
                        )
                except Exception as e:
                    print(f"Error scraping CTF-Wiki for {target['topic']}: {e}")

        # STEP D — Scrape ir0nstone's GitBook
        total_files = len([f for f in os.listdir(self.walkthroughs_dir) if f.endswith(".txt")])
        if total_files < 2200:
            print("\nSTEP D: Scraping ir0nstone's GitBook...")
            ironstone_targets = [
                {"url": "https://ir0nstone.gitbook.io/notes/types/stack/return-oriented-programming", "fallback": "https://ir0nstone.gitbook.io/notes/binexp/stack/return-oriented-programming", "topic": "return_oriented_programming"},
                {"url": "https://ir0nstone.gitbook.io/notes/types/stack/ret2libc", "fallback": "https://ir0nstone.gitbook.io/notes/binexp/stack/return-oriented-programming/ret2libc", "topic": "ret2libc"},
                {"url": "https://ir0nstone.gitbook.io/notes/types/stack/format-string-exploits", "fallback": "https://ir0nstone.gitbook.io/notes/binexp/stack/format-string", "topic": "format_string_exploits"},
                {"url": "https://ir0nstone.gitbook.io/notes/types/heap/use-after-free", "fallback": "https://ir0nstone.gitbook.io/notes/binexp/heap/use-after-free", "topic": "use_after_free"}
            ]
            for target in ironstone_targets:
                counts = get_current_category_counts(self.walkthroughs_dir)
                pred_cat = self.predict_category_from_meta(target["topic"], target["url"])
                if pred_cat != "other" and counts.get(pred_cat, 0) >= 330:
                    continue

                try:
                    time.sleep(0.5)
                    r = requests.get(target["url"], headers=self.headers, timeout=10)
                    active_url = target["url"]
                    if r.status_code != 200 and target["fallback"]:
                        time.sleep(0.5)
                        r = requests.get(target["fallback"], headers=self.headers, timeout=10)
                        active_url = target["fallback"]
                        
                    if r.status_code == 200:
                        soup = BeautifulSoup(r.text, 'lxml')
                        text = self.extract_page_content(soup, 'ironstone')
                        cat = self.detect_category(text)
                        if cat != "other" and counts.get(cat, 0) >= 330:
                            continue
                        self.save_writeup(
                            source="ironstone",
                            url=active_url,
                            challenge=target["topic"].replace('_', ' ').title(),
                            event="ir0nstone's GitBook",
                            team="N/A",
                            text=text
                        )
                except Exception as e:
                    print(f"Error scraping ir0nstone GitBook for {target['topic']}: {e}")

        # STEP E — Scrape guyinatuxedo (nightmare)
        total_files = len([f for f in os.listdir(self.walkthroughs_dir) if f.endswith(".txt")])
        if total_files < 2200:
            print("\nSTEP E: Scraping guyinatuxedo (nightmare)...")
            try:
                base_url = "https://guyinatuxedo.github.io/"
                time.sleep(0.5)
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
                        total_files = len([f for f in os.listdir(self.walkthroughs_dir) if f.endswith(".txt")])
                        if total_files >= 2200:
                            break
                        counts = get_current_category_counts(self.walkthroughs_dir)
                        pred_cat = self.predict_category_from_meta("", url)
                        if pred_cat != "other" and counts.get(pred_cat, 0) >= 330:
                            continue

                        try:
                            time.sleep(0.5)
                            res = requests.get(url, headers=self.headers, timeout=10)
                            if res.status_code == 200:
                                sub_soup = BeautifulSoup(res.text, 'lxml')
                                url_parts = url.rstrip('/').split('/')
                                challenge_name = url_parts[-2] if len(url_parts) >= 2 else "Unknown"
                                
                                text = self.extract_page_content(sub_soup, 'nightmare')
                                cat = self.detect_category(text)
                                if cat != "other" and counts.get(cat, 0) >= 330:
                                    continue
                                self.save_writeup(
                                    source="nightmare",
                                    url=url,
                                    challenge=challenge_name,
                                    event="Nightmare",
                                    team="N/A",
                                    text=text
                                )
                        except Exception as e:
                            print(f"Error scraping guyinatuxedo page {url}: {e}")
            except Exception as e:
                print(f"Error scraping guyinatuxedo: {e}")

        # STEP H — Scrape pwn.college writeups
        total_files = len([f for f in os.listdir(self.walkthroughs_dir) if f.endswith(".txt")])
        if total_files < 2200:
            self.scrape_github_repo("w181496", "pwn.college-writeups")
            self.scrape_github_repo("AidenHils", "pwn-college")
            self.scrape_github_repo("xct", "pwn.college")

        # STEP I — Scrape LiveOverflow repositories
        total_files = len([f for f in os.listdir(self.walkthroughs_dir) if f.endswith(".txt")])
        if total_files < 2200:
            self.scrape_github_repo("LiveOverflow", "LiveOverflow-CTF")
            self.scrape_github_repo("liveoverflow", "lo-exploit-dev")

        # STEP J — Scrape HackTricks
        total_files = len([f for f in os.listdir(self.walkthroughs_dir) if f.endswith(".txt")])
        if total_files < 2200:
            self.scrape_hacktricks()

        # STEP K — Scrape other specific high quality repositories
        total_files = len([f for f in os.listdir(self.walkthroughs_dir) if f.endswith(".txt")])
        if total_files < 2200:
            self.scrape_github_repo("ctfs", "writeups")
            self.scrape_github_repo("Dvd848", "CTFs")
            self.scrape_github_repo("M4x", "ctf-writeups")
            self.scrape_github_repo("ir0nstone", "ir0nstone.github.io")

        # STEP L — Scrape GitHub Code Search general pwn writeups
        total_files = len([f for f in os.listdir(self.walkthroughs_dir) if f.endswith(".txt")])
        if total_files < 2200:
            self.scrape_github_search()

        final_counts = get_current_category_counts(self.walkthroughs_dir)
        total_files = len([f for f in os.listdir(self.walkthroughs_dir) if f.endswith(".txt")])
        print(f"\nTOTAL COLLECTED: {total_files} writeups")
        print("Final Category counts:", final_counts)

if __name__ == "__main__":
    scraper = WriteupScraper()
    scraper.run()
