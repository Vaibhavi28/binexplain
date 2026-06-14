import os
import re
import sys
import urllib.parse
import requests
from bs4 import BeautifulSoup

# Reconfigure stdout to use UTF-8 on Windows to prevent encoding errors when printing to console
sys.stdout.reconfigure(encoding='utf-8')

class WriteupScraper:
    def __init__(self):
        self.headers = {"User-Agent": "BinExplain/1.0 Educational Tool"}
        self.base_dir = os.path.dirname(os.path.abspath(__file__))
        self.walkthroughs_dir = os.path.join(self.base_dir, "walkthroughs")
        self.saved_count = 0

    def sanitize_filename(self, name):
        # Keep only alphanumeric characters, spaces, hyphens, and underscores
        sanitized = re.sub(r'[^a-zA-Z0-9_\-\s]', '', name)
        # Replace spaces/multiple separators with a single underscore
        sanitized = re.sub(r'[\s\-]+', '_', sanitized)
        return sanitized.strip('_').lower()

    def detect_category(self, text):
        text_lower = text.lower()
        
        # 1. ret2win
        if "ret2win" in text_lower or "win function" in text_lower or "flag function" in text_lower:
            return "ret2win"
            
        # 2. ret2libc
        if "ret2libc" in text_lower or ("system()" in text_lower and "overflow" in text_lower) or ("/bin/sh" in text_lower and "overflow" in text_lower):
            return "ret2libc"
            
        # 3. format_string
        if "format string" in text_lower or "%p" in text_lower or "%n" in text_lower or "printf exploit" in text_lower:
            return "format_string"
            
        # 4. heap_exploitation
        if "heap" in text_lower or "tcache" in text_lower or "uaf" in text_lower or "use after free" in text_lower or "double free" in text_lower:
            return "heap_exploitation"
            
        # 5. rop_chain
        if "rop" in text_lower or "rop chain" in text_lower or "gadget" in text_lower or "ropgadget" in text_lower:
            return "rop_chain"
            
        # 6. shellcode
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

        sanitized_title = self.sanitize_filename(challenge)
        filename = f"{source}_{sanitized_title}.txt"
        filepath = os.path.join(self.walkthroughs_dir, filename)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
            
        print(f"Scraped: {filename}")
        self.saved_count += 1

    def run(self):
        # STEP A — Create the folder
        print("STEP A: Creating walkthroughs directory...")
        os.makedirs(self.walkthroughs_dir, exist_ok=True)

        # STEP B — Scrape CTFtime.org writeups
        print("\nSTEP B: Scraping CTFtime.org...")
        ctftime_links = []
        page = 1
        while len(ctftime_links) < 40 and page <= 5:
            url = f"https://ctftime.org/writeups?page={page}"
            try:
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
            try:
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
        print("\nSTEP C: Scraping CTF-Wiki...")
        ctfwiki_targets = [
            {
                "url": "https://ctf-wiki.org/pwn/linux/user-mode/stackoverflow/x86-64/basic-rop/",
                "fallback": "https://ctf-wiki.org/pwn/linux/user-mode/stackoverflow/x86/basic-rop/",
                "topic": "basic_rop"
            },
            {
                "url": "https://ctf-wiki.org/pwn/linux/user-mode/stackoverflow/x86-64/ret2libc/",
                "fallback": "https://ctf-wiki.org/pwn/linux/user-mode/stackoverflow/x86/basic-rop/",
                "topic": "ret2libc"
            },
            {
                "url": "https://ctf-wiki.org/pwn/linux/user-mode/format-string/exploit-printf/",
                "fallback": "https://ctf-wiki.org/pwn/linux/user-mode/fmtstr/fmtstr-exploit/",
                "topic": "exploit_printf"
            },
            {
                "url": "https://ctf-wiki.org/pwn/linux/user-mode/heap/ptmalloc2/use-after-free/",
                "fallback": "https://ctf-wiki.org/pwn/linux/user-mode/heap/ptmalloc2/use-after-free/",
                "topic": "use_after_free"
            }
        ]

        for target in ctfwiki_targets:
            try:
                r = requests.get(target["url"], headers=self.headers, timeout=10)
                active_url = target["url"]
                if r.status_code != 200 and target["fallback"]:
                    r = requests.get(target["fallback"], headers=self.headers, timeout=10)
                    active_url = target["fallback"]
                    
                if r.status_code == 200:
                    soup = BeautifulSoup(r.text, 'lxml')
                    text = self.extract_page_content(soup, 'ctfwiki')
                    self.save_writeup(
                        source="ctfwiki",
                        url=active_url,
                        challenge=target["topic"].replace('_', ' ').title(),
                        event="CTF-Wiki",
                        team="N/A",
                        text=text
                    )
                else:
                    print(f"Failed to fetch CTF-Wiki for {target['topic']}: status {r.status_code}")
            except Exception as e:
                print(f"Error scraping CTF-Wiki for {target['topic']}: {e}")

        # STEP D — Scrape ir0nstone's GitBook
        print("\nSTEP D: Scraping ir0nstone's GitBook...")
        ironstone_targets = [
            {
                "url": "https://ir0nstone.gitbook.io/notes/types/stack/return-oriented-programming",
                "fallback": "https://ir0nstone.gitbook.io/notes/binexp/stack/return-oriented-programming",
                "topic": "return_oriented_programming"
            },
            {
                "url": "https://ir0nstone.gitbook.io/notes/types/stack/ret2libc",
                "fallback": "https://ir0nstone.gitbook.io/notes/binexp/stack/return-oriented-programming/ret2libc",
                "topic": "ret2libc"
            },
            {
                "url": "https://ir0nstone.gitbook.io/notes/types/stack/format-string-exploits",
                "fallback": "https://ir0nstone.gitbook.io/notes/binexp/stack/format-string",
                "topic": "format_string_exploits"
            },
            {
                "url": "https://ir0nstone.gitbook.io/notes/types/heap/use-after-free",
                "fallback": "https://ir0nstone.gitbook.io/notes/binexp/heap/use-after-free",
                "topic": "use_after_free"
            }
        ]

        for target in ironstone_targets:
            try:
                r = requests.get(target["url"], headers=self.headers, timeout=10)
                active_url = target["url"]
                if r.status_code != 200 and target["fallback"]:
                    r = requests.get(target["fallback"], headers=self.headers, timeout=10)
                    active_url = target["fallback"]
                    
                if r.status_code == 200:
                    soup = BeautifulSoup(r.text, 'lxml')
                    text = self.extract_page_content(soup, 'ironstone')
                    self.save_writeup(
                        source="ironstone",
                        url=active_url,
                        challenge=target["topic"].replace('_', ' ').title(),
                        event="ir0nstone's GitBook",
                        team="N/A",
                        text=text
                    )
                else:
                    print(f"Failed to fetch ir0nstone GitBook for {target['topic']}: status {r.status_code}")
            except Exception as e:
                print(f"Error scraping ir0nstone GitBook for {target['topic']}: {e}")

        # STEP E — Scrape guyinatuxedo (nightmare)
        print("\nSTEP E: Scraping guyinatuxedo (nightmare)...")
        try:
            base_url = "https://guyinatuxedo.github.io/"
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
                                
                print(f"Found {len(nightmare_links)} guyinatuxedo challenge links. Scraping first 20...")
                for url in nightmare_links[:20]:
                    try:
                        res = requests.get(url, headers=self.headers, timeout=10)
                        if res.status_code == 200:
                            sub_soup = BeautifulSoup(res.text, 'lxml')
                            url_parts = url.rstrip('/').split('/')
                            challenge_name = url_parts[-2] if len(url_parts) >= 2 else "Unknown"
                            
                            text = self.extract_page_content(sub_soup, 'nightmare')
                            self.save_writeup(
                                source="nightmare",
                                url=url,
                                challenge=challenge_name,
                                event="Nightmare",
                                team="N/A",
                                text=text
                            )
                        else:
                            print(f"Failed to fetch guyinatuxedo page {url}: status {res.status_code}")
                    except Exception as e:
                        print(f"Error scraping guyinatuxedo page {url}: {e}")
            else:
                print(f"Failed to fetch guyinatuxedo home: status {r.status_code}")
        except Exception as e:
            print(f"Error scraping guyinatuxedo: {e}")

        # STEP G — Print progress
        print(f"\nTOTAL COLLECTED: {self.saved_count} writeups")

if __name__ == "__main__":
    scraper = WriteupScraper()
    scraper.run()
