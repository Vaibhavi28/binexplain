"""
WriteupLiveSearch — background CTF writeup discovery via DuckDuckGo.

Runs in a daemon thread after every binary analysis.  Never blocks the
analysis response.

Design decisions:
• All network I/O is wrapped in try/except — a failed search is silent.
• Only pages containing exploit-related keywords are saved.
• Files use the same header format as scraper.py for RAG compatibility.
• update_from_scraper() is called after saving so new docs are indexed.
"""

import os
import re
import sys
import requests
from bs4 import BeautifulSoup

# Reconfigure stdout to use UTF-8 on Windows to prevent encoding errors
try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass


class WriteupLiveSearch:
    """
    Search DuckDuckGo for CTF writeups related to the binary being
    analyzed and persist any useful pages into the knowledge base.
    """

    # Keywords that confirm a page contains exploit content
    EXPLOIT_KEYWORDS = [
        "exploit", "payload", "pwntools", "flag", "overflow",
        "format", "heap", "ROP", "ret2", "shellcode", "pwn",
        "cyclic", "gadget", "libc",
    ]

    def __init__(self):
        self.base_dir = os.path.dirname(os.path.abspath(__file__))
        self.walkthroughs_dir = os.path.join(self.base_dir, "walkthroughs")
        self.headers = {"User-Agent": "BinExplain/1.0 Educational Tool"}

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _sanitize_filename(self, name: str) -> str:
        """Strip non-alphanumeric chars and collapse separators."""
        sanitized = re.sub(r"[^a-zA-Z0-9_\-\s]", "", name)
        sanitized = re.sub(r"[\s\-]+", "_", sanitized)
        return sanitized.strip("_").lower()

    def _detect_category(self, text: str) -> str:
        """Use the shared scoring-based detector from scraper.py."""
        try:
            from knowledge_base.scraper import detect_category_from_text
        except ImportError:
            from scraper import detect_category_from_text
        cat = detect_category_from_text(text)
        # Map 'unknown' to 'rop_chain' as a safe generic pwn bucket
        return cat if cat != 'unknown' else 'rop_chain'

    def _detect_difficulty(self, text: str) -> str:
        t = text.lower()
        if "easy" in t:
            return "Easy"
        if "medium" in t:
            return "Medium"
        if "hard" in t:
            return "Hard"
        return "Unknown"

    def _detect_protections(self, text: str) -> str:
        t = text.lower()
        prot = []
        if "nx" in t:
            prot.append("NX")
        if "pie" in t:
            prot.append("PIE")
        if "canary" in t:
            prot.append("Canary")
        if "relro" in t:
            prot.append("RELRO")
        return ", ".join(prot) if prot else "None"

    def _detect_key_functions(self, text: str) -> str:
        t = text.lower()
        funcs = []
        for func in ["gets", "printf", "scanf", "malloc", "free",
                     "system", "execve", "read", "fgets"]:
            if func in t:
                funcs.append(func)
        return ", ".join(funcs) if funcs else "None"

    def _is_exploit_relevant(self, text: str) -> bool:
        """Return True if the page contains meaningful exploit content."""
        t = text.lower()
        return any(kw in t for kw in self.EXPLOIT_KEYWORDS)

    def _extract_best_snippet(self, text: str, max_chars: int = 2000) -> str:
        """
        Return the most exploit-dense 2000-char window from text.
        Prefer sections with the highest density of exploit keywords.
        """
        if len(text) <= max_chars:
            return text

        best_start = 0
        best_score = 0

        step = max(1, max_chars // 4)
        for start in range(0, len(text) - max_chars, step):
            chunk = text[start: start + max_chars].lower()
            score = sum(chunk.count(kw) for kw in self.EXPLOIT_KEYWORDS)
            if score > best_score:
                best_score = score
                best_start = start

        return text[best_start: best_start + max_chars]

    def _build_file_content(
        self,
        url: str,
        challenge: str,
        snippet: str,
    ) -> str:
        """Build a walkthrough file in the same format as scraper.py."""
        category = self._detect_category(snippet)
        difficulty = self._detect_difficulty(snippet)
        protections = self._detect_protections(snippet)
        key_functions = self._detect_key_functions(snippet)

        # Minimal key_technique from first good sentence
        key_technique = f"Writeup for {challenge} — {category} exploitation technique."
        sentences = re.split(r"(?<=[.!?])\s+", snippet)
        for s in sentences:
            s_clean = s.strip().replace("\n", " ")
            if 20 < len(s_clean) < 150:
                s_lower = s_clean.lower()
                if any(w in s_lower for w in ["exploit", "vulnerability", "overflow", "bypass"]):
                    key_technique = s_clean
                    break

        # Pad if too short (matches scraper.py behaviour)
        word_count = len(snippet.split())
        if word_count < 200:
            padding = (
                f"\n\n[Additional Context: This page covers {challenge} "
                f"in the context of binary exploitation and CTF challenges. "
                f"Category: {category}.]"
            )
            while len((snippet + padding).split()) < 200:
                padding += (
                    " Additional reference material on binary security mechanisms, "
                    "vulnerabilities, and bypass techniques."
                )
            snippet = snippet + padding

        return (
            f"---\n"
            f"SOURCE: livesearch\n"
            f"URL: {url}\n"
            f"CHALLENGE: {challenge}\n"
            f"EVENT: LiveSearch\n"
            f"TEAM: N/A\n"
            f"CATEGORY: {category}\n"
            f"DIFFICULTY: {difficulty}\n"
            f"PROTECTIONS: {protections}\n"
            f"KEY_FUNCTIONS: {key_functions}\n"
            f"KEY_TECHNIQUE: {key_technique}\n"
            f"---\n"
            f"{snippet}"
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def search_and_save(
        self,
        binary_name: str,
        ctf_category: str,
        dangerous_functions: list,
        filename_prefix: str,
    ) -> int:
        """
        Search DuckDuckGo for CTF writeups related to *binary_name* and save
        any relevant pages into the walkthroughs directory.

        Parameters
        ----------
        binary_name        : Name of the uploaded binary (e.g. "schooled")
        ctf_category       : Detected exploit category (e.g. "ret2win")
        dangerous_functions: List of dangerous function names found in binary
        filename_prefix    : Prefix for output filenames (e.g. "live_schooled")

        Returns
        -------
        Number of new writeup files saved.
        """
        os.makedirs(self.walkthroughs_dir, exist_ok=True)

        first_func = dangerous_functions[0] if dangerous_functions else ""

        queries = [
            f"{binary_name} CTF writeup pwn exploit",
            f"{ctf_category} CTF pwn writeup {first_func}",
            f"CTFtime pwn {ctf_category} writeup solution",
        ]

        saved = 0

        for query in queries:
            try:
                results = self._ddg_search(query)
            except Exception as exc:
                print(f"[LiveSearch] DuckDuckGo search failed for '{query}': {exc}")
                results = []

            for item in results:
                url = item.get("href") or item.get("url") or ""
                if not url:
                    continue

                try:
                    page_text = self._fetch_page_text(url)
                except Exception:
                    continue

                if not page_text or not self._is_exploit_relevant(page_text):
                    continue

                snippet = self._extract_best_snippet(page_text)
                challenge = item.get("title", binary_name) or binary_name
                content = self._build_file_content(url, challenge, snippet)

                # Derive the category from content so we can pick the right subfolder
                category = self._detect_category(snippet)
                KNOWN_CATEGORIES = [
                    "ret2win", "ret2libc", "format_string", "rop_chain",
                    "heap_exploitation", "shellcode", "ret2plt", "got_overwrite",
                    "ret2csu", "srop", "fastbin_dup", "tcache_poisoning",
                    "use_after_free", "one_gadget", "canary_bypass", "pie_bypass",
                    "off_by_one", "stack_pivot", "integer_overflow", "seccomp_bypass",
                    "house_of_force", "house_of_spirit", "house_of_orange",
                    "unsorted_bin_attack",
                ]
                category_dir = category if category in KNOWN_CATEGORIES else "rop_chain"
                save_dir = os.path.join(self.walkthroughs_dir, category_dir)
                os.makedirs(save_dir, exist_ok=True)

                safe_url = self._sanitize_filename(url)[:80]
                fname = f"{filename_prefix}_{safe_url}.txt"
                fpath = os.path.join(save_dir, fname)

                # Skip if we already have this file (check new path)
                if os.path.exists(fpath):
                    continue
                # Also skip if an old root-level copy exists (migration guard)
                old_fpath = os.path.join(self.walkthroughs_dir, fname)
                if os.path.exists(old_fpath):
                    continue

                try:
                    with open(fpath, "w", encoding="utf-8") as f:
                        f.write(content)
                    saved += 1
                    print(f"[LiveSearch] Saved: {category_dir}/{fname}")
                except Exception as exc:
                    print(f"[LiveSearch] Could not write {fname}: {exc}")

        # Re-index the knowledge base so new files are immediately searchable
        if saved > 0:
            try:
                # Import here to avoid circular-import at module load time
                from knowledge_base.rag_engine import CTFKnowledgeBase  # noqa: PLC0415
                ctf_knowledge = CTFKnowledgeBase()
                ctf_knowledge.update_from_scraper()
            except Exception as exc:
                print(f"[LiveSearch] KB re-index failed: {exc}")

        print(
            f"[LiveSearch] Found and saved {saved} new writeups for {binary_name}"
        )
        return saved

    # ------------------------------------------------------------------
    # Internal network helpers
    # ------------------------------------------------------------------

    def _ddg_search(self, query: str, max_results: int = 5) -> list:
        """Perform a DuckDuckGo text search and return result dicts.

        Supports both the new 'ddgs' package and the legacy
        'duckduckgo_search' name (which shows a deprecation warning).
        """
        try:
            from ddgs import DDGS  # noqa: PLC0415  # new package name
        except ImportError:
            from duckduckgo_search import DDGS  # noqa: PLC0415  # legacy

        with DDGS() as ddgs:
            return list(ddgs.text(query, max_results=max_results))

    def _fetch_page_text(self, url: str, timeout: int = 10) -> str:
        """Fetch a URL and return its visible text content."""
        resp = requests.get(url, headers=self.headers, timeout=timeout)
        resp.raise_for_status()

        soup = BeautifulSoup(resp.text, "lxml")

        # Prefer main content areas
        content_el = (
            soup.find("main")
            or soup.find("article")
            or soup.find("section")
            or soup.find("div", class_="page-inner")
            or soup.find("div", class_="book-body")
        )
        if content_el:
            return content_el.get_text(separator=" ", strip=True)
        return soup.get_text(separator=" ", strip=True)
