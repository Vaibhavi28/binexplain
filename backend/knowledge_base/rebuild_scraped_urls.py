import os, re, json

WALKTHROUGH_DIR = r'backend/knowledge_base/walkthroughs'
SCRAPED_FILE = r'backend/knowledge_base/scraped_urls.json'

urls = set()
for root, dirs, files in os.walk(WALKTHROUGH_DIR):
    for fname in files:
        if not fname.endswith('.txt'):
            continue
        fpath = os.path.join(root, fname)
        try:
            with open(fpath, encoding='utf-8', errors='ignore') as f:
                header = f.read(500)
            match = re.search(r'URL:\s*(\S+)', header)
            if match:
                urls.add(match.group(1))
        except Exception:
            pass

with open(SCRAPED_FILE, 'w') as f:
    json.dump(list(urls), f)

print(f'Rebuilt scraped_urls.json with {len(urls)} real URLs')
print(f'Removed all bloated non-writeup URLs')
