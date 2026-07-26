import sys
import re

sys.stdout.reconfigure(encoding='utf-8')

with open('frontend/src/App.jsx', encoding='utf-8', errors='replace') as f:
    lines = f.readlines()

# Look specifically for raw multi-byte mojibake sequences (â followed by non-ascii)
# These are the most common: â€™ â€œ âœ… âš¡ etc.
# We look for the byte pattern: 0xC2-0xE2 range chars followed by 0x80-0xBF range
pattern = re.compile(r'[\xc2-\xe2][\x80-\xbf][\x80-\xbf]?')

found = []
for i, line in enumerate(lines, 1):
    # Check for mojibake: sequences like â followed by chars in high range
    raw = line.encode('utf-8')
    # Look for literal multi-byte sequences embedded as raw bytes in source
    for m in re.finditer(rb'[\xc3\xc2\xe2][\x80-\xbf][\x80-\xbf]?', raw):
        col = raw[:m.start()].decode('utf-8', errors='replace').count('\x00') + 1
        found.append((i, m.start(), m.group(), line.strip()[:80]))

if not found:
    # Alternative approach: look for characters like â, Ã directly in the string
    mojibake_chars = ['â', 'Ã', 'Â', 'ã', 'à']
    for i, line in enumerate(lines, 1):
        for c in mojibake_chars:
            if c in line:
                found.append((i, 0, c.encode(), line.strip()[:80]))
                break

seen = set()
for linenum, col, seq, context in found:
    key = (linenum, seq)
    if key not in seen:
        seen.add(key)
        print(f"Line {linenum}: {repr(seq)} in: {context}")
