"""
Fix emoji mojibake in BinExplain frontend files.
Uses Unicode escape sequences to avoid cp1252 encoding issues in the script itself.
"""

import os

# Mojibake map: broken sequence (as it appears in the file) -> correct emoji
# Using \\uXXXX escapes so this file itself stays ASCII-safe
MOJIBAKE_MAP = [
    # Sequence      # Correct replacement (use unicode escapes)
    ("ðŸ\x94\xac", "\U0001f52c"),  # 🔬
    ("ðŸ\x94", "\U0001f4dd"),      # 📝 (fallback, will be narrowed below)
    ("ðŸ\x94\x8b", "\U0001f4cb"),  # 📋
    ("ðŸ\x94\x97", "\U0001f517"),  # 🔗
    ("ðŸ\x94\x84", "\U0001f504"),  # 🔄
    ("ðŸ\x94\x8a", "\U0001f50a"),  # 🔊
    ("ðŸ\x94\xa2", "\U0001f522"),  # 🔢
    ("ðŸ\x93\xa6", "\U0001f4e6"),  # 📦
    ("ðŸ\x93\x8a", "\U0001f4ca"),  # 📊
    ("ðŸ\x91\x8d", "\U0001f44d"),  # 👍
    ("ðŸ\x91\x8e", "\U0001f44e"),  # 👎
    ("ðŸ\x92¬", "\U0001f4ac"),     # 💬
    ("ðŸ\x8e\xaf", "\U0001f3af"),  # 🎯
    ("ðŸ\x8e\xb2", "\U0001f3b2"),  # 🎲
    ("ðŸ\x9a©", "\U0001f6a9"),     # 🚩
    ("ðŸ§\xa0", "\U0001f9e0"),     # 🧠
    ("ðŸ§©", "\U0001f9e9"),        # 🧩
    ("ðŸ\x9b¡", "\U0001f6e1"),     # 🛡
    ("ðŸ\x97", "\U0001f3d7"),      # 🏗
    ("ðŸ\x96¼", "\U0001f5bc"),     # 🖼
    ("â\x9a ï¸\x8f", "\u26a0\ufe0f"),  # ⚠️
    ("â\x9a ï¸", "\u26a0\ufe0f"),      # ⚠️ variant
    ("â\x9a ", "\u26a0\ufe0f"),         # ⚠️ no variation selector
    ("â\x9c\x93", "\u2713"),       # ✓
    ("â\x94\x80", "\u2500"),       # ─
    ("ï¸\x8f", ""),               # lone variation selector, remove
    ("\xef\xb8\x8f", ""),         # same in latin bytes form
    ("ï¸", ""),                   # any remaining lone vs16
    (" ï¸", ""),                  # with preceding space
    # Source Code tab fix
    ("ðŸ\x93\x8f", "\U0001f4dd"),  # 📝 (if 📏 was mojibaked)
]

def fix_file(path):
    print(f"\nProcessing: {path}")

    with open(path, "rb") as f:
        raw = f.read()

    # Detect encoding
    try:
        text = raw.decode("utf-8")
        print("  Decoded as UTF-8")
    except UnicodeDecodeError:
        print("  Not valid UTF-8, trying cp1252...")
        latin = raw.decode("cp1252")
        # Re-encode as latin-1 to get original bytes, decode as utf-8
        text = latin.encode("latin-1").decode("utf-8")
        print("  Recovered via cp1252->latin-1->utf-8")

    # Apply all fixes
    changed = 0
    for broken, correct in MOJIBAKE_MAP:
        count = text.count(broken)
        if count > 0:
            text = text.replace(broken, correct)
            changed += count
            print(f"  Fixed {count}x: {repr(broken)} -> {repr(correct)}")

    # Write clean UTF-8 without BOM
    with open(path, "w", encoding="utf-8", newline="") as f:
        f.write(text)
    
    if changed == 0:
        print("  No changes needed (file looks clean)")
    else:
        print(f"  Saved. Total replacements: {changed}")

# Run
os.chdir(os.path.dirname(os.path.abspath(__file__)))

fix_file("frontend/src/App.jsx")
fix_file("frontend/src/index.css")

# Verify index.html
with open("frontend/index.html", "r", encoding="utf-8") as f:
    html = f.read()
if '<meta charset="UTF-8"' in html:
    print('\nindex.html: <meta charset="UTF-8" /> present')
else:
    print('\nWARNING: index.html missing <meta charset="UTF-8" />')

print("\nDone. Run npm run build to verify.")
