import re

with open('frontend/src/App.jsx', 'rb') as f:
    text = f.read().decode('utf-8', errors='ignore')

replacements = [
    # Clean emojis
    ('🔬', '[Binary]'),
    ('📝', '[Code]'),
    ('⚠️', '[Warning]'),
    ('🎯', '[CTF]'),
    ('🎲', '[Difficulty]'),
    ('🔒', '[Security]'),
    ('🛡️', '[Security]'),
    ('🛡', '[Security]'),
    ('📊', '[CVSS]'),
    ('📐', '[Offset]'),
    ('🔗', '[ROP]'),
    ('⚡', '[Tools]'),
    ('💡', '[AI]'),
    ('💬', '[Chat]'),
    ('📋', '[Commands]'),
    ('🚩', '[Flags]'),
    ('🔍', '[Strings]'),
    
    # Mojibake variants found in previous logs
    ('ðŸ”¬', '[Binary]'),
    ('ðŸ“', '[Code]'),
    ('âš ï¸', '[Warning]'),
    ('âš ', '[Warning]'),
    ('ðŸŽ¯', '[CTF]'),
    ('ðŸŽ²', '[Difficulty]'),
    ('ðŸ›¡ï¸\x8f', '[Security]'),
    ('ðŸ›¡', '[Security]'),
    ('ðŸ“Š', '[CVSS]'),
    ('ðŸ“', '[Offset]'),
    ('ðŸ”—', '[ROP]'),
    ('âš¡', '[Tools]'),
    ('ðŸ’¡', '[AI]'),
    ('ðŸ’¬', '[Chat]'),
    ('ðŸ“«', '[Chat]'),
    ('ðŸ“‹', '[Commands]'),
    ('ðŸš©', '[Flags]'),
    ('ðŸ” ', '[Strings]'),
]

for old, new in replacements:
    text = text.replace(old, new)

# To remove other emojis and emoji-related mojibake:
# Emojis in utf-8 often start with \U0001....
# In mojibake (cp1252 to utf-8), they often appear as 'ðŸ...' (ðŸ is \u00f0\u0178)
# Remove remaining explicit emojis
text = re.sub(r'[\U00010000-\U0010ffff]', '', text)
text = re.sub(r'[\u2600-\u27BF]', '', text)  # Misc symbols (like warning, but we already replaced warning)

# Remove remaining mojibake sequences that look like emojis (ðŸ...)
text = re.sub(r'ðŸ.{1,3}', '', text)
text = re.sub(r'ï¸\x8f', '', text)
text = re.sub(r'ï¸', '', text)

# There are other mojibake characters like â, \x9d, etc. The user didn't explicitly ask to remove them, but they might be broken UI elements. Let's fix the specific UI ones:
text = text.replace('â–¶', '▶')
text = text.replace('â€¹', '‹')
text = text.replace('â€º', '›')
text = text.replace('âœ•', '✕')

# General cleanup of empty brackets if any mojibake got caught inside brackets or similar
# Actually, let's just write the file out
with open('frontend/src/App.jsx', 'wb') as f:
    f.write(text.encode('utf-8'))

print("Emoji replacement complete!")
