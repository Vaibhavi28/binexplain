import re

with open('frontend/src/App.jsx', 'rb') as f:
    text = f.read().decode('utf-8')

def fix_mojibake_broad(match):
    try:
        return match.group(0).encode('cp1252').decode('utf-8')
    except:
        return match.group(0)

# The character 'ð' is \u00f0
fixed_text = re.sub(r'\u00f0[\x80-\xFF\x00-\x7F]+', fix_mojibake_broad, text)
fixed_text = fixed_text.replace('â”€', '─')
fixed_text = fixed_text.replace('âœ“', '✓')
# Fix any remaining broken ones
fixed_text = fixed_text.replace('dY"', '⚠️')

with open('frontend/src/App.jsx', 'wb') as f:
    f.write(fixed_text.encode('utf-8'))
print('Fixed App.jsx encoding')
