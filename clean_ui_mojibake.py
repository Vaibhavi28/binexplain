with open('frontend/src/App.jsx', 'r', encoding='utf-8') as f:
    text = f.read()

# Replace mojibake UI elements with plain ASCII equivalents
text = text.replace('â–¶', '>')
text = text.replace('â€¹', '<')
text = text.replace('â€º', '>')
text = text.replace('âœ•', 'X')
text = text.replace('â†’', '->')
text = text.replace('â†\x90', '<-') # if there's a left arrow

# Also, there's `â”€` which is `─` (box drawing character) used in comments. I'll change it to `-` to make it pure ASCII
text = text.replace('â”€', '-')
# And `âœ“` which is `✓` (check mark). I'll change it to `[v]`
text = text.replace('âœ“', '[v]')
# And `â€¢` which is `•` (bullet). I'll change it to `*`
text = text.replace('â€¢', '*')

# Replace any remaining \x9d or cp1252 artifacts that could render garbled
import re
text = re.sub(r'[\x80-\xFF]', '', text)

# Just one more pass of explicit emojis from user request that might have been skipped if mojibake was different
text = text.replace('ðŸ”¬', '[Binary]')
text = text.replace('ðŸ“', '[Code]')
text = text.replace('âš ï¸', '[Warning]')
text = text.replace('âš ', '[Warning]')
text = text.replace('ðŸŽ¯', '[CTF]')
text = text.replace('ðŸŽ²', '[Difficulty]')
text = text.replace('ðŸ›¡ï¸', '[Security]')
text = text.replace('ðŸ›¡', '[Security]')
text = text.replace('ðŸ“Š', '[CVSS]')
text = text.replace('ðŸ“', '[Offset]')
text = text.replace('ðŸ”—', '[ROP]')
text = text.replace('âš¡', '[Tools]')
text = text.replace('ðŸ’¡', '[AI]')
text = text.replace('ðŸ’¬', '[Chat]')
text = text.replace('ðŸ“«', '[Chat]')
text = text.replace('ðŸ“‹', '[Commands]')
text = text.replace('ðŸš©', '[Flags]')
text = text.replace('ðŸ” ', '[Strings]')

# I also noticed 🤔 was replaced by '?' in some places, I'll replace any remaining emoji-like ones
text = text.replace('🤔', '[?]')
text = text.replace('👍', '[Helpful]')
text = text.replace('👎', '[Not Helpful]')
text = text.replace('🔓', '[Unlock]')
text = text.replace('🧠', '[AI Hints]')
text = text.replace('🧩', '[Interesting]')
text = text.replace('🏗️', '[Libc]')
text = text.replace('⚙️', '[Function]')

# General remove of any remaining unicode past 007F to ensure absolutely no garbled text
text = re.sub(r'[^\x00-\x7F]+', '', text)

with open('frontend/src/App.jsx', 'w', encoding='utf-8') as f:
    f.write(text)

print('Mojibake fixing complete.')
