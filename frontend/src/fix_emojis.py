import re

with open('frontend/src/App.jsx', 'r', encoding='utf-8') as f:
    text = f.read()

# Exact matches based on previous analysis and App.jsx context
replacements = {
    'ðŸ”¬': '🔬',
    'ðŸ“„': '📄',
    'ðŸ“¦': '📦',
    'ðŸŽ¯': '🎯',
    'ðŸŽ²': '🎲',
    'ðŸ›¡ï¸\x8f': '🛡️',
    'ðŸ›¡': '🛡️',
    'ðŸ“Š': '📊',
    'ðŸ“': '📏',
    'ðŸ§©': '🧩',
    'ðŸ§\xa0': '🧠',
    'ðŸ‘\x8d': '👍',
    'ðŸ‘Ž': '👎',
    'ðŸ”€': '🔀',
    'ðŸ—ï¸\x8f': '🏗️',
    'ðŸ—': '🏗️',
    'ðŸ”¢': '🔢',
    '⚙ï¸\x8f': '⚙️',
    '⚙': '⚙️',
    'ðŸ“‹': '📋',
    'ðŸ“«': '💬',
    'ðŸš©': '🚩',
    'ðŸ”': '🔍',
    'ðŸ”‘': '🔑',
    'ðŸ”“': '🔓',
    'âš ï¸\x8f': '⚠️',
    'âš': '⚠️',
    'ðŸ’¬': '💬',
    'ðŸ–¼ï¸\x8f': '🖼️',
    'ðŸ–¼': '🖼️',
    'âœ“': '✓',
    'â”€': '─',
    'ðŸ”—': '🔗',
    'â†“ï¸\x8f': '⬇️',
    'â†“': '⬇️'
}

for k, v in replacements.items():
    text = text.replace(k, v)

with open('frontend/src/App.jsx', 'w', encoding='utf-8') as f:
    f.write(text)

with open('frontend/src/index.css', 'r', encoding='utf-8') as f:
    text_css = f.read()
for k, v in replacements.items():
    text_css = text_css.replace(k, v)
with open('frontend/src/index.css', 'w', encoding='utf-8') as f:
    f.write(text_css)

print('Emoji replacements done')
