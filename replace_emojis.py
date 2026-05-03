import re

with open('frontend/src/App.jsx', 'r', encoding='utf-8') as f:
    text = f.read()

# Exact replacements requested by user
replacements = {
    '🔬': '[Binary]',
    '📝': '[Code]',
    '⚠️': '[Warning]',
    '🎯': '[CTF]',
    '🎲': '[Difficulty]',
    '🔒': '[Security]',
    '🛡️': '[Security]', # Adding this since we used it previously
    '🛡': '[Security]',
    '📊': '[CVSS]',
    '📐': '[Offset]',
    '🔗': '[ROP]',
    '⚡': '[Tools]',
    '💡': '[AI]',
    '💬': '[Chat]',
    '📋': '[Commands]',
    '🚩': '[Flags]',
    '🔍': '[Strings]'
}

for emoji_char, plain_text in replacements.items():
    text = text.replace(emoji_char, plain_text)

# Regex to match other emojis (Unicode ranges covering most emojis)
# Emoticons: 1F600-1F64F, Misc Symbols: 2600-26FF, Dingbats: 2700-27BF, 
# Transport/Map: 1F680-1F6FF, Supplemental: 1F900-1F9FF, Symbols/Pictographs: 1F300-1F5FF, 1FA70-1FAFF
emoji_pattern = re.compile(
    r'['
    r'\U0001f600-\U0001f64f'  # emoticons
    r'\U0001f300-\U0001f5ff'  # symbols & pictographs
    r'\U0001f680-\U0001f6ff'  # transport & map symbols
    r'\U0001f1e0-\U0001f1ff'  # flags (iOS)
    r'\U0001f900-\U0001f9ff'  # supplemental emojis
    r'\U0001fa70-\U0001faff'  # symbols and pictographs extended-a
    r'\u2600-\u26ff'          # misc symbols
    r'\u2700-\u27bf'          # dingbats
    r'\u2b50'                 # star
    r'\u2b55'                 # heavy large circle
    r'\u23f0-\u23f3'          # clocks
    r'\u23e9-\u23ef'          # media controls
    r'\u25b6\u25c0'           # play/reverse
    r'\u231a\u231b'           # watches
    r'\u2122\u00a9\u00ae'     # tm, c, r
    r'\u203c\u2049'           # double exclamation, exclamation question
    r'\u2753-\u2755'          # questions/exclamations
    r'\u2757'                 # heavy exclamation
    r'\u2139'                 # information
    r'\u2194-\u2199'          # arrows
    r'\u21a9-\u21aa'          # arrows
    r'\u2934-\u2935'          # arrows
    r'\u3297\u3299'           # circled ideographs
    r'\u24c2'                 # circled M
    r'\U0001f004'             # mahjong
    r'\U0001f0cf'             # joker
    r'\U0001f170-\U0001f171'  # a/b blood type
    r'\U0001f17e-\U0001f17f'  # o/p blood type
    r'\U0001f18e'             # ab blood type
    r'\U0001f191-\U0001f19a'  # squared words
    r'\U0001f201-\U0001f202'  # squared katakana
    r'\U0001f21a'             # squared cjk
    r'\U0001f22f'             # squared cjk
    r'\U0001f232-\U0001f23a'  # squared cjk
    r'\U0001f250-\U0001f251'  # circular cjk
    r'\u25aa-\u25ab'          # small squares
    r'\u25fb-\u25fe'          # medium squares
    r']+', flags=re.UNICODE)

text = emoji_pattern.sub('', text)

# Also remove the variation selector 16 which often turns text to emoji
text = text.replace('\ufe0f', '')

with open('frontend/src/App.jsx', 'w', encoding='utf-8') as f:
    f.write(text)

print('Emoji replacements complete!')
