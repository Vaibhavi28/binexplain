export const parseAIResponse = (responseText) => {
  if (!responseText) return [];
  const segments = [];
  const codeBlockRegex = /```(\w*)\n?([\s\S]*?)```/g;
  let lastIndex = 0;
  let match;

  while ((match = codeBlockRegex.exec(responseText)) !== null) {
    if (match.index > lastIndex) {
      const prose = responseText.slice(lastIndex, match.index).trim();
      if (prose) segments.push({ type: 'prose', content: prose });
    }
    const language = (match[1] || 'bash').toLowerCase();
    const content = match[2].trim();
    if (['bash', 'sh', 'shell', ''].includes(language)) {
      const commands = content.split('\n')
        .map(l => l.trim())
        .filter(l => l && !l.startsWith('#'));
      commands.forEach(cmd => {
        if (cmd) segments.push({ type: 'command', content: cmd });
      });
    } else {
      segments.push({ type: 'code', content, language });
    }
    lastIndex = match.index + match[0].length;
  }
  if (lastIndex < responseText.length) {
    const prose = responseText.slice(lastIndex).trim();
    if (prose) segments.push({ type: 'prose', content: prose });
  }
  return segments;
};
