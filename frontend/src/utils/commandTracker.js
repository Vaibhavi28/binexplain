export const extractCommandsFromHistory = (chatHistory) => {
  const commands = new Set();
  chatHistory.forEach(msg => {
    if (msg.role === "assistant") {
      const bashBlockRegex = /```(?:bash|sh|shell)\n?([\s\S]*?)```/g;
      let match;
      while ((match = bashBlockRegex.exec(msg.content)) !== null) {
        const lines = match[1].trim().split('\n');
        lines.forEach(line => {
          const trimmed = line.trim();
          if (trimmed && !trimmed.startsWith('#')) commands.add(trimmed);
        });
      }
    }
  });
  return Array.from(commands);
};

export const extractFailedCommands = (chatHistory) => {
  const failedIndicators = [
    "didn't work", "didnt work", "not working", "doesn't work",
    "nothing happened", "still stuck", "same error", "failed",
    "no output", "command not found", "useless", "wrong", "that didn't help"
  ];
  const failed = new Set();
  for (let i = 1; i < chatHistory.length; i++) {
    const msg = chatHistory[i];
    const prevMsg = chatHistory[i - 1];
    if (msg.role === "user" && prevMsg.role === "assistant") {
      const userLower = msg.content.toLowerCase();
      if (failedIndicators.some(ind => userLower.includes(ind))) {
        extractCommandsFromHistory([prevMsg]).forEach(c => failed.add(c));
      }
    }
  }
  return Array.from(failed);
};
