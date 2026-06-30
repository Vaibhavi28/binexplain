import React, { useState } from 'react';
import CommandDiagram from './CommandDiagram';

const BACKEND_URL = import.meta.env.VITE_BACKEND_URL || 'http://localhost:8000';

export default function CommandBlock({ command, language, binaryContext }) {
  const [copied, setCopied] = useState(false);
  const [explanation, setExplanation] = useState(null);
  const [loading, setLoading] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(command);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleExplain = async () => {
    if (loading) return;
    setLoading(true);
    try {
      const res = await fetch(`${BACKEND_URL}/explain-command`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          command: command,
          binary_context: binaryContext || {},
        }),
      });
      if (res.ok) {
        const data = await res.json();
        setExplanation(data.explanation);
      } else {
        setExplanation("Error: Could not retrieve explanation.");
      }
    } catch (err) {
      setExplanation("Error: Network failure.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="chat-code-block" style={{ marginBottom: '12px', width: '100%' }}>
      <div className="chat-code-header">
        {language && <span className="chat-code-lang">{language}</span>}
        <div style={{ display: 'flex', gap: '8px' }}>
          <button 
            className="chat-code-copy-btn" 
            onClick={handleExplain} 
            type="button" 
            title="Explain command"
            disabled={loading}
          >
            {loading ? '...' : '\u2753 Explain'}
          </button>
          <button className="chat-code-copy-btn" onClick={handleCopy} type="button" title="Copy code">
            {copied ? '\u2713 Copied!' : '\ud83d\udccb Copy'}
          </button>
        </div>
      </div>
      <pre className="chat-code-pre"><code>{command}</code></pre>
      {explanation && (
        <div style={{ borderTop: '1px solid #30363d' }}>
          <CommandDiagram explanation={explanation} rawCommand={command} />
        </div>
      )}
    </div>
  );
}
