import React, { useState } from 'react';
import { detectToolInCommand } from '../utils/toolDetection';

const CommandBlock = ({ command, binaryContext }) => {
  const [copied, setCopied] = useState(false);
  const [explaining, setExplaining] = useState(false);
  const [explanation, setExplanation] = useState(null);
  const [installCopied, setInstallCopied] = useState(false);

  const toolInfo = detectToolInCommand(command);

  const handleCopy = async () => {
    await navigator.clipboard.writeText(command);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleInstallCopy = async () => {
    if (!toolInfo) return;
    await navigator.clipboard.writeText(toolInfo.installCmd);
    setInstallCopied(true);
    setTimeout(() => setInstallCopied(false), 2000);
  };

  const handleExplain = async () => {
    if (explanation) { setExplanation(null); return; }
    setExplaining(true);
    try {
      const backendUrl = import.meta.env.VITE_BACKEND_URL || 'http://localhost:8000';
      const res = await fetch(`${backendUrl}/explain-command`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ command, binary_context: binaryContext })
      });
      const data = await res.json();
      setExplanation(data.explanation || data.response || 'No explanation available');
    } catch {
      setExplanation('Could not fetch explanation. Check your connection.');
    } finally {
      setExplaining(false);
    }
  };

  const styles = {
    block: {
      background: '#0d1117', border: '1px solid #30363d',
      borderRadius: '8px', margin: '8px 0', overflow: 'hidden',
      fontFamily: "'JetBrains Mono', 'Fira Code', 'Courier New', monospace"
    },
    commandLine: {
      display: 'flex', alignItems: 'center', padding: '10px 14px',
      gap: '10px', background: '#161b22'
    },
    prompt: { color: '#7ee787', fontWeight: 'bold', fontSize: '14px', flexShrink: 0 },
    commandText: { flex: 1, color: '#e6edf3', fontSize: '13px', wordBreak: 'break-all' },
    actions: { display: 'flex', gap: '6px', flexShrink: 0 },
    btn: {
      padding: '4px 10px', borderRadius: '5px', border: '1px solid #30363d',
      background: '#21262d', color: '#8b949e', fontSize: '12px',
      cursor: 'pointer', whiteSpace: 'nowrap', fontFamily: 'inherit'
    },
    installBar: {
      display: 'flex', alignItems: 'center', gap: '8px',
      padding: '6px 14px', background: '#1a1200',
      borderTop: '1px solid #30363d', fontSize: '12px'
    },
    explanationPanel: {
      padding: '16px', background: '#0d1117', borderTop: '1px solid #30363d'
    }
  };

  // Split explanation into clean lines/sentences for readability
  const renderExplanation = (text) => {
    if (!text) return null;
    // Split by newline first, then by sentence-ending period+space within a line
    const lines = text.split('\n').flatMap(line => {
      const trimmed = line.trim();
      if (!trimmed) return [];
      // Split numbered list items like "1. ... 2. ..."
      const numSplit = trimmed.split(/(?=\d+\.\s)/);
      if (numSplit.length > 1) return numSplit.map(s => s.trim()).filter(Boolean);
      return [trimmed];
    });

    return lines.map((line, i) => {
      const trimmed = line.trim();
      if (!trimmed) return null;
      const isNumbered = /^\d+\./.test(trimmed);
      const isBullet = /^[•\-\+\*]/.test(trimmed);
      const isSubBullet = /^\s+[•\-\+]/.test(line);
      return (
        <div key={i} style={{
          display: 'flex', gap: '8px', alignItems: 'flex-start',
          marginBottom: '8px',
          paddingLeft: isSubBullet ? '16px' : '0'
        }}>
          {(isNumbered || isBullet || isSubBullet) ? (
            <span style={{
              flexShrink: 0, color: '#58a6ff',
              fontSize: '12px', marginTop: '2px', minWidth: '16px'
            }}>
              {isNumbered ? trimmed.match(/^\d+/)[0] + '.' : '•'}
            </span>
          ) : (
            <span style={{ flexShrink: 0, color: '#388bfd', fontSize: '14px', marginTop: '1px' }}>›</span>
          )}
          <span style={{ color: '#c9d1d9', fontSize: '13px', lineHeight: '1.6' }}>
            {isNumbered ? trimmed.replace(/^\d+\.\s*/, '') : isBullet ? trimmed.slice(1).trim() : trimmed}
          </span>
        </div>
      );
    }).filter(Boolean);
  };

  return (
    <div style={styles.block}>
      <div style={styles.commandLine}>
        <span style={styles.prompt}>$</span>
        <code style={styles.commandText}>{command}</code>
        <div style={styles.actions}>
          <button style={{
            ...styles.btn,
            ...(copied ? {background: '#1a3a1a', color: '#7ee787', borderColor: '#3fb950'} : {})
          }} onClick={handleCopy}>
            {copied ? '✓ Copied' : '⎘ Copy'}
          </button>
          <button style={{
            ...styles.btn,
            ...(explanation ? {background: '#1c2d4a', color: '#79c0ff', borderColor: '#388bfd'} : {})
          }} onClick={handleExplain} disabled={explaining}>
            {explaining ? '⟳ ...' : explanation ? '✕ Close' : '? Explain'}
          </button>
        </div>
      </div>

      {toolInfo && (
        <div style={styles.installBar}>
          <span style={{color: '#e3b341'}}>⬇</span>
          <span style={{color: '#8b949e', flex: 1}}>
            Requires <strong style={{color: '#e3b341'}}>{toolInfo.tool}</strong>
          </span>
          <button style={{
            ...styles.btn, background: '#1c1a00', borderColor: '#9e6a03', color: '#e3b341',
            ...(installCopied ? {background: '#0d1a0d', color: '#7ee787'} : {})
          }} onClick={handleInstallCopy}>
            {installCopied ? '✓ Copied' : '⎘ Copy Install'}
          </button>
        </div>
      )}

      {explanation && (
        <div style={styles.explanationPanel}>
          <div style={{
            fontSize: '10px', color: '#58a6ff', marginBottom: '12px',
            textTransform: 'uppercase', letterSpacing: '0.1em', fontWeight: 700,
            display: 'flex', alignItems: 'center', gap: '6px'
          }}>
            <span>💡</span> Command Breakdown
          </div>
          <div style={{ display: 'flex', flexDirection: 'column' }}>
            {renderExplanation(explanation)}
          </div>
        </div>
      )}
    </div>
  );
};

export default CommandBlock;

