import React from 'react';

const TOKEN_COLORS = {
  program:  { bg: '#1c2d4a', border: '#388bfd', text: '#79c0ff' },
  flag:     { bg: '#2d1a4a', border: '#bc8cff', text: '#d2a8ff' },
  argument: { bg: '#1a3a1a', border: '#3fb950', text: '#7ee787' },
  pipe:     { bg: '#3a2a1a', border: '#e3b341', text: '#e3b341' },
  operator: { bg: '#3a2a1a', border: '#e3b341', text: '#e3b341' },
};

const CommandDiagram = ({ explanation, rawCommand }) => {
  if (!explanation || !explanation.tokens) {
    return (
      <div style={{padding: '12px', color: '#8b949e', fontSize: '13px'}}>
        {typeof explanation === 'string' ? explanation : 'No breakdown available'}
      </div>
    );
  }

  const { tokens, summary, expected_output, ctf_relevance } = explanation;

  return (
    <div style={{padding: '16px', background: '#0d1117'}}>
      <div style={{
        fontSize: '11px', color: '#8b949e', textTransform: 'uppercase',
        letterSpacing: '0.08em', marginBottom: '14px', fontWeight: 600
      }}>
        Command Breakdown
      </div>

      {/* Token row — the command split into colored highlighted pieces */}
      <div style={{
        display: 'flex', flexWrap: 'wrap', gap: '4px', marginBottom: '20px',
        fontFamily: "'JetBrains Mono', monospace", fontSize: '14px'
      }}>
        {tokens.map((tok, i) => {
          const colors = TOKEN_COLORS[tok.type] || TOKEN_COLORS.argument;
          return (
            <span key={i} style={{
              background: colors.bg, border: `1px solid ${colors.border}`,
              color: colors.text, padding: '4px 8px', borderRadius: '4px',
              position: 'relative'
            }}>
              {tok.text}
            </span>
          );
        })}
      </div>

      {/* Vertical connector lines down to explanation cards */}
      <div style={{
        display: 'flex', flexWrap: 'wrap', gap: '8px', marginBottom: '16px'
      }}>
        {tokens.map((tok, i) => {
          const colors = TOKEN_COLORS[tok.type] || TOKEN_COLORS.argument;
          return (
            <div key={i} style={{
              display: 'flex', flexDirection: 'column', alignItems: 'flex-start',
              minWidth: '140px', maxWidth: '220px'
            }}>
              <div style={{
                width: '2px', height: '14px', background: colors.border,
                marginLeft: '10px'
              }} />
              <div style={{
                background: '#161b22', border: `1px solid ${colors.border}`,
                borderRadius: '6px', padding: '8px 10px', width: '100%'
              }}>
                <code style={{color: colors.text, fontSize: '12px', display: 'block', marginBottom: '4px'}}>
                  {tok.text}
                </code>
                <span style={{color: '#c9d1d9', fontSize: '11px', lineHeight: '1.4'}}>
                  {tok.meaning}
                </span>
              </div>
            </div>
          );
        })}
      </div>

      {/* Summary sections */}
      {summary && (
        <div style={{marginBottom: '10px'}}>
          <div style={{fontSize: '11px', color: '#8b949e', fontWeight: 600, marginBottom: '3px'}}>
            ▶ WHAT THIS DOES
          </div>
          <p style={{color: '#c9d1d9', fontSize: '13px', margin: 0, lineHeight: '1.5'}}>{summary}</p>
        </div>
      )}
      {expected_output && (
        <div style={{marginBottom: '10px'}}>
          <div style={{fontSize: '11px', color: '#8b949e', fontWeight: 600, marginBottom: '3px'}}>
            📤 EXPECTED OUTPUT
          </div>
          <p style={{color: '#c9d1d9', fontSize: '13px', margin: 0, lineHeight: '1.5'}}>{expected_output}</p>
        </div>
      )}
      {ctf_relevance && (
        <div>
          <div style={{fontSize: '11px', color: '#8b949e', fontWeight: 600, marginBottom: '3px'}}>
            🚩 CTF RELEVANCE
          </div>
          <p style={{color: '#c9d1d9', fontSize: '13px', margin: 0, lineHeight: '1.5'}}>{ctf_relevance}</p>
        </div>
      )}
    </div>
  );
};

export default CommandDiagram;
