import React, { useState } from 'react';

export default function CTFOrientation() {
  const [dismissed, setDismissed] = useState(() => {
    if (typeof window !== 'undefined') {
      return localStorage.getItem('ctf_orientation_seen') === '1';
    }
    return false;
  });

  if (dismissed) return null;

  const handleDismiss = () => {
    localStorage.setItem('ctf_orientation_seen', '1');
    setDismissed(true);
  };

  return (
    <div style={{
      background: 'rgba(56, 139, 253, 0.08)',
      border: '1px solid #388bfd',
      borderRadius: '12px',
      padding: '28px',
      marginBottom: '32px',
      color: '#c9d1d9',
      boxShadow: '0 4px 20px rgba(0, 0, 0, 0.25)',
      fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif'
    }}>
      <h3 style={{
        margin: '0 0 16px',
        fontSize: '18px',
        fontWeight: 700,
        color: '#f0f6fc',
        textAlign: 'center'
      }}>
        🏁 Welcome to BinExplain! Quick 30-Second Orientation
      </h3>

      {/* 3 Cards Container */}
      <div style={{
        display: 'flex',
        gap: '20px',
        flexWrap: 'wrap',
        marginBottom: '24px'
      }}>
        {/* Card 1 */}
        <div style={{
          flex: '1 1 220px',
          background: '#0d1117',
          border: '1px solid #30363d',
          borderRadius: '8px',
          padding: '20px',
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          textAlign: 'center'
        }}>
          <span style={{ fontSize: '28px', marginBottom: '12px' }}>🚩</span>
          <h4 style={{ margin: '0 0 8px', fontSize: '14px', fontWeight: 700, color: '#f0f6fc' }}>
            What is a CTF?
          </h4>
          <p style={{ margin: 0, fontSize: '13px', lineHeight: '1.5', color: '#8b949e' }}>
            CTF stands for Capture The Flag. It is a cybersecurity competition where participants solve security puzzles called challenges. 
            Each challenge has a hidden text called a "flag" (like <code>flag&#123;example&#125;</code>) that you submit to score points. 
            This tool helps you with the "binary exploitation" (pwn) category.
          </p>
        </div>

        {/* Card 2 */}
        <div style={{
          flex: '1 1 220px',
          background: '#0d1117',
          border: '1px solid #30363d',
          borderRadius: '8px',
          padding: '20px',
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          textAlign: 'center'
        }}>
          <span style={{ fontSize: '28px', marginBottom: '12px' }}>🔍</span>
          <h4 style={{ margin: '0 0 8px', fontSize: '14px', fontWeight: 700, color: '#f0f6fc' }}>
            What is binary exploitation?
          </h4>
          <p style={{ margin: 0, fontSize: '13px', lineHeight: '1.5', color: '#8b949e' }}>
            Binary exploitation means finding and using security bugs in compiled programs ("binaries"). 
            When software has bugs, attackers can sometimes trick the program into doing things it was not supposed to do 
            — like opening a terminal shell or printing a secret flag. This is called exploiting a "vulnerability".
          </p>
        </div>

        {/* Card 3 */}
        <div style={{
          flex: '1 1 220px',
          background: '#0d1117',
          border: '1px solid #30363d',
          borderRadius: '8px',
          padding: '20px',
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          textAlign: 'center'
        }}>
          <span style={{ fontSize: '28px', marginBottom: '12px' }}>🤖</span>
          <h4 style={{ margin: '0 0 8px', fontSize: '14px', fontWeight: 700, color: '#f0f6fc' }}>
            How does this tool help?
          </h4>
          <p style={{ margin: 0, fontSize: '13px', lineHeight: '1.5', color: '#8b949e' }}>
            Upload a binary file and BinExplain will: detect what type of vulnerability likely exists, 
            show you the program's security protections, generate a starting exploit script, 
            and give you AI-powered hints tailored to that specific binary. No guessing what to do first.
          </p>
        </div>
      </div>

      {/* Got it Button */}
      <div style={{ textAlign: 'center' }}>
        <button
          onClick={handleDismiss}
          style={{
            background: '#238636',
            border: '1px solid #2ea043',
            borderRadius: '6px',
            color: '#fff',
            padding: '12px 28px',
            fontSize: '14px',
            fontWeight: 600,
            cursor: 'pointer',
            boxShadow: '0 2px 6px rgba(35, 134, 54, 0.3)',
            transition: 'background 0.15s'
          }}
          onMouseEnter={(e) => { e.currentTarget.style.background = '#2ea043'; }}
          onMouseLeave={(e) => { e.currentTarget.style.background = '#238636'; }}
        >
          Got it — show me how binaries work →
        </button>
      </div>
    </div>
  );
}
