import React, { useState } from 'react';

const BACKEND_URL = import.meta.env.VITE_BACKEND_URL || 'http://localhost:8000';

const CARDS = [
  {
    id: 'ret2win',
    title: 'ret2win',
    difficulty: 'Easy',
    difficultyColor: { bg: '#162c1e', border: '#2ea043', text: '#56d364' },
    desc: 'Find a picoCTF binary exploitation challenge rated Easy. Look for challenges named \'buffer overflow\', \'vuln\', or \'get it\'.',
    where: 'picoCTF.org → Binary Exploitation → Easy',
    checklist: [
      'CTF Category: ret2win (High confidence)',
      'Win function detected in symbol table',
      'Overflow offset predicted from disassembly',
      'Pwntools template pre-populated with win address'
    ]
  },
  {
    id: 'format_string',
    title: 'format_string',
    difficulty: 'Easy/Medium',
    difficultyColor: { bg: '#382a17', border: '#d29922', text: '#f0e042' },
    desc: 'Look for CTF binaries that print your input back to you. Test manually: python3 -c \'print("%p")\' | ./binary. If you see 0x... in the output, it is vulnerable.',
    where: 'CTFtime.org → filter by pwn → look for format string tag',
    checklist: [
      'CTF Category: format_string',
      'printf() without format argument detected',
      'Similar writeups from knowledge base',
      'fmtstr_payload usage in AI hints'
    ]
  },
  {
    id: 'heap_exploitation',
    title: 'heap_exploitation',
    difficulty: 'Hard',
    difficultyColor: { bg: '#3c1e1e', border: '#f85149', text: '#ff7b72' },
    desc: 'Look for binaries with a menu (1. Add, 2. Delete, 3. Edit). Menu-driven heap challenges are very common.',
    where: 'HackTheBox → Challenges → Pwn → Medium/Hard',
    checklist: [
      'CTF Category: heap_exploitation',
      'Heap functions detected (malloc/free)',
      'Menu structure detected in strings',
      'AI hints reference specific heap technique'
    ],
    hasDemoPath: '/demos/schooled',
    demoName: 'schooled',
    demoSource: 'MetaCTF Flash CTF — "Schooled"',
    demoLicense: 'Public CTF challenge, freely distributable'
  },
  {
    id: 'ret2libc',
    title: 'ret2libc',
    difficulty: 'Medium',
    difficultyColor: { bg: '#382a17', border: '#d29922', text: '#f0e042' },
    desc: 'Look for binaries with NX enabled but no stack canary. Run checksec first — if NX=Enabled and Canary=No, this is likely.',
    where: 'picoCTF → Binary Exploitation → Medium',
    checklist: [
      'CTF Category: ret2libc',
      'Libc version identified',
      'PLT/GOT table extracted',
      'Pwntools template with libc leak scaffold'
    ]
  },
  {
    id: 'rop_chain',
    title: 'rop_chain',
    difficulty: 'Medium/Hard',
    difficultyColor: { bg: '#3c1e1e', border: '#f85149', text: '#ff7b72' },
    desc: 'Look for binaries with NX enabled AND a stack canary. Full protection binaries almost always require ROP.',
    where: 'CTFtime.org → pwn → filter for harder challenges',
    checklist: [
      'CTF Category: rop_chain',
      'ROP gadgets detected with addresses',
      'pop rdi gadget highlighted if present',
      'Pwntools template with gadget addresses'
    ]
  },
  {
    id: 'shellcode',
    title: 'shellcode',
    difficulty: 'Easy (with older binaries)',
    difficultyColor: { bg: '#162c1e', border: '#2ea043', text: '#56d364' },
    desc: 'Look for old CTF binaries (pre-2015) or challenges specifically marked as NX disabled. These are rare in modern CTFs.',
    where: 'picoCTF older archives, Pwnable.kr',
    checklist: [
      'CTF Category: shellcode',
      'NX: Disabled shown in checksec',
      'shellcraft.sh() mentioned in AI hints'
    ]
  }
];

export default function TryItYourself({ onSectionChange }) {
  const [loading, setLoading] = useState(false);
  const [loadingMsg, setLoadingMsg] = useState('');
  const [analysisData, setAnalysisData] = useState(null);
  const [error, setError] = useState(null);
  const [expandedSteps, setExpandedSteps] = useState({});

  const [demoLoading, setDemoLoading] = useState(null);
  const [demoResult, setDemoResult] = useState(null);
  const [demoError, setDemoError] = useState(null);

  const handleAnalyzeDemo = async (demoName) => {
    setDemoLoading(demoName);
    setDemoResult(null);
    setDemoError(null);
    try {
      const backendUrl = import.meta.env.VITE_BACKEND_URL || 'http://localhost:8000';
      const resp = await fetch(`${backendUrl}/demo-analysis/${demoName}`);
      if (!resp.ok) throw new Error(`Status ${resp.status}`);
      const data = await resp.json();
      setDemoResult(data);
    } catch (err) {
      setDemoError('Could not load demo analysis. Is the backend running?');
    } finally {
      setDemoLoading(null);
    }
  };

  const handleAnalyzeRet2winDemo = async (cardId) => {
    setLoading(true);
    setLoadingMsg(`Analyzing demo_${cardId}...`);
    setError(null);
    setAnalysisData(null);
    setExpandedSteps({});
    try {
      const res = await fetch(`${BACKEND_URL}/demo-analysis/demo_${cardId}`);
      if (!res.ok) {
        throw new Error(`Demo analysis failed with status: ${res.status}`);
      }
      const data = await res.json();
      setAnalysisData(data);
    } catch (err) {
      console.error('[TryItYourself] Error analyzing demo:', err);
      setError(err.message || 'Failed to fetch demo analysis');
    } finally {
      setLoading(false);
    }
  };

  const toggleStep = (stepNum) => {
    setExpandedSteps(prev => ({
      ...prev,
      [stepNum]: !prev[stepNum]
    }));
  };

  return (
    <div style={{ maxWidth: '100%', margin: '0 auto' }}>
      <h2 style={{ color: 'var(--text-primary)', fontSize: '20px',
        fontWeight: 600, marginBottom: '8px', textAlign: 'center' }}>
        Practice Challenges & Targets
      </h2>
      <p style={{ color: 'var(--text-secondary)', fontSize: '14px',
        textAlign: 'center', marginBottom: '32px' }}>
        Ready to take what you have learned and apply it to a real binary? Choose a target, download a challenge, and run it through the BinExplain analyser.
      </p>

      {/* Grid of 6 Challenge Cards */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))',
        gap: '20px',
        marginBottom: '48px'
      }}>
        {CARDS.map((c) => (
          <div
            key={c.id}
            style={{
              background: '#161b22',
              border: '1px solid #30363d',
              borderRadius: '10px',
              padding: '24px',
              display: 'flex',
              flexDirection: 'column',
              justifyContent: 'space-between',
              minHeight: '340px',
              transition: 'transform 0.15s, border-color 0.15s, box-shadow 0.15s'
            }}
            onMouseEnter={(e) => {
              e.currentTarget.style.transform = 'translateY(-2px)';
              e.currentTarget.style.borderColor = '#388bfd';
              e.currentTarget.style.boxShadow = '0 4px 12px rgba(56, 139, 253, 0.1)';
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.transform = 'translateY(0)';
              e.currentTarget.style.borderColor = '#30363d';
              e.currentTarget.style.boxShadow = 'none';
            }}
          >
            <div>
              {/* Header */}
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
                <h3 style={{ margin: 0, fontSize: '16px', fontWeight: 700, color: '#f0f6fc', fontFamily: 'monospace' }}>
                  {c.title}
                </h3>
                <span style={{
                  fontSize: '9px',
                  fontWeight: 700,
                  padding: '2px 6px',
                  borderRadius: '4px',
                  background: c.difficultyColor.bg,
                  border: `1px solid ${c.difficultyColor.border}`,
                  color: c.difficultyColor.text,
                  textTransform: 'uppercase'
                }}>
                  {c.difficulty}
                </span>
              </div>

              {/* Description */}
              <p style={{ color: '#c9d1d9', fontSize: '14px', lineHeight: '1.5', margin: '0 0 16px' }}>
                {c.desc}
              </p>

              {/* Source/Find */}
              <div style={{ marginBottom: '20px' }}>
                <div style={{ fontSize: '10px', color: '#8b949e', textTransform: 'uppercase', fontWeight: 700, marginBottom: '4px' }}>
                  Where to find
                </div>
                <div style={{ color: '#58a6ff', fontSize: '12px', fontWeight: 500 }}>
                  {c.where}
                </div>
              </div>

              {/* Checklist */}
              <div style={{ marginBottom: '24px' }}>
                <div style={{ fontSize: '10px', color: '#8b949e', textTransform: 'uppercase', fontWeight: 700, marginBottom: '6px' }}>
                  What BinExplain finds
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                  {c.checklist.map((item, idx) => (
                    <div key={idx} style={{ display: 'flex', alignItems: 'flex-start', gap: '8px', fontSize: '11px', color: '#c9d1d9' }}>
                      <span style={{ color: '#56d364', fontWeight: 'bold' }}>✓</span>
                      <span>{item}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* Action */}
            {c.id === 'ret2win' ? (
              <button
                onClick={() => handleAnalyzeRet2winDemo(c.id)}
                style={{
                  display: 'block',
                  width: '100%',
                  padding: '10px 14px',
                  background: '#238636',
                  border: '1px solid #2ea043',
                  borderRadius: '6px',
                  color: '#fff',
                  fontSize: '14px',
                  fontWeight: 600,
                  textAlign: 'center',
                  cursor: 'pointer',
                  transition: 'all 0.15s'
                }}
                onMouseEnter={(e) => { e.currentTarget.style.background = '#2ea043'; }}
                onMouseLeave={(e) => { e.currentTarget.style.background = '#238636'; }}
              >
                Analyze demo binary →
              </button>
            ) : c.hasDemoPath ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', width: '100%' }}>
                <div style={{
                  padding: '14px',
                  border: '1px solid #388bfd',
                  borderRadius: '8px',
                  background: '#1c2d4a22',
                  textAlign: 'left'
                }}>
                  <div style={{ fontSize: '12px', color: '#8b949e', marginBottom: '10px' }}>
                    <strong style={{ color: '#79c0ff' }}>Demo binary available</strong>
                    {' — '}{c.demoSource}
                    <span style={{ marginLeft: '8px', fontSize: '11px',
                      color: '#484f58', fontStyle: 'italic' }}>
                      ({c.demoLicense})
                    </span>
                  </div>
                  <button
                    onClick={() => handleAnalyzeDemo(c.demoName)}
                    disabled={demoLoading === c.demoName}
                    style={{
                      width: '100%', padding: '10px', borderRadius: '6px',
                      fontSize: '13px', fontWeight: 600,
                      cursor: demoLoading === c.demoName ? 'not-allowed' : 'pointer',
                      background: demoLoading === c.demoName ? '#21262d' : '#238636',
                      border: '1px solid #2ea043', color: 'white',
                      opacity: demoLoading === c.demoName ? 0.6 : 1,
                    }}
                  >
                    {demoLoading === c.demoName
                      ? 'Loading analysis...'
                      : `▶ Analyze ${c.demoName} — see BinExplain in action`}
                  </button>
                </div>
                {demoResult && demoResult.demoName === c.demoName && (
                  <DemoResultPanel result={demoResult} />
                )}
                {demoError && demoLoading !== c.demoName && (
                  <div style={{ color: '#ff7b72', fontSize: '12px', marginTop: '8px' }}>{demoError}</div>
                )}
                <a
                  href="/"
                  style={{
                    display: 'block',
                    padding: '8px 12px',
                    background: 'transparent',
                    border: '1px solid #30363d',
                    borderRadius: '6px',
                    color: '#58a6ff',
                    textDecoration: 'none',
                    fontSize: '13px',
                    fontWeight: 500,
                    textAlign: 'center',
                    transition: 'background 0.15s'
                  }}
                  onMouseEnter={(e) => { e.currentTarget.style.background = 'rgba(56, 139, 253, 0.1)'; }}
                  onMouseLeave={(e) => { e.currentTarget.style.background = 'transparent'; }}
                >
                  Try your own binary → upload it to BinExplain
                </a>
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                <button
                  disabled
                  style={{
                    display: 'block',
                    width: '100%',
                    padding: '10px 14px',
                    background: '#21262d',
                    border: '1px solid #30363d',
                    borderRadius: '6px',
                    color: '#8b949e',
                    fontSize: '14px',
                    fontWeight: 600,
                    textAlign: 'center',
                    cursor: 'not-allowed'
                  }}
                >
                  Demo coming soon
                </button>
                <a
                  href="/"
                  style={{
                    display: 'block',
                    padding: '8px 12px',
                    background: 'transparent',
                    border: '1px solid #30363d',
                    borderRadius: '6px',
                    color: '#58a6ff',
                    textDecoration: 'none',
                    fontSize: '13px',
                    fontWeight: 500,
                    textAlign: 'center',
                    transition: 'background 0.15s'
                  }}
                  onMouseEnter={(e) => { e.currentTarget.style.background = 'rgba(56, 139, 253, 0.1)'; }}
                  onMouseLeave={(e) => { e.currentTarget.style.background = 'transparent'; }}
                >
                  Try your own binary → upload it to BinExplain
                </a>
              </div>
            )}
          </div>
        ))}
      </div>

      {/* Loading state */}
      {loading && (
        <div style={{
          marginTop: '32px',
          marginBottom: '32px',
          padding: '32px',
          background: '#161b22',
          border: '1px solid #30363d',
          borderRadius: '12px',
          textAlign: 'center',
          color: '#c9d1d9'
        }}>
          <div className="spinner" style={{
            margin: '0 auto 16px',
            width: '40px',
            height: '40px',
            border: '4px solid rgba(56, 139, 253, 0.2)',
            borderTop: '4px solid #388bfd',
            borderRadius: '50%',
            animation: 'spin 1s linear infinite'
          }} />
          <style>{`
            @keyframes spin {
              0% { transform: rotate(0deg); }
              100% { transform: rotate(360deg); }
            }
          `}</style>
          <p style={{ margin: 0, fontSize: '15px', fontWeight: 600 }}>{loadingMsg}</p>
        </div>
      )}

      {/* Error state */}
      {error && (
        <div style={{
          marginTop: '32px',
          marginBottom: '32px',
          padding: '24px',
          background: '#442323',
          border: '1px solid #f85149',
          borderRadius: '12px',
          color: '#ff7b72',
          textAlign: 'center'
        }}>
          <p style={{ margin: 0, fontSize: '15px', fontWeight: 600 }}>{error}</p>
        </div>
      )}

      {/* Walkthrough Panel */}
      {analysisData && (
        <div style={{
          marginTop: '32px',
          marginBottom: '48px',
          padding: '32px',
          background: '#161b22',
          border: '1px solid #30363d',
          borderRadius: '12px',
          boxShadow: '0 8px 32px rgba(0, 0, 0, 0.4)'
        }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '24px', flexWrap: 'wrap', gap: '16px' }}>
            <div>
              <h3 style={{ margin: 0, fontSize: '22px', color: '#f0f6fc', fontWeight: 700 }}>
                Analysis Results: <code style={{ color: '#58a6ff' }}>{analysisData.filename}</code>
              </h3>
              <p style={{ margin: '4px 0 0', color: '#8b949e', fontSize: '14px' }}>
                Architecture: {analysisData.architecture} ({analysisData.bits}-bit) | CTF Category: {analysisData.ctf_category.category} ({analysisData.ctf_category.confidence} confidence)
              </p>
            </div>
            
            {/* Protections Badges */}
            <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
              <span style={{ padding: '4px 8px', borderRadius: '4px', fontSize: '11px', fontWeight: 700, background: '#442323', border: '1px solid #f85149', color: '#ff7b72', textTransform: 'uppercase' }}>NX Enabled</span>
              <span style={{ padding: '4px 8px', borderRadius: '4px', fontSize: '11px', fontWeight: 700, background: '#162c1e', border: '1px solid #2ea043', color: '#56d364', textTransform: 'uppercase' }}>PIE Disabled</span>
              <span style={{ padding: '4px 8px', borderRadius: '4px', fontSize: '11px', fontWeight: 700, background: '#162c1e', border: '1px solid #2ea043', color: '#56d364', textTransform: 'uppercase' }}>No Canary</span>
              <span style={{ padding: '4px 8px', borderRadius: '4px', fontSize: '11px', fontWeight: 700, background: '#382a17', border: '1px solid #d29922', color: '#f0e042', textTransform: 'uppercase' }}>Partial RELRO</span>
            </div>
          </div>
          
          {/* AI Hints Section */}
          <div style={{
            background: 'rgba(56, 139, 253, 0.08)',
            border: '1px solid #388bfd',
            borderRadius: '8px',
            padding: '16px',
            marginBottom: '24px',
            display: 'flex',
            gap: '12px'
          }}>
            <span style={{ fontSize: '20px' }}>🤖</span>
            <div>
              <h4 style={{ margin: '0 0 6px', color: '#58a6ff', fontSize: '14px', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.05em' }}>AI Exploit Hint</h4>
              <p style={{ margin: 0, color: '#c9d1d9', fontSize: '14px', lineHeight: '1.6' }}>
                {analysisData.ai_hints}
              </p>
            </div>
          </div>
          
          {/* Plain English Accordion Walkthrough */}
          <h4 style={{ color: '#f0f6fc', fontSize: '16px', fontWeight: 600, marginBottom: '16px' }}>Plain English Walkthrough</h4>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', marginBottom: '32px' }}>
            {analysisData.plain_english_walkthrough.map((step) => {
              const isOpen = !!expandedSteps[step.step];
              return (
                <div key={step.step} style={{ border: '1px solid #30363d', borderRadius: '8px', overflow: 'hidden' }}>
                  <button
                    onClick={() => toggleStep(step.step)}
                    style={{
                      width: '100%',
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'center',
                      padding: '16px 20px',
                      background: '#161b22',
                      border: 'none',
                      color: '#f0f6fc',
                      textAlign: 'left',
                      fontSize: '15px',
                      fontWeight: 600,
                      cursor: 'pointer'
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                      <span style={{
                        color: isOpen ? '#56d364' : '#8b949e',
                        fontWeight: 700
                      }}>
                        {isOpen ? '✓' : '○'} Step {step.step}:
                      </span>
                      <span>{step.title}</span>
                    </div>
                    <span style={{ color: '#8b949e' }}>{isOpen ? '▲' : '▼'}</span>
                  </button>
                  {isOpen && (
                    <div style={{ padding: '20px', background: '#0d1117', borderTop: '1px solid #30363d', color: '#c9d1d9', fontSize: '14px', lineHeight: '1.6' }}>
                      {step.content}
                    </div>
                  )}
                </div>
              );
            })}
          </div>

          {/* Pwntools Template */}
          <h4 style={{ color: '#f0f6fc', fontSize: '16px', fontWeight: 600, marginBottom: '12px' }}>Python Exploit Script (pwntools)</h4>
          <div style={{ position: 'relative', background: '#0d1117', border: '1px solid #30363d', borderRadius: '8px', padding: '16px', overflowX: 'auto' }}>
            <pre style={{ margin: 0, fontFamily: 'monospace', fontSize: '13px', color: '#c9d1d9', lineHeight: '1.5' }}>
              <code>{analysisData.pwntools_template}</code>
            </pre>
            <button
              onClick={() => {
                navigator.clipboard.writeText(analysisData.pwntools_template);
                alert("Copied to clipboard!");
              }}
              style={{
                position: 'absolute',
                top: '12px',
                right: '12px',
                padding: '6px 12px',
                background: '#21262d',
                border: '1px solid #30363d',
                borderRadius: '4px',
                color: '#c9d1d9',
                fontSize: '12px',
                fontWeight: 600,
                cursor: 'pointer'
              }}
            >
              Copy
            </button>
          </div>
        </div>
      )}

      {/* Bottom CTA Block */}
      <div style={{
        background: '#161b22',
        border: '1px solid #30363d',
        borderRadius: '12px',
        padding: '40px 24px',
        textAlign: 'center',
        boxShadow: '0 4px 20px rgba(0,0,0,0.2)',
        marginTop: '32px'
      }}>
        <h3 style={{ color: '#f0f6fc', fontSize: '22px', fontWeight: 700, margin: '0 0 12px' }}>
          Ready for your own binary?
        </h3>
        <p style={{ color: '#8b949e', fontSize: '14px', maxWidth: '500px', margin: '0 auto 24px', lineHeight: '1.5' }}>
          Drop your CTF executable or ZIP files containing binaries directly into our analysis suite to extract dynamic insights instantly.
        </p>

        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '16px' }}>
          <a
            href="/"
            style={{
              display: 'inline-block',
              padding: '12px 28px',
              background: '#238636',
              border: '1px solid #2ea043',
              color: '#fff',
              borderRadius: '8px',
              textDecoration: 'none',
              fontSize: '15px',
              fontWeight: 600,
              boxShadow: '0 2px 6px rgba(35, 134, 54, 0.3)',
              transition: 'background 0.15s'
            }}
            onMouseEnter={(e) => { e.currentTarget.style.background = '#2ea043'; }}
            onMouseLeave={(e) => { e.currentTarget.style.background = '#238636'; }}
          >
            Ready for your own binary? Use the full tool →
          </a>
          
          <span style={{ color: '#8b949e', fontSize: '12px', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
            or
          </span>

          <button
            onClick={() => {
              if (onSectionChange) {
                onSectionChange('flowchart');
              }
              window.scrollTo({ top: 0, behavior: 'smooth' });
            }}
            style={{
              background: 'none',
              border: 'none',
              color: '#58a6ff',
              fontSize: '14px',
              fontWeight: 600,
              cursor: 'pointer',
              textDecoration: 'underline',
              padding: '4px 8px'
            }}
          >
            Not sure where to start? Try the exploitation flowchart first →
          </button>
        </div>
      </div>
    </div>
  );
}

function DemoResultPanel({ result }) {
  const [expandedStep, setExpandedStep] = useState(null);

  return (
    <div style={{ marginTop: '16px' }}>
      {/* Header */}
      <div style={{
        display: 'flex', gap: '8px', flexWrap: 'wrap',
        marginBottom: '14px', alignItems: 'center',
      }}>
        <span style={{
          padding: '4px 10px', borderRadius: '12px', fontSize: '12px',
          background: '#1c2d4a', border: '1px solid #388bfd',
          color: '#79c0ff', fontWeight: 700,
        }}>
          {result.ctf_category?.category}
        </span>
        <span style={{
          padding: '4px 10px', borderRadius: '12px', fontSize: '12px',
          background: '#382a17', border: '1px solid #d29922', color: '#f0e042',
        }}>
          {result.difficulty}
        </span>
        {Object.entries(result.protections || {}).map(([k, v]) => (
          <span key={k} style={{
            padding: '3px 8px', borderRadius: '10px', fontSize: '11px',
            background: v === 'Enabled' || v === 'Full RELRO' ? '#3a0000' : '#162c1e',
            border: `1px solid ${v === 'Enabled' || v === 'Full RELRO' ? '#f85149' : '#3fb950'}`,
            color: v === 'Enabled' || v === 'Full RELRO' ? '#f85149' : '#56d364',
          }}>
            {k.toUpperCase()}: {v === 'Enabled' ? 'ON' : v === 'No' ? 'OFF' : v}
          </span>
        ))}
      </div>

      {/* AI Hints */}
      <div style={{
        background: '#161b22', border: '1px solid #30363d',
        borderRadius: '6px', padding: '12px 14px', marginBottom: '14px',
        fontSize: '13px', color: '#c9d1d9', lineHeight: '1.6',
        textAlign: 'left'
      }}>
        <div style={{ fontSize: '11px', color: '#8b949e', marginBottom: '6px',
          textTransform: 'uppercase', letterSpacing: '0.08em' }}>
          BinExplain AI Hints
        </div>
        {result.ai_hints}
      </div>

      {/* Walkthrough steps */}
      <div style={{ fontSize: '12px', color: '#8b949e', marginBottom: '10px',
        textTransform: 'uppercase', letterSpacing: '0.06em', textAlign: 'left' }}>
        Plain English Walkthrough
      </div>
      {(result.plain_english_walkthrough || []).map(step => (
        <div key={step.step} style={{ marginBottom: '6px' }}>
          <div
            onClick={() => setExpandedStep(expandedStep === step.step ? null : step.step)}
            style={{
              display: 'flex', justifyContent: 'space-between',
              padding: '10px 14px', cursor: 'pointer',
              background: expandedStep === step.step ? '#1c2d4a' : '#161b22',
              border: '1px solid #30363d',
              borderRadius: expandedStep === step.step ? '6px 6px 0 0' : '6px',
              textAlign: 'left'
            }}
          >
            <span style={{ color: '#c9d1d9', fontSize: '13px', fontWeight: 600 }}>
              Step {step.step}: {step.title}
            </span>
            <span style={{ color: '#8b949e' }}>
              {expandedStep === step.step ? '▲' : '▼'}
            </span>
          </div>
          {expandedStep === step.step && (
            <div style={{
              padding: '12px 14px', background: '#0d1117',
              border: '1px solid #30363d', borderTop: 'none',
              borderRadius: '0 0 6px 6px',
              fontSize: '13px', color: '#c9d1d9', lineHeight: '1.6',
              textAlign: 'left'
            }}>
              {step.content}
            </div>
          )}
        </div>
      ))}

      {/* Pwntools template */}
      {result.pwntools_template && (
        <div style={{ marginTop: '14px', textAlign: 'left' }}>
          <div style={{ fontSize: '12px', color: '#8b949e', marginBottom: '6px',
            textTransform: 'uppercase', letterSpacing: '0.06em' }}>
            Starter Exploit Script
          </div>
          <div style={{
            background: '#0d1117', border: '1px solid #30363d',
            borderRadius: '6px', padding: '12px 14px', position: 'relative',
          }}>
            <button
              onClick={() => {
                navigator.clipboard.writeText(result.pwntools_template);
                alert("Copied to clipboard!");
              }}
              style={{
                position: 'absolute', top: '8px', right: '8px',
                background: '#21262d', border: '1px solid #30363d',
                color: '#8b949e', borderRadius: '4px', padding: '2px 8px',
                fontSize: '11px', cursor: 'pointer',
              }}
            >⎘ Copy</button>
            <pre style={{ color: '#79c0ff', fontSize: '12px', margin: 0,
              whiteSpace: 'pre-wrap', fontFamily: 'monospace' }}>
              {result.pwntools_template}
            </pre>
          </div>
        </div>
      )}
    </div>
  );
}
