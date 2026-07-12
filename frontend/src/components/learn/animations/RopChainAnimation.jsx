import React, { useState, useRef, useEffect } from 'react';

const sleep = ms => new Promise(r => setTimeout(r, ms));

export default function RopChainAnimation() {
  const [phase, setPhase] = useState(0);
  const [activeGadget, setActiveGadget] = useState(-1);
  const [registers, setRegisters] = useState({ rdi: '???', rip: '???' });
  const [playing, setPlaying] = useState(false);
  const [termText, setTermText] = useState('');
  const cancelRef = useRef(false);
  const reducedMotion = useRef(
    typeof window !== 'undefined' &&
    window.matchMedia('(prefers-reduced-motion: reduce)').matches
  );

  const GADGETS = [
    { addr: '0x401234', asm: 'pop rdi ; ret', color: '#bc8cff',
      effect: 'RDI ← "/bin/sh" address', label: 'Gadget 1' },
    { addr: '0x7f...1b3e', asm: '/bin/sh string', color: '#3fb950',
      effect: 'RDI = 0x7fabc1b3e1a', label: 'Argument' },
    { addr: '0x7f...5229', asm: 'system()', color: '#f85149',
      effect: 'system("/bin/sh") called!', label: 'Target' },
  ];

  const resetAll = () => {
    cancelRef.current = true;
    setPhase(0); setActiveGadget(-1);
    setRegisters({ rdi: '???', rip: '???' });
    setPlaying(false); setTermText('');
    setTimeout(() => { cancelRef.current = false; }, 100);
  };

  const play = async () => {
    if (playing) return;
    resetAll();
    await sleep(60);
    cancelRef.current = false;
    setPlaying(true);

    if (reducedMotion.current) {
      setPhase(3); setActiveGadget(2);
      setRegisters({ rdi: '0x7fabc1b3e1a', rip: '0x7f...5229' });
      setTermText('[ROP] Executing chain...\nsh: $ id\nuid=0(root)');
      setPlaying(false);
      return;
    }

    setPhase(1); await sleep(600);
    if (cancelRef.current) return;

    setPhase(2);
    for (let i = 0; i < GADGETS.length; i++) {
      if (cancelRef.current) return;
      setActiveGadget(i);
      if (i === 0) setRegisters(r => ({ ...r, rip: '0x401234' }));
      if (i === 1) setRegisters({ rdi: '0x7fabc1b3e1a', rip: '0x7f...1b3e' });
      if (i === 2) setRegisters(r => ({ ...r, rip: '0x7f...5229' }));
      await sleep(900);
    }

    if (cancelRef.current) return;
    setPhase(3);
    const msg = '[ROP] Executing gadget chain...\n[+] pop rdi → 0x7fabc1b3e1a\n[+] Calling system("/bin/sh")\nsh: $ id\nuid=0(root) gid=0(root)';
    for (let i = 0; i <= msg.length; i++) {
      if (cancelRef.current) return;
      setTermText(msg.slice(0, i));
      await sleep(15);
    }
    setPlaying(false);
  };

  useEffect(() => () => { cancelRef.current = true; }, []);

  return (
    <div style={{ maxWidth: '520px', margin: '20px auto' }}>
      {/* Register state */}
      {phase >= 2 && (
        <div style={{
          display: 'flex', gap: '8px', marginBottom: '14px',
          fontFamily: 'monospace', fontSize: '12px',
        }}>
          {['rdi','rip'].map(reg => (
            <div key={reg} style={{
              flex: 1, border: '1px solid #21262d', borderRadius: '6px',
              padding: '8px 12px', background: '#161b22',
            }}>
              <span style={{ color: '#8b949e' }}>{reg.toUpperCase()}: </span>
              <span style={{ color: '#79c0ff', fontWeight: 700 }}>
                {registers[reg]}
              </span>
            </div>
          ))}
        </div>
      )}

      {/* Gadget chain — horizontal with connecting arrows */}
      <div style={{ marginBottom: '14px' }}>
        <div style={{ fontSize: '11px', color: '#8b949e', marginBottom: '10px',
          textTransform: 'uppercase', letterSpacing: '0.06em' }}>
          ROP CHAIN EXECUTION
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0' }}>
          {GADGETS.map((g, i) => (
            <React.Fragment key={i}>
              <div style={{
                flex: 1, border: `2px solid ${activeGadget === i ? g.color : '#21262d'}`,
                borderRadius: '8px', padding: '12px 10px', textAlign: 'center',
                background: activeGadget === i ? g.color + '22' : '#0d1117',
                transition: 'all 0.3s',
                boxShadow: activeGadget === i ? `0 0 14px ${g.color}66` : 'none',
              }}>
                <div style={{ fontSize: '10px', color: '#484f58', marginBottom: '4px' }}>
                  {g.label}
                </div>
                <div style={{ fontFamily: 'monospace', fontSize: '11px',
                  color: activeGadget >= i ? g.color : '#484f58',
                  fontWeight: 700, marginBottom: '4px' }}>
                  {g.asm}
                </div>
                <div style={{ fontSize: '10px', color: '#484f58', fontFamily: 'monospace' }}>
                  {g.addr}
                </div>
                {activeGadget === i && (
                  <div style={{ fontSize: '10px', color: g.color,
                    marginTop: '6px', fontWeight: 600 }}>
                    {g.effect}
                  </div>
                )}
              </div>
              {i < GADGETS.length - 1 && (
                <div style={{
                  color: activeGadget > i ? '#3fb950' : '#21262d',
                  fontSize: '20px', padding: '0 4px',
                  transition: 'color 0.3s',
                }}>→</div>
              )}
            </React.Fragment>
          ))}
        </div>
      </div>

      {/* NX explanation */}
      {phase >= 1 && (
        <div style={{
          border: '1px solid #30363d', borderRadius: '6px',
          padding: '8px 14px', marginBottom: '14px',
          fontSize: '12px', color: '#8b949e', background: '#161b22',
        }}>
          <strong style={{ color: '#e3b341' }}>NX enabled</strong> — stack not executable.
          ROP reuses <em>existing</em> code — no shellcode needed.
          Each gadget ends with <code style={{ background: '#0d1117',
            padding: '1px 5px', borderRadius: '3px', color: '#79c0ff' }}>ret</code>,
          which pops the next address from the stack and jumps to it.
        </div>
      )}

      {/* Terminal */}
      {termText && (
        <div style={{
          background: '#0d1117', border: '1px solid #3fb950',
          borderRadius: '6px', padding: '12px 16px', marginBottom: '14px',
        }}>
          <pre style={{ color: '#7ee787', fontSize: '12px', margin: 0,
            whiteSpace: 'pre-wrap', fontFamily: 'monospace' }}>{termText}</pre>
        </div>
      )}

      {/* Buttons */}
      <div style={{ display: 'flex', gap: '8px' }}>
        <button onClick={play} disabled={playing} style={{
          flex: 1, padding: '9px 0', borderRadius: '6px', fontSize: '13px',
          fontWeight: 600, cursor: playing ? 'not-allowed' : 'pointer',
          background: playing ? '#21262d' : '#238636',
          border: '1px solid #2ea043', color: 'white', opacity: playing ? 0.6 : 1,
        }}>
          {playing ? 'Animating...' : phase === 0 ? '▶ Play Animation' : '↺ Replay'}
        </button>
        {phase > 0 && !playing && (
          <button onClick={resetAll} style={{
            padding: '9px 14px', borderRadius: '6px', fontSize: '13px',
            cursor: 'pointer', background: '#21262d',
            border: '1px solid #30363d', color: '#8b949e',
          }}>Reset</button>
        )}
      </div>
    </div>
  );
}
