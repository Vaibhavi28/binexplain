import React, { useState, useRef, useEffect } from 'react';

export default function Ret2libcAnimation() {
  const [speed, setSpeed] = useState(1); // 1 = normal, 0.5 = slow
  const sleep = ms => new Promise(r => setTimeout(r, ms * (1 / speed)));
  const [phase, setPhase] = useState(0);
  const [libcBase, setLibcBase] = useState('???');
  const [systemAddr, setSystemAddr] = useState('???');
  const [playing, setPlaying] = useState(false);
  const [termText, setTermText] = useState('');
  const [payloadRow, setPayloadRow] = useState(-1);
  const reducedMotion = useRef(
    typeof window !== 'undefined' &&
    window.matchMedia('(prefers-reduced-motion: reduce)').matches
  );
  const cancelRef = useRef(false);

  const PAYLOAD = [
    { label: 'PADDING', value: 'A × 72', color: '#388bfd' },
    { label: 'pop rdi ; ret', value: '0x401234 (gadget)', color: '#bc8cff' },
    { label: '/bin/sh address', value: 'libc_base + 0x1b3e1a', color: '#3fb950' },
    { label: 'system() address', value: 'libc_base + 0x52290', color: '#f85149' },
  ];

  const resetAll = () => {
    cancelRef.current = true;
    setPhase(0); setLibcBase('???'); setSystemAddr('???');
    setPlaying(false); setTermText(''); setPayloadRow(-1);
    setTimeout(() => { cancelRef.current = false; }, 100);
  };

  const play = async () => {
    if (playing) return;
    resetAll();
    await sleep(108);
    cancelRef.current = false;
    setPlaying(true);

    if (reducedMotion.current) {
      setPhase(3); setLibcBase('0x7f4abc000000'); setSystemAddr('0x7f4abc052290');
      setPayloadRow(3);
      setTermText('[+] libc base: 0x7f4abc000000\n[+] system: 0x7f4abc052290\n$ id\nuid=0(root)');
      setPlaying(false);
      return;
    }

    // Phase 1: Leak
    setPhase(1); await sleep(1440); await sleep(600); // reading pause
    if (cancelRef.current) return;
    setPhase(2);
    const leaked = '0x7f4abc000000';
    setLibcBase(leaked);
    await sleep(1440); await sleep(600); // reading pause
    if (cancelRef.current) return;
    setSystemAddr('0x7f4abc052290');

    // Phase 2: Build payload
    await sleep(1080); await sleep(600); // reading pause
    if (cancelRef.current) return;
    setPhase(3);
    for (let i = 0; i < PAYLOAD.length; i++) {
      if (cancelRef.current) return;
      setPayloadRow(i);
      await sleep(900); await sleep(600); // reading pause
    }

    const msg = '[+] libc base: 0x7f4abc000000\n[+] system(): 0x7f4abc052290\n[+] Sending payload...\n$ id\nuid=0(root) gid=0(root)';
    for (let i = 0; i <= msg.length; i++) {
      if (cancelRef.current) return;
      setTermText(msg.slice(0, i));
      await sleep(35);
    }
    setPlaying(false);
  };

  useEffect(() => () => { cancelRef.current = true; }, []);

  return (
    <div style={{ maxWidth: '520px', margin: '20px auto' }}>
      {/* Memory map */}
      <div style={{ marginBottom: '14px' }}>
        <div style={{ fontSize: '11px', color: '#8b949e', marginBottom: '8px',
          textTransform: 'uppercase', letterSpacing: '0.06em' }}>MEMORY MAP</div>
        <div style={{ display: 'flex', gap: '8px' }}>
          <div style={{
            flex: 1, border: '1px solid #388bfd', borderRadius: '6px',
            padding: '10px', textAlign: 'center', background: '#1c2d4a22',
          }}>
            <div style={{ color: '#79c0ff', fontWeight: 700, fontFamily: 'monospace', fontSize: '12px' }}>
              Binary
            </div>
            <div style={{ color: '#388bfd', fontSize: '11px', marginTop: '4px' }}>
              0x400000 (fixed)
            </div>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', color: '#484f58' }}>
            {phase >= 2 ? (
              <span style={{ color: '#3fb950', fontSize: '18px' }}>→</span>
            ) : (
              <span style={{ fontSize: '12px' }}>leak →</span>
            )}
          </div>
          <div style={{
            flex: 1, border: `1px solid ${phase >= 2 ? '#3fb950' : '#30363d'}`,
            borderRadius: '6px', padding: '10px', textAlign: 'center',
            background: phase >= 2 ? '#3fb95022' : '#0d1117',
            transition: 'all 0.4s',
          }}>
            <div style={{ color: phase >= 2 ? '#56d364' : '#484f58',
              fontWeight: 700, fontFamily: 'monospace', fontSize: '12px' }}>
              libc.so
            </div>
            <div style={{ color: phase >= 2 ? '#3fb950' : '#484f58',
              fontSize: '11px', marginTop: '4px', fontFamily: 'monospace' }}>
              {libcBase}
            </div>
          </div>
        </div>
        {phase >= 2 && systemAddr !== '???' && (
          <div style={{
            marginTop: '8px', padding: '8px 12px',
            border: '1px solid #f85149', borderRadius: '6px',
            background: '#f8514918', fontFamily: 'monospace', fontSize: '12px',
          }}>
            <span style={{ color: '#8b949e' }}>system() = </span>
            <span style={{ color: '#f85149', fontWeight: 700 }}>{libcBase}</span>
            <span style={{ color: '#8b949e' }}> + 0x52290 = </span>
            <span style={{ color: '#ff7b72', fontWeight: 700 }}>{systemAddr}</span>
          </div>
        )}
      </div>

      {/* Payload builder */}
      {phase >= 3 && (
        <div style={{ marginBottom: '14px' }}>
          <div style={{ fontSize: '11px', color: '#8b949e', marginBottom: '8px',
            textTransform: 'uppercase', letterSpacing: '0.06em' }}>PAYLOAD (Stack layout)</div>
          {PAYLOAD.map((row, i) => (
            <div key={i} style={{
              border: `1px solid ${i <= payloadRow ? row.color : '#21262d'}`,
              borderRadius: '6px', padding: '8px 14px', marginBottom: '5px',
              display: 'flex', justifyContent: 'space-between',
              fontFamily: 'monospace', fontSize: '12px',
              background: i <= payloadRow ? row.color + '18' : '#0d1117',
              opacity: i <= payloadRow ? 1 : 0.3,
              transition: 'all 0.4s',
            }}>
              <span style={{ color: row.color, fontWeight: 600 }}>{row.label}</span>
              <span style={{ color: '#8b949e' }}>{row.value}</span>
            </div>
          ))}
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
          {playing ? '▶ Animating...' : phase === 0 ? '▶ Play Animation' : '↺ Replay'}
        </button>
        <button
          onClick={() => setSpeed(s => s === 1 ? 0.5 : 1)}
          disabled={playing}
          style={{
            padding: '9px 14px', borderRadius: '6px', fontSize: '12px',
            cursor: playing ? 'not-allowed' : 'pointer', background: '#21262d',
            border: '1px solid #30363d', color: '#8b949e', opacity: playing ? 0.6 : 1,
          }}
        >
          {speed === 1 ? 'Slow (1x) Mode' : 'Fast Normal Speed'}
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
