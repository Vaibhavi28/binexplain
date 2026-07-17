import React, { useState, useRef, useEffect } from 'react';

const SHELLCODE_BYTES = [
  '\\x48', '\\x31', '\\xff', '\\x48', '\\x31', '\\xd2',
  '\\x48', '\\x31', '\\xf6', '\\x0f', '\\x05', '...',
];

export default function ShellcodeAnimation() {
  const [speed, setSpeed] = useState(1);
  const sleep = ms => new Promise(r => setTimeout(r, ms * (1 / speed)));
  const [phase, setPhase] = useState(0);
  const [bytesFilled, setBytesFilled] = useState(0);
  const [retHijacked, setRetHijacked] = useState(false);
  const [executing, setExecuting] = useState(false);
  const [playing, setPlaying] = useState(false);
  const [termText, setTermText] = useState('');
  const cancelRef = useRef(false);
  const reducedMotion = useRef(
    typeof window !== 'undefined' &&
    window.matchMedia('(prefers-reduced-motion: reduce)').matches
  );

  const resetAll = () => {
    cancelRef.current = true;
    setPhase(0); setBytesFilled(0); setRetHijacked(false);
    setExecuting(false); setPlaying(false); setTermText('');
    setTimeout(() => { cancelRef.current = false; }, 100);
  };

  const play = async () => {
    if (playing) return;
    resetAll();
    await sleep(108);
    cancelRef.current = false;
    setPlaying(true);

    if (reducedMotion.current) {
      setPhase(4); setBytesFilled(SHELLCODE_BYTES.length);
      setRetHijacked(true); setExecuting(true);
      setTermText('$ ./vuln < payload\nexecve("/bin/sh", NULL, NULL)\nsh: $ id\nuid=0(root)');
      setPlaying(false);
      return;
    }

    setPhase(1); await sleep(1260); await sleep(600); // reading pause
    if (cancelRef.current) return;

    // Phase 2: write shellcode bytes
    setPhase(2);
    for (let i = 0; i <= SHELLCODE_BYTES.length; i++) {
      if (cancelRef.current) return;
      setBytesFilled(i);
      await sleep(216);
    }

    // Phase 3: overwrite return address
    await sleep(540); await sleep(600); // reading pause
    if (cancelRef.current) return;
    setPhase(3); setRetHijacked(true);
    await sleep(1260); await sleep(600); // reading pause

    // Phase 4: execute
    if (cancelRef.current) return;
    setPhase(4); setExecuting(true);
    await sleep(720); await sleep(600); // reading pause

    const msg = 'execve("/bin/sh", NULL, NULL) called\n\nsh: $ id\nuid=0(root) gid=0(root)\nsh: $ cat flag.txt\nflag{shellc0de_runs_when_NX_is_0ff}';
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
      {/* NX status badge */}
      <div style={{
        display: 'inline-flex', alignItems: 'center', gap: '8px',
        border: '1px solid #f85149', background: '#f8514918',
        borderRadius: '6px', padding: '6px 14px', marginBottom: '14px',
        fontSize: '12px',
      }}>
        <span style={{ color: '#f85149', fontWeight: 700 }}>NX: DISABLED</span>
        <span style={{ color: '#8b949e' }}>Stack is executable!</span>
      </div>

      {/* Stack visualization */}
      <div style={{ marginBottom: '14px' }}>
        <div style={{ fontSize: '11px', color: '#8b949e', textAlign: 'right',
          marginBottom: '4px', fontFamily: 'monospace' }}>HIGH ADDRESS ↑</div>

        {/* Return address */}
        <div style={{
          border: `1px solid ${retHijacked ? '#f85149' : '#30363d'}`,
          borderRadius: '6px', padding: '10px 16px', marginBottom: '6px',
          display: 'flex', justifyContent: 'space-between',
          fontFamily: 'monospace', fontSize: '13px',
          background: retHijacked ? '#3a0000' : '#0d1117',
          transition: 'all 0.4s',
          boxShadow: executing ? '0 0 14px #f8514966' : 'none',
        }}>
          <span style={{ color: retHijacked ? '#f85149' : '#484f58', fontWeight: 700 }}>
            RETURN ADDRESS
          </span>
          <span style={{ color: retHijacked ? '#ff7b72' : '#484f58', fontSize: '12px' }}>
            {retHijacked ? '→ 0x7ffd1234 (stack!)' : 'original return'}
          </span>
        </div>

        {/* Buffer with shellcode bytes */}
        <div style={{
          border: `1px solid ${executing ? '#3fb950' : bytesFilled > 0 ? '#388bfd' : '#30363d'}`,
          borderRadius: '6px', padding: '12px 16px', marginBottom: '6px',
          fontFamily: 'monospace', fontSize: '12px',
          background: executing ? '#162c1e' : bytesFilled > 0 ? '#1c2d4a' : '#0d1117',
          transition: 'all 0.4s',
          boxShadow: executing ? '0 0 14px #3fb95066' : 'none',
          minHeight: '60px',
        }}>
          <div style={{ color: '#8b949e', fontSize: '11px', marginBottom: '6px' }}>
            LOCAL BUFFER (64B) {phase >= 2 && bytesFilled > 0 ? '— SHELLCODE INJECTED' : ''}
          </div>
          <div style={{ wordBreak: 'break-all', lineHeight: '1.6' }}>
            {SHELLCODE_BYTES.slice(0, bytesFilled).map((b, i) => (
              <span key={i} style={{ color: executing ? '#56d364' : '#79c0ff' }}>{b}</span>
            ))}
            {bytesFilled > 0 && bytesFilled < SHELLCODE_BYTES.length && (
              <span style={{ color: '#388bfd', animation: 'blink 0.5s step-end infinite' }}>|</span>
            )}
          </div>
          {executing && (
            <div style={{ color: '#3fb950', fontSize: '11px', marginTop: '6px', fontWeight: 700 }}>
              ▶ CPU executing shellcode bytes...
            </div>
          )}
        </div>

        <div style={{ fontSize: '11px', color: '#484f58', textAlign: 'right',
          fontFamily: 'monospace' }}>LOW ADDRESS ↓</div>
      </div>

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
          {speed === 1 ? '🐢 Slow Mode' : '⚡ Normal Speed'}
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
