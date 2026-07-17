import React, { useState, useRef, useEffect } from 'react';

const STACK_ROWS = [
  { label: 'Return Address', color: '#f85149', hidden: '[ protected ]' },
  { label: 'Stack Canary',   color: '#e3b341', hidden: '[ protected ]' },
  { label: 'Libc Address',   color: '#bc8cff', hidden: '[ protected ]' },
  { label: 'Your Input Buffer', color: '#388bfd', hidden: '[ your input ]' },
];

const LEAKED_VALUES = [
  '0x7ffd1234abcd',
  '0x0000000000000000',
  '0x0000000000401234',
  '0x70252e70',  // %p. in ASCII
];

export default function FormatStringAnimation() {
  const [speed, setSpeed] = useState(1); // 1 = normal, 0.5 = slow
  const [phase, setPhase] = useState(0);
  const [inputText, setInputText] = useState('');
  const [revealed, setRevealed] = useState([false, false, false, false]);
  const [playing, setPlaying] = useState(false);
  const [termText, setTermText] = useState('');
  const [highlight4, setHighlight4] = useState(false);
  const reducedMotion = useRef(
    typeof window !== 'undefined' &&
    window.matchMedia('(prefers-reduced-motion: reduce)').matches
  );
  const timerRef = useRef(null);

  const resetAll = () => {
    if (timerRef.current) clearTimeout(timerRef.current);
    setPhase(0); setInputText(''); setRevealed([false,false,false,false]);
    setPlaying(false); setTermText(''); setHighlight4(false);
  };

  const sleep = ms => new Promise(r => (timerRef.current = setTimeout(r, ms * (1 / speed))));

  const play = async () => {
    if (playing) return;
    resetAll();
    await sleep(90);
    setPlaying(true);

    if (reducedMotion.current) {
      setPhase(3);
      setInputText('%p.%p.%p.%p');
      setRevealed([true,true,true,true]);
      setTermText('$ echo "%p.%p.%p.%p" | ./vuln\n0x7ffd1234abcd.0x0.0x401234.0x70252e70');
      setHighlight4(true);
      setPlaying(false);
      return;
    }

    // Phase 1 — show stack
    setPhase(1);
    await sleep(1080); await sleep(600); // reading pause

    // Phase 2 — type the format string
    setPhase(2);
    const fmt = '%p.%p.%p.%p';
    for (let i = 0; i <= fmt.length; i++) {
      setInputText(fmt.slice(0, i));
      await sleep(144);
    }
    await sleep(720); await sleep(600); // reading pause

    // Phase 3 — reveal each stack value one by one
    setPhase(3);
    for (let i = 0; i < 4; i++) {
      setRevealed(prev => { const n = [...prev]; n[i] = true; return n; });
      await sleep(900); await sleep(600); // reading pause
    }

    // Terminal output typewriter
    const output = '$ echo "%p.%p.%p.%p" | ./vuln\n0x7ffd1234abcd.0x0.0x401234.0x70252e70';
    setTermText('');
    for (let i = 0; i <= output.length; i++) {
      setTermText(output.slice(0, i));
      await sleep(35);
    }

    await sleep(1080);
    // Phase 4 — highlight the buffer position
    setHighlight4(true);
    setPlaying(false);
  };

  useEffect(() => () => { if (timerRef.current) clearTimeout(timerRef.current); }, []);

  return (
    <div style={{ maxWidth: '520px', margin: '20px auto' }}>
      <div style={{ fontSize: '12px', color: '#8b949e', marginBottom: '12px', textAlign: 'center' }}>
        {phase === 0 && 'Click Play to see how printf() leaks memory'}
        {phase === 1 && 'Stack memory — values are hidden until leaked'}
        {phase === 2 && 'Typing format specifiers as input...'}
        {phase === 3 && 'printf() reads format specifiers — leaking stack!'}
      </div>

      {/* Stack rows */}
      <div style={{ marginBottom: '12px' }}>
        <div style={{ fontSize: '11px', color: '#484f58', textAlign: 'right',
          marginBottom: '4px', fontFamily: 'monospace' }}>HIGH ADDRESS ↑</div>

        {STACK_ROWS.map((row, i) => (
          <div key={i} style={{
            border: `1px solid ${revealed[i] ? row.color : '#30363d'}`,
            borderRadius: '6px', padding: '10px 16px', marginBottom: '6px',
            display: 'flex', justifyContent: 'space-between', alignItems: 'center',
            fontFamily: 'monospace', fontSize: '13px',
            background: revealed[i] ? row.color + '18' : '#0d1117',
            transition: 'all 0.4s',
          }}>
            <span style={{ color: row.color, fontWeight: 600 }}>{row.label}</span>
            <span style={{
              color: revealed[i] ? row.color : '#484f58',
              fontSize: '12px', fontWeight: revealed[i] ? 700 : 400,
            }}>
              {revealed[i] ? LEAKED_VALUES[i] : row.hidden}
            </span>
          </div>
        ))}

        <div style={{ fontSize: '11px', color: '#484f58', textAlign: 'right',
          marginTop: '4px', fontFamily: 'monospace' }}>LOW ADDRESS ↓</div>
      </div>

      {/* Input box */}
      {phase >= 2 && (
        <div style={{
          background: '#161b22', border: '1px solid #30363d',
          borderRadius: '6px', padding: '10px 14px', marginBottom: '12px',
          fontFamily: 'monospace', fontSize: '13px',
          display: 'flex', alignItems: 'center', gap: '8px',
        }}>
          <span style={{ color: '#8b949e', fontSize: '11px' }}>Enter name:</span>
          <span style={{ color: '#f85149', fontWeight: 700 }}>{inputText}</span>
          {playing && phase === 2 && (
            <span style={{ color: '#f85149', animation: 'blink 1s step-end infinite' }}>|</span>
          )}
        </div>
      )}

      {/* Buffer position highlight */}
      {highlight4 && (
        <div style={{
          background: '#1c2d4a', border: '1px solid #388bfd',
          borderRadius: '6px', padding: '10px 14px', marginBottom: '12px',
          fontSize: '13px', color: '#79c0ff',
        }}>
          <strong>0x70252e70</strong> = "%p." in ASCII.
          This is your buffer — you are at stack position 4.
          Now use <code style={{ background: '#0d1117', padding: '1px 6px', borderRadius: '3px' }}>
            %4$p
          </code> to read exactly this position.
        </div>
      )}

      {/* Terminal */}
      {termText && (
        <div style={{
          background: '#0d1117', border: '1px solid #3fb950',
          borderRadius: '6px', padding: '12px 16px', marginBottom: '12px',
        }}>
          <div style={{ fontSize: '10px', color: '#3fb950', marginBottom: '6px',
            textTransform: 'uppercase', letterSpacing: '0.08em' }}>Output</div>
          <pre style={{ color: '#7ee787', fontSize: '12px', margin: 0, whiteSpace: 'pre-wrap',
            fontFamily: 'monospace' }}>{termText}</pre>
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
