import React, { useState, useRef, useEffect } from 'react';

export default function RetwinAnimation() {
  const [speed, setSpeed] = useState(1); // 1 = normal, 0.5 = slow
  const [stage, setStage] = useState(0);
  const [byteCount, setByteCount] = useState(0);
  const [playing, setPlaying] = useState(false);
  const [termText, setTermText] = useState('');
  const reducedMotion = useRef(
    typeof window !== 'undefined' &&
    window.matchMedia('(prefers-reduced-motion: reduce)').matches
  );
  const timelineRef = useRef(null);
  const counterRef = useRef(null);
  const boxRefs = {
    buffer: useRef(null),
    padding: useRef(null),
    rbp: useRef(null),
    retAddr: useRef(null),
    terminal: useRef(null),
  };

  const STAGES = [
    { label: 'Normal execution', color: '#8b949e' },
    { label: 'Buffer filling...', color: '#388bfd' },
    { label: 'Overflowing!', color: '#e3b341' },
    { label: 'Return address hijacked', color: '#f85149' },
    { label: 'win() called — flag!', color: '#3fb950' },
  ];

  const resetAll = () => {
    if (timelineRef.current) { timelineRef.current.pause(); timelineRef.current = null; }
    if (counterRef.current) { clearInterval(counterRef.current); counterRef.current = null; }
    setStage(0); setByteCount(0); setPlaying(false); setTermText('');
    const colors = {
      buffer: { bg: '#0d1117', border: '#388bfd', text: '#79c0ff' },
      padding: { bg: '#0d1117', border: '#30363d', text: '#8b949e' },
      rbp:    { bg: '#0d1117', border: '#30363d', text: '#8b949e' },
      retAddr:{ bg: '#0d1117', border: '#30363d', text: '#8b949e' },
    };
    Object.entries(boxRefs).forEach(([key, ref]) => {
      if (!ref.current || key === 'terminal') return;
      const c = colors[key] || colors.padding;
      ref.current.style.background = c.bg;
      ref.current.style.borderColor = c.border;
      ref.current.style.transform = 'translateX(0)';
      ref.current.style.transition = '';
    });
    if (boxRefs.retAddr.current) {
      const label = boxRefs.retAddr.current.querySelector('.box-label');
      const sub = boxRefs.retAddr.current.querySelector('.box-sub');
      if (label) label.textContent = 'RETURN ADDRESS';
      if (sub) sub.textContent = '← Overwrite with win() address';
      sub && (sub.style.color = '#8b949e');
    }
    if (boxRefs.terminal.current) boxRefs.terminal.current.style.opacity = '0';
  };

  const typewriter = (text, onChar) => {
    let i = 0;
    const id = setInterval(() => {
      onChar(text.slice(0, i + 1));
      i++;
      if (i >= text.length) clearInterval(id);
    }, 35 * (1 / speed));
    counterRef.current = id;
  };

  const jumpToFinal = () => {
    setStage(4); setByteCount(80);
    if (boxRefs.buffer.current)  boxRefs.buffer.current.style.background = '#1c2d4a';
    if (boxRefs.padding.current) boxRefs.padding.current.style.background = '#3a2a00';
    if (boxRefs.rbp.current)     boxRefs.rbp.current.style.background = '#3a1500';
    if (boxRefs.retAddr.current) {
      boxRefs.retAddr.current.style.background = '#3a0000';
      boxRefs.retAddr.current.style.borderColor = '#f85149';
      const label = boxRefs.retAddr.current.querySelector('.box-label');
      const sub   = boxRefs.retAddr.current.querySelector('.box-sub');
      if (label) label.textContent = '0x401196 → win()';
      if (sub)   { sub.textContent = '← Return Address Hijacked'; sub.style.color = '#f85149'; }
    }
    if (boxRefs.terminal.current) {
      boxRefs.terminal.current.style.opacity = '1';
      const el = boxRefs.terminal.current.querySelector('.term-text');
      if (el) el.textContent = '$ ./pwn < payload\nWelcome! Here is your flag:\nflag{r3t2w1n_1s_c1ass1c}';
    }
  };

  const play = async () => {
    if (playing) return;
    resetAll();
    await new Promise(r => setTimeout(r, 50));
    if (reducedMotion.current) { jumpToFinal(); return; }
    setPlaying(true);

    const scale = (val) => val * 1.8 * (1 / speed);
    const scaleWithPause = (val) => (val * 1.8 + 600) * (1 / speed);

    const anime = (await import('animejs')).default;
    const tl = anime.timeline({ easing: 'easeOutQuad', autoplay: true });
    timelineRef.current = tl;

    // Stage 1 — fill the buffer blue
    tl.add({
      targets: boxRefs.buffer.current,
      backgroundColor: ['#0d1117', '#1c2d4a'],
      borderColor: ['#388bfd', '#79c0ff'],
      duration: scale(900),
      begin: () => setStage(1),
      update: a => setByteCount(Math.floor((a.progress / 100) * 64)),
      complete: () => setByteCount(64),
    });

    // Stage 2 — overflow into padding (amber)
    tl.add({
      targets: boxRefs.padding.current,
      backgroundColor: ['#0d1117', '#3a2a00'],
      borderColor: ['#30363d', '#e3b341'],
      duration: scale(500),
      begin: () => setStage(2),
      update: a => setByteCount(64 + Math.floor((a.progress / 100) * 8)),
    }, '+=' + scaleWithPause(80));

    // Stage 2b — overflow into saved rbp (orange)
    tl.add({
      targets: boxRefs.rbp.current,
      backgroundColor: ['#0d1117', '#3a1500'],
      borderColor: ['#30363d', '#f0883e'],
      duration: scale(400),
      update: a => setByteCount(72 + Math.floor((a.progress / 100) * 8)),
    }, '+=' + scale(40));

    // Stage 3 — hijack return address (red)
    tl.add({
      targets: boxRefs.retAddr.current,
      backgroundColor: ['#0d1117', '#3a0000'],
      borderColor: ['#30363d', '#f85149'],
      duration: scale(600),
      begin: () => {
        setStage(3); setByteCount(80);
        const label = boxRefs.retAddr.current?.querySelector('.box-label');
        const sub   = boxRefs.retAddr.current?.querySelector('.box-sub');
        if (label) label.textContent = '0x401196 → win()';
        if (sub)   { sub.textContent = '← Return Address Hijacked'; sub.style.color = '#f85149'; }
      },
    }, '+=' + scaleWithPause(60));

    // Shake the hijacked box
    tl.add({
      targets: boxRefs.retAddr.current,
      translateX: [0, -5, 5, -4, 4, -2, 2, 0],
      duration: scale(450),
      easing: 'linear',
    }, '+=' + scale(40));

    // Stage 4 — terminal typewriter
    tl.add({
      targets: boxRefs.terminal.current,
      opacity: [0, 1],
      duration: scale(350),
      begin: () => {
        setStage(4);
        typewriter(
          '$ ./pwn < payload\nWelcome! Here is your flag:\nflag{r3t2w1n_1s_c1ass1c}',
          txt => {
            const el = boxRefs.terminal.current?.querySelector('.term-text');
            if (el) el.textContent = txt;
          }
        );
      },
      complete: () => setPlaying(false),
    }, '+=' + scaleWithPause(500));
  };

  useEffect(() => () => {
    if (timelineRef.current) timelineRef.current.pause();
    if (counterRef.current)  clearInterval(counterRef.current);
  }, []);

  const boxBase = (borderCol) => ({
    border: `1px solid ${borderCol}`,
    borderRadius: '6px', padding: '11px 16px', marginBottom: '6px',
    display: 'flex', justifyContent: 'space-between', alignItems: 'center',
    fontFamily: 'monospace', fontSize: '13px', transition: 'background 0.3s, border-color 0.3s',
  });

  return (
    <div style={{ margin: '20px 0', maxWidth: '520px', marginLeft: 'auto', marginRight: 'auto' }}>
      {/* Stage indicator */}
      <div style={{ display: 'flex', gap: '6px', marginBottom: '14px', flexWrap: 'wrap' }}>
        {STAGES.map((s, i) => (
          <span key={i} style={{
            fontSize: '10px', padding: '2px 8px', borderRadius: '10px',
            background: stage === i ? s.color + '22' : '#0d1117',
            border: `1px solid ${stage === i ? s.color : '#21262d'}`,
            color: stage === i ? s.color : '#484f58',
            transition: 'all 0.3s', fontWeight: stage === i ? 700 : 400,
          }}>
            {i === stage ? '▶ ' : ''}{s.label}
          </span>
        ))}
      </div>

      {/* Address label */}
      <div style={{ fontSize: '11px', color: '#8b949e', textAlign: 'right',
        marginBottom: '4px', fontFamily: 'monospace' }}>
        HIGH ADDRESS ↑
      </div>

      {/* Stack boxes — high to low address (top to bottom) */}
      <div ref={boxRefs.retAddr} style={boxBase('#30363d')}>
        <span className="box-label" style={{ color: '#f85149', fontWeight: 700 }}>
          RETURN ADDRESS
        </span>
        <span className="box-sub" style={{ color: '#8b949e', fontSize: '11px' }}>
          ← Overwrite with win() address
        </span>
      </div>

      <div ref={boxRefs.rbp} style={boxBase('#30363d')}>
        <span style={{ color: '#8b949e', fontWeight: 600 }}>SAVED RBP</span>
        <span style={{ color: '#484f58', fontSize: '11px' }}>8 bytes</span>
      </div>

      <div ref={boxRefs.padding} style={boxBase('#30363d')}>
        <span style={{ color: '#8b949e', fontWeight: 600 }}>PADDING</span>
        <span style={{ color: '#484f58', fontSize: '11px' }}>fills gap to RBP</span>
      </div>

      <div ref={boxRefs.buffer} style={boxBase('#388bfd')}>
        <div>
          <span style={{ color: '#79c0ff', fontWeight: 700 }}>LOCAL BUFFER</span>
          <span style={{ color: '#484f58', fontSize: '11px', marginLeft: '8px' }}>64 bytes</span>
        </div>
        <span style={{ color: '#388bfd', fontSize: '11px' }}>
          {byteCount > 0 ? `${byteCount}B written` : '← Input starts here'}
        </span>
      </div>

      <div style={{ fontSize: '11px', color: '#8b949e', textAlign: 'right',
        marginTop: '4px', marginBottom: '16px', fontFamily: 'monospace' }}>
        LOW ADDRESS ↓ &nbsp; stack grows downward
      </div>

      {/* Buttons */}
      <div style={{ display: 'flex', gap: '8px', marginBottom: '16px' }}>
        <button onClick={play} disabled={playing} style={{
          flex: 1, padding: '9px 0', borderRadius: '6px', fontSize: '13px',
          fontWeight: 600, cursor: playing ? 'not-allowed' : 'pointer',
          background: playing ? '#21262d' : '#238636',
          border: '1px solid #2ea043', color: 'white', opacity: playing ? 0.6 : 1,
        }}>
          {playing ? '▶ Animating...' : stage === 0 ? '▶ Play Animation' : '↺ Replay'}
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
        {stage > 0 && !playing && (
          <button onClick={resetAll} style={{
            padding: '9px 16px', borderRadius: '6px', fontSize: '13px',
            cursor: 'pointer', background: '#21262d',
            border: '1px solid #30363d', color: '#8b949e',
          }}>
            Reset
          </button>
        )}
      </div>

      {/* Terminal output */}
      <div ref={boxRefs.terminal} style={{
        opacity: 0, background: '#0d1117', border: '1px solid #3fb950',
        borderRadius: '6px', padding: '14px 16px', transition: 'opacity 0.4s',
      }}>
        <div style={{ fontSize: '10px', color: '#3fb950', marginBottom: '8px',
          textTransform: 'uppercase', letterSpacing: '0.08em' }}>
          Terminal Output
        </div>
        <pre className="term-text" style={{
          color: '#7ee787', fontSize: '13px', fontFamily: 'monospace',
          margin: 0, whiteSpace: 'pre-wrap',
        }} />
      </div>

      {reducedMotion.current && (
        <p style={{ fontSize: '11px', color: '#484f58', textAlign: 'center', marginTop: '8px' }}>
          Reduced motion enabled — showing final state only
        </p>
      )}
    </div>
  );
}
