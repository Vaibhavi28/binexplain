import React, { useState, useRef, useEffect } from 'react';
import anime from 'animejs';

const STAGES = ['idle', 'filling', 'overflow', 'hijack', 'result'];

export default function RetwinMemoryAnimation() {
  const [speed, setSpeed] = useState(1); // 1 = normal, 0.5 = slow
  const [stage, setStage] = useState('idle');
  const [byteCount, setByteCount] = useState(0);
  const [playing, setPlaying] = useState(false);
  const sleep = ms => new Promise(r => setTimeout(r, ms * (1 / speed)));
  const timelineRef = useRef(null);
  const prefersReducedMotion = useRef(
    window.matchMedia('(prefers-reduced-motion: reduce)').matches
  );

  const bufferRef = useRef(null);
  const paddingRef = useRef(null);
  const rbpRef = useRef(null);
  const retAddrRef = useRef(null);
  const terminalRef = useRef(null);

  const resetToIdle = () => {
    if (timelineRef.current) {
      timelineRef.current.pause();
      timelineRef.current = null;
    }
    setStage('idle');
    setByteCount(0);
    setPlaying(false);

    // Reset all box styles
    [bufferRef, paddingRef, rbpRef, retAddrRef].forEach(ref => {
      if (ref.current) {
        ref.current.style.background = 'transparent';
        ref.current.style.opacity = '0.5';
        ref.current.style.transform = 'none';
      }
    });
    if (retAddrRef.current) {
      const label = retAddrRef.current.querySelector('.addr-label');
      if (label) label.textContent = 'RETURN ADDRESS';
      const sub = retAddrRef.current.querySelector('.addr-sub');
      if (sub) sub.textContent = '← Overwrite with win() address';
    }
    if (terminalRef.current) {
      terminalRef.current.style.opacity = '0';
      terminalRef.current.querySelector('.term-text').textContent = '';
    }
  };

  const runAnimation = () => {
    if (playing) return;
    resetToIdle();

    // If user prefers reduced motion, jump to final state
    if (prefersReducedMotion.current) {
      setStage('result');
      setByteCount(64);
      if (bufferRef.current) bufferRef.current.style.background = '#1c2d4a';
      if (paddingRef.current) paddingRef.current.style.background = '#3a2a00';
      if (rbpRef.current) rbpRef.current.style.background = '#3a1500';
      if (retAddrRef.current) {
        retAddrRef.current.style.background = '#3a0000';
        const label = retAddrRef.current.querySelector('.addr-label');
        if (label) label.textContent = '0x401196 (win)';
        const sub = retAddrRef.current.querySelector('.addr-sub');
        if (sub) sub.textContent = '← Return Address Hijacked';
      }
      if (terminalRef.current) {
        terminalRef.current.style.opacity = '1';
        terminalRef.current.querySelector('.term-text').textContent =
          '$ ./binary < payload\nWelcome to the flag zone!\nflag{r3t2w1n_4ch13v3d}';
      }
      return;
    }

    setPlaying(true);
    const scale = (val) => val * 1.8 * (1 / speed);
    const scaleWithPause = (val) => (val * 1.8 + 600) * (1 / speed);

    const tl = anime.timeline({ easing: 'easeOutQuad' });
    timelineRef.current = tl;

    // Stage 1: Fill the buffer (0 to 64 bytes)
    tl.add({
      targets: bufferRef.current,
      backgroundColor: ['transparent', '#1c2d4a'],
      opacity: [0.5, 1],
      duration: scale(800),
      begin: () => setStage('filling'),
      update: (anim) => {
        const progress = anim.progress / 100;
        setByteCount(Math.floor(progress * 64));
        if (bufferRef.current) {
          bufferRef.current.style.backgroundImage =
            `linear-gradient(to right, #388bfd ${progress * 100}%, transparent ${progress * 100}%)`;
        }
      },
      complete: () => setByteCount(64)
    });

    // Stage 2: Overflow into padding and RBP
    tl.add({
      targets: paddingRef.current,
      backgroundColor: ['transparent', '#3a2a00'],
      opacity: [0.5, 1],
      duration: scale(500),
      begin: () => setStage('overflow'),
      update: (anim) => {
        const progress = anim.progress / 100;
        setByteCount(64 + Math.floor(progress * 8));
      }
    }, '+=' + scaleWithPause(100));

    tl.add({
      targets: rbpRef.current,
      backgroundColor: ['transparent', '#3a1500'],
      opacity: [0.5, 1],
      duration: scale(400),
      update: (anim) => {
        const progress = anim.progress / 100;
        setByteCount(72 + Math.floor(progress * 8));
      }
    }, '+=' + scale(50));

    // Stage 3: Hijack the return address
    tl.add({
      targets: retAddrRef.current,
      backgroundColor: ['transparent', '#3a0000'],
      opacity: [0.5, 1],
      duration: scale(600),
      begin: () => {
        setStage('hijack');
        setByteCount(80);
        if (retAddrRef.current) {
          const label = retAddrRef.current.querySelector('.addr-label');
          if (label) label.textContent = '0x401196 (win)';
          const sub = retAddrRef.current.querySelector('.addr-sub');
          if (sub) sub.textContent = '← Return Address Hijacked';
        }
      }
    }, '+=' + scaleWithPause(100));

    // Shake the return address box
    tl.add({
      targets: retAddrRef.current,
      translateX: [0, -4, 4, -4, 4, -3, 3, 0],
      duration: scale(400),
      easing: 'linear'
    }, '+=' + scale(50));

    // Stage 4: Show terminal output
    tl.add({
      targets: terminalRef.current,
      opacity: [0, 1],
      duration: scale(400),
      begin: () => setStage('result'),
      complete: () => {
        // Typewriter effect
        const text = '$ ./binary < payload\nWelcome to the flag zone!\nflag{r3t2w1n_4ch13v3d}';
        const el = terminalRef.current?.querySelector('.term-text');
        if (!el) return;
        el.textContent = '';
        let i = 0;
        const interval = setInterval(() => {
          el.textContent += text[i];
          i++;
          if (i >= text.length) {
            clearInterval(interval);
            setPlaying(false);
          }
        }, 35 * (1 / speed));
      }
    }, '+=' + scaleWithPause(600));
  };

  useEffect(() => {
    return () => {
      if (timelineRef.current) timelineRef.current.pause();
    };
  }, []);

  const boxStyle = (borderColor) => ({
    border: `1px solid ${borderColor}`,
    borderRadius: '6px',
    padding: '10px 16px',
    marginBottom: '6px',
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    fontFamily: 'monospace',
    fontSize: '13px',
    transition: 'background-color 0.3s',
    opacity: 0.5,
  });

  return (
    <div id="ret2win-memory-diagram" style={{ margin: '20px 0' }}>
      <div style={{
        fontSize: '11px', color: '#8b949e', textTransform: 'uppercase',
        letterSpacing: '0.08em', marginBottom: '12px', textAlign: 'center'
      }}>
        STACK — HIGH ADDRESS AT TOP
        {stage === 'filling' || stage === 'overflow' || stage === 'hijack' ? (
          <span style={{
            marginLeft: '12px', color: '#e3b341',
            fontFamily: 'monospace'
          }}>
            {byteCount} bytes written
          </span>
        ) : null}
      </div>

      {/* Stack boxes — top to bottom = high to low address */}
      <div ref={retAddrRef} style={boxStyle('#f85149')}>
        <span className="addr-label" style={{ color: '#f85149', fontWeight: 700 }}>
          RETURN ADDRESS
        </span>
        <span className="addr-sub" style={{ color: '#8b949e', fontSize: '11px' }}>
          ← Overwrite with win() address
        </span>
      </div>

      <div ref={rbpRef} style={boxStyle('#e3b341')}>
        <span style={{ color: '#e3b341', fontWeight: 600 }}>SAVED RBP</span>
        <span style={{ color: '#8b949e', fontSize: '11px' }}>8 bytes — fill with A's</span>
      </div>

      <div ref={paddingRef} style={boxStyle('#f0883e')}>
        <span style={{ color: '#f0883e', fontWeight: 600 }}>BUFFER PADDING</span>
        <span style={{ color: '#8b949e', fontSize: '11px' }}>Variable bytes — A's</span>
      </div>

      <div ref={bufferRef} style={boxStyle('#388bfd')}>
        <span style={{ color: '#388bfd', fontWeight: 600 }}>LOCAL BUFFER (64 bytes)</span>
        <span style={{ color: '#8b949e', fontSize: '11px' }}>← Your input starts here</span>
      </div>

      <div style={{
        fontSize: '11px', color: '#8b949e', textAlign: 'center',
        marginTop: '6px', marginBottom: '16px'
      }}>
        LOW ADDRESS ↑ stack grows downward
      </div>

      {/* Buttons */}
      <div style={{ display: 'flex', gap: '10px', justifyContent: 'center', marginBottom: '16px' }}>
        <button
          onClick={runAnimation}
          disabled={playing}
          style={{
            padding: '8px 20px', borderRadius: '6px', fontSize: '13px',
            fontWeight: 600, cursor: playing ? 'not-allowed' : 'pointer',
            background: playing ? '#21262d' : '#238636',
            border: '1px solid #2ea043', color: 'white',
            opacity: playing ? 0.6 : 1
          }}
        >
          {playing ? '▶ Playing...' : stage === 'idle' ? '▶ Play Animation' : '↺ Replay'}
        </button>
        <button
          onClick={() => setSpeed(s => s === 1 ? 0.5 : 1)}
          disabled={playing}
          style={{
            padding: '8px 14px', borderRadius: '6px', fontSize: '12px',
            cursor: playing ? 'not-allowed' : 'pointer', background: '#21262d',
            border: '1px solid #30363d', color: '#8b949e', opacity: playing ? 0.6 : 1,
          }}
        >
          {speed === 1 ? 'Slow (1x) Mode' : 'Fast Normal Speed'}
        </button>
        {stage !== 'idle' && !playing && (
          <button
            onClick={resetToIdle}
            style={{
              padding: '8px 16px', borderRadius: '6px', fontSize: '13px',
              cursor: 'pointer', background: '#21262d',
              border: '1px solid #30363d', color: '#8b949e'
            }}
          >
            Reset
          </button>
        )}
      </div>

      {/* Terminal output */}
      <div
        ref={terminalRef}
        style={{
          opacity: 0, background: '#0d1117', border: '1px solid #3fb950',
          borderRadius: '6px', padding: '14px 16px'
        }}
      >
        <div style={{
          fontSize: '11px', color: '#3fb950', marginBottom: '8px',
          textTransform: 'uppercase', letterSpacing: '0.08em'
        }}>
          Output
        </div>
        <pre className="term-text" style={{
          color: '#7ee787', fontSize: '13px', fontFamily: 'monospace',
          margin: 0, whiteSpace: 'pre-wrap'
        }} />
      </div>

      {prefersReducedMotion.current && (
        <p style={{ fontSize: '11px', color: '#8b949e', textAlign: 'center', marginTop: '8px' }}>
          Animation disabled (prefers-reduced-motion). Showing final state.
        </p>
      )}
    </div>
  );
}
