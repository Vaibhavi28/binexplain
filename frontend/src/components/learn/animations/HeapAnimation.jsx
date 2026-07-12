import React, { useState, useRef, useEffect } from 'react';

const sleep = ms => new Promise(r => setTimeout(r, ms));

export default function HeapAnimation() {
  const [phase, setPhase] = useState(0);
  const [playing, setPlaying] = useState(false);
  const [termText, setTermText] = useState('');
  const [freeList, setFreeList] = useState([]);
  const [showWarning, setShowWarning] = useState(false);
  const reducedMotion = useRef(
    typeof window !== 'undefined' &&
    window.matchMedia('(prefers-reduced-motion: reduce)').matches
  );
  const cancelRef = useRef(false);

  const resetAll = () => {
    cancelRef.current = true;
    setPhase(0); setPlaying(false);
    setTermText(''); setFreeList([]); setShowWarning(false);
    setTimeout(() => { cancelRef.current = false; }, 100);
  };

  const CHUNKS = [
    null,
    { label: 'Chunk A', sub: 'malloc(64)', color: '#388bfd', border: '#79c0ff' },
    { label: 'Chunk B', sub: 'malloc(64)', color: '#bc8cff', border: '#d2a8ff' },
    { label: 'Chunk B (freed)', sub: 'free(B)', color: '#21262d', border: '#484f58' },
    { label: 'Chunk C (attacker)', sub: 'malloc(64) → B slot!', color: '#f85149', border: '#ff7b72' },
  ];

  const play = async () => {
    if (playing) return;
    resetAll();
    await sleep(60);
    cancelRef.current = false;
    setPlaying(true);

    if (reducedMotion.current) {
      setPhase(5);
      setFreeList([]);
      setShowWarning(true);
      setTermText('free(B) then malloc(64) returns B\'s address\nChunk C = Chunk B memory!\nAttacker controls B\'s data');
      setPlaying(false);
      return;
    }

    setPhase(1); await sleep(700);
    if (cancelRef.current) return;
    setPhase(2); await sleep(700);
    if (cancelRef.current) return;
    setPhase(3); setFreeList(['B']); await sleep(900);
    if (cancelRef.current) return;
    setPhase(4); setFreeList([]);
    setShowWarning(true); await sleep(700);
    if (cancelRef.current) return;

    const msg = 'malloc(64) returned 0x5588abc12340\nSame address as freed Chunk B!\nChunk C overlaps Chunk B — attacker data written';
    setTermText('');
    for (let i = 0; i <= msg.length; i++) {
      if (cancelRef.current) return;
      setTermText(msg.slice(0, i));
      await sleep(16);
    }
    setPhase(5);
    setPlaying(false);
  };

  useEffect(() => () => { cancelRef.current = true; }, []);

  const visibleChunks = () => {
    if (phase === 0) return [];
    if (phase === 1) return [CHUNKS[1]];
    if (phase === 2) return [CHUNKS[1], CHUNKS[2]];
    if (phase === 3) return [CHUNKS[1], CHUNKS[3]];
    return [CHUNKS[1], CHUNKS[4]];
  };

  return (
    <div style={{ maxWidth: '520px', margin: '20px auto' }}>
      <div style={{ display: 'flex', gap: '16px', alignItems: 'flex-start' }}>
        {/* Heap visualization */}
        <div style={{ flex: 1 }}>
          <div style={{ fontSize: '11px', color: '#8b949e', marginBottom: '8px',
            textTransform: 'uppercase', letterSpacing: '0.06em' }}>HEAP</div>
          {phase === 0 && (
            <div style={{ border: '1px dashed #21262d', borderRadius: '6px',
              padding: '20px', textAlign: 'center', color: '#484f58', fontSize: '12px' }}>
              Press Play to allocate chunks
            </div>
          )}
          {visibleChunks().map((c, i) => c && (
            <div key={i} style={{
              border: `1px solid ${c.border}`,
              background: c.color + '22',
              borderRadius: '6px', padding: '10px 14px', marginBottom: '6px',
              fontFamily: 'monospace', fontSize: '13px',
              animation: 'slideDown 0.3s ease-out',
            }}>
              <div style={{ color: c.border, fontWeight: 700 }}>{c.label}</div>
              <div style={{ color: '#8b949e', fontSize: '11px', marginTop: '2px' }}>{c.sub}</div>
            </div>
          ))}
          {showWarning && (
            <div style={{
              border: '1px solid #f85149', background: '#f8514922',
              borderRadius: '6px', padding: '8px 14px', marginTop: '4px',
              fontSize: '12px', color: '#f85149',
            }}>
              ⚠ Pointer to B now reads attacker-controlled data (C)
            </div>
          )}
        </div>

        {/* Freelist panel */}
        <div style={{ width: '120px' }}>
          <div style={{ fontSize: '11px', color: '#8b949e', marginBottom: '8px',
            textTransform: 'uppercase', letterSpacing: '0.06em' }}>TCACHE</div>
          <div style={{
            border: '1px solid #21262d', borderRadius: '6px', padding: '8px 10px',
            minHeight: '60px', fontFamily: 'monospace', fontSize: '12px',
          }}>
            {freeList.length === 0
              ? <span style={{ color: '#484f58' }}>empty</span>
              : freeList.map((f, i) => (
                <div key={i} style={{ color: '#d2a8ff', marginBottom: '2px' }}>
                  [{f}] → null
                </div>
              ))
            }
          </div>
          <div style={{ fontSize: '10px', color: '#484f58', marginTop: '4px', textAlign: 'center' }}>
            freed chunks wait here
          </div>
        </div>
      </div>

      {/* Terminal */}
      {termText && (
        <div style={{
          background: '#0d1117', border: '1px solid #3fb950',
          borderRadius: '6px', padding: '12px 16px', margin: '14px 0',
        }}>
          <pre style={{ color: '#7ee787', fontSize: '12px', margin: 0,
            whiteSpace: 'pre-wrap', fontFamily: 'monospace' }}>{termText}</pre>
        </div>
      )}

      {/* Buttons */}
      <div style={{ display: 'flex', gap: '8px', marginTop: '14px' }}>
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

      <style>{`@keyframes slideDown {
        from { opacity:0; transform:translateY(-8px); }
        to   { opacity:1; transform:translateY(0); }
      }`}</style>
    </div>
  );
}
