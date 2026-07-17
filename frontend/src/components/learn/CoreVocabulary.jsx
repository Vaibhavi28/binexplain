import React from 'react';

export default function CoreVocabulary() {
  const terms = [
    {
      title: '1. STACK',
      definition: 'A pile of memory where your program keeps track of what function called what, and what to do next.',
      visual: (
        <div style={{ display: 'flex', flexDirection: 'column-reverse', gap: '3px', alignItems: 'center', width: '120px', margin: '0 auto' }}>
          <div style={{ border: '1px solid #30363d', background: '#21262d', padding: '2px 8px', borderRadius: '4px', fontSize: '10px', width: '100%', textAlign: 'center', color: '#c9d1d9' }}>main()</div>
          <div style={{ border: '1px solid #388bfd', background: '#1c2d4a', padding: '2px 8px', borderRadius: '4px', fontSize: '10px', width: '100%', textAlign: 'center', color: '#79c0ff' }}>vuln()</div>
          <div style={{ border: '1px solid #56d364', background: '#162c1e', padding: '2px 8px', borderRadius: '4px', fontSize: '10px', width: '100%', textAlign: 'center', color: '#56d364' }}>buf[64]</div>
        </div>
      ),
      whyItMatters: 'This is where buffer overflows happen.',
    },
    {
      title: '2. RETURN ADDRESS',
      definition: "A note on the stack telling the CPU 'go back here when this function finishes.'",
      visual: (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '4px', alignItems: 'center', position: 'relative', width: '140px', margin: '0 auto' }}>
          <div style={{ border: '1px solid #f85149', background: '#3a0000', padding: '2px 8px', borderRadius: '4px', fontSize: '10px', color: '#ff7b72', width: '100%', textAlign: 'center', zIndex: 2 }}>RET ADDR</div>
          <div style={{ height: '14px', zIndex: 1, display: 'flex', alignItems: 'center' }}>
            <svg width="24" height="14" viewBox="0 0 24 14" fill="none">
              <path d="M12 0 v14 M12 14 l-4-4 M12 14 l4-4" stroke="#ff7b72" strokeWidth="1.5" />
            </svg>
          </div>
          <div style={{ border: '1px solid #30363d', background: '#21262d', padding: '2px 8px', borderRadius: '4px', fontSize: '10px', color: '#8b949e', width: '100%', textAlign: 'center', zIndex: 2 }}>main()</div>
        </div>
      ),
      whyItMatters: 'Overwrite this note, and you control where the program goes next.',
    },
    {
      title: '3. BUFFER OVERFLOW',
      definition: 'Writing more data into a memory box than it was built to hold, so the extra data spills into the box next to it.',
      visual: (
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', position: 'relative', width: '120px', margin: '0 auto' }}>
          <div style={{ display: 'flex', gap: '8px', color: '#f85149', fontSize: '12px', fontWeight: 'bold', height: '14px' }}>
            <span>↑</span><span>↑</span><span>↑</span>
          </div>
          <div style={{ border: '1px solid #e3b341', background: '#3a2a00', padding: '4px 8px', borderRadius: '4px', fontSize: '11px', color: '#e3b341', width: '100%', textAlign: 'center' }}>
            64 bytes
          </div>
        </div>
      ),
      whyItMatters: 'This is how you reach and overwrite the return address.',
    },
    {
      title: '4. NX (No-Execute)',
      definition: 'A rule that says: this piece of memory can be run as code, OR written to as data — never both at once.',
      visual: (
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%' }}>
          <div style={{ position: 'relative', border: '1px solid #30363d', background: '#21262d', padding: '8px 16px', borderRadius: '6px', fontSize: '11px', color: '#c9d1d9', fontFamily: 'monospace' }}>
            [ STACK MEMORY ]
            <span style={{ position: 'absolute', top: '-10px', right: '-10px', background: '#f85149', color: '#fff', fontSize: '9px', fontWeight: 'bold', padding: '2px 6px', borderRadius: '10px', border: '1px solid #fff' }}>
              🚫 NO RUN
            </span>
          </div>
        </div>
      ),
      whyItMatters: "If NX is on, you can't just inject your own code — you have to reuse code that's already there (ROP).",
    },
    {
      title: '5. GADGET',
      definition: "A tiny 2-3 instruction fragment already inside the program's own code, ending in 'return.'",
      visual: (
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%' }}>
          <div style={{ border: '1px solid #bc8cff', background: '#bc8cff15', padding: '6px 12px', borderRadius: '6px', fontFamily: 'monospace', fontSize: '11px', color: '#d2a8ff' }}>
            <span style={{ color: '#ff7b72' }}>pop</span> rdi ; <span style={{ color: '#ff7b72' }}>ret</span>
          </div>
        </div>
      ),
      whyItMatters: "You chain gadgets together to build actions out of code that already exists.",
    },
    {
      title: '6. ROP (Return-Oriented Programming)',
      definition: 'Chaining multiple gadgets together, one after another, to make the CPU do something useful — without injecting any new code.',
      visual: (
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '4px', width: '100%', height: '100%' }}>
          <div style={{ border: '1px solid #bc8cff', background: '#bc8cff15', padding: '3px 6px', borderRadius: '4px', fontSize: '9px', fontFamily: 'monospace', color: '#d2a8ff' }}>pop rdi</div>
          <div style={{ color: '#8b949e', fontSize: '11px' }}>→</div>
          <div style={{ border: '1px solid #3fb950', background: '#3fb95015', padding: '3px 6px', borderRadius: '4px', fontSize: '9px', fontFamily: 'monospace', color: '#56d364' }}>/bin/sh</div>
          <div style={{ color: '#8b949e', fontSize: '11px' }}>→</div>
          <div style={{ border: '1px solid #f85149', background: '#f8514915', padding: '3px 6px', borderRadius: '4px', fontSize: '9px', fontFamily: 'monospace', color: '#ff7b72' }}>system</div>
        </div>
      ),
      whyItMatters: 'This is how you bypass NX without writing your own shellcode.',
    },
    {
      title: '7. PIE (Position Independent Executable)',
      definition: 'A setting that makes the program load at a random memory address every single time it runs.',
      visual: (
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: '4px', height: '100%', width: '100%' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', width: '160px', position: 'relative' }}>
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
              <span style={{ fontSize: '10px', color: '#e3b341', fontWeight: 'bold' }}>?</span>
              <div style={{ border: '1px dashed #e3b341', background: '#3a2a0044', padding: '4px 8px', borderRadius: '4px', fontSize: '9px', color: '#8b949e', fontFamily: 'monospace' }}>
                0x7f3a...
              </div>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
              <span style={{ fontSize: '10px', color: '#e3b341', fontWeight: 'bold' }}>?</span>
              <div style={{ border: '1px dashed #e3b341', background: '#3a2a0044', padding: '4px 8px', borderRadius: '4px', fontSize: '9px', color: '#8b949e', fontFamily: 'monospace' }}>
                0x7ffd...
              </div>
            </div>
          </div>
        </div>
      ),
      whyItMatters: "If PIE is on, you can't hardcode an address — you need to leak one first.",
    },
    {
      title: '8. CANARY',
      definition: 'A random secret value placed right before the return address. If it changes, the program knows it was attacked and crashes on purpose.',
      visual: (
        <div style={{ display: 'flex', gap: '6px', alignItems: 'center', justifyContent: 'center', height: '100%' }}>
          <div style={{ border: '1px solid #e3b341', background: '#e3b34118', padding: '4px 8px', borderRadius: '4px', fontSize: '10px', color: '#e3b341', display: 'flex', alignItems: 'center', gap: '3px' }}>
            <span>🐤</span> canary
          </div>
          <div style={{ color: '#8b949e', fontSize: '11px' }}>|</div>
          <div style={{ border: '1px solid #f85149', background: '#f8514918', padding: '4px 8px', borderRadius: '4px', fontSize: '10px', color: '#ff7b72' }}>
            RET ADDR
          </div>
        </div>
      ),
      whyItMatters: 'It catches simple buffer overflows before they can hijack the return address.',
    },
    {
      title: '9. GOT (Global Offset Table)',
      definition: 'A lookup table the program uses to find the real memory address of functions like printf() or system() at runtime.',
      visual: (
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%' }}>
          <div style={{ border: '1px solid #30363d', borderRadius: '6px', background: '#0d1117', padding: '4px 8px', width: '160px', fontFamily: 'monospace', fontSize: '9px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', color: '#bc8cff', borderBottom: '1px solid #21262d', paddingBottom: '2px' }}>
              <span>printf</span><span>→ 0x7f2a...</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', color: '#ff7b72', paddingTop: '2px' }}>
              <span>system</span><span>→ 0x7f3b...</span>
            </div>
          </div>
        </div>
      ),
      whyItMatters: 'If this table is writable, you can trick the program into calling a different function than it meant to.',
    },
    {
      title: '10. RELRO (Relocation Read-Only)',
      definition: 'A setting that makes the GOT table read-only after the program starts, so it can never be changed again.',
      visual: (
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%' }}>
          <div style={{ position: 'relative', border: '1px solid #3fb950', borderRadius: '6px', background: '#162c1e', padding: '4px 8px', width: '160px', fontFamily: 'monospace', fontSize: '9px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', color: '#8b949e', borderBottom: '1px solid #21262d', paddingBottom: '2px' }}>
              <span>printf</span><span>→ 0x7f2a...</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', color: '#8b949e', paddingTop: '2px' }}>
              <span>system</span><span>→ 0x7f3b...</span>
            </div>
            <span style={{ position: 'absolute', top: '-8px', right: '-8px', fontSize: '11px', background: '#3fb950', borderRadius: '50%', width: '16px', height: '16px', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              🔒
            </span>
          </div>
        </div>
      ),
      whyItMatters: 'Full RELRO blocks GOT-overwrite attacks entirely.',
    },
    {
      title: '11. HEAP',
      definition: 'A separate area of memory for data your program asks for while it\'s running, using malloc(). You give it back with free().',
      visual: (
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%' }}>
          <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap', width: '130px', justifyContent: 'center', position: 'relative' }}>
            <div style={{ border: '1px solid #d2a8ff', background: '#bc8cff15', fontSize: '9px', padding: '2px 4px', borderRadius: '3px', transform: 'rotate(-5deg)' }}>Chunk A</div>
            <div style={{ border: '1px solid #79c0ff', background: '#388bfd15', fontSize: '9px', padding: '2px 4px', borderRadius: '3px', transform: 'rotate(8deg)' }}>Chunk B</div>
            <div style={{ border: '1px solid #ff7b72', background: '#f8514915', fontSize: '9px', padding: '2px 4px', borderRadius: '3px', transform: 'rotate(-2deg)' }}>Chunk C</div>
          </div>
        </div>
      ),
      whyItMatters: 'Bugs in how a program manages this memory lead to heap exploitation.',
    },
    {
      title: '12. LIBC',
      definition: 'A shared library of common functions — printf, malloc, system — that almost every program on Linux uses.',
      visual: (
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%' }}>
          <div style={{ border: '1px solid #30363d', background: '#21262d', padding: '4px 10px', borderRadius: '6px', width: '130px', textAlign: 'center', fontFamily: 'monospace' }}>
            <div style={{ fontSize: '10px', color: '#58a6ff', fontWeight: 'bold', borderBottom: '1px solid #30363d', paddingBottom: '2px', marginBottom: '2px' }}>libc.so</div>
            <div style={{ display: 'flex', justifyContent: 'space-around', fontSize: '8px', color: '#8b949e' }}>
              <span>system()</span>
              <span>printf()</span>
            </div>
          </div>
        </div>
      ),
      whyItMatters: 'It contains system(), which is how ret2libc attacks get a shell without any code injection.',
    },
  ];

  return (
    <div style={{ margin: '0 auto', padding: '20px 0' }}>
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fill, minmax(320px, 1fr))',
        gap: '20px',
        width: '100%'
      }}>
        {terms.map((t, idx) => (
          <div
            key={idx}
            style={{
              background: '#161b22',
              border: '1px solid #30363d',
              borderRadius: '10px',
              padding: '18px',
              minHeight: '220px',
              display: 'flex',
              flexDirection: 'column',
              gap: '10px',
              boxSizing: 'border-box'
            }}
          >
            <div style={{ fontSize: '16px', fontWeight: 700, color: '#79c0ff' }}>
              {t.title}
            </div>
            <div style={{ fontSize: '13px', color: '#c9d1d9', lineHeight: 1.5, flexGrow: 1 }}>
              {t.definition}
            </div>
            <div style={{ height: '60px', display: 'flex', alignItems: 'center', justifyContent: 'center', overflow: 'hidden' }}>
              {t.visual}
            </div>
            <div style={{
              fontSize: '12px',
              fontStyle: 'italic',
              color: '#8b949e',
              borderTop: '1px solid #21262d',
              paddingTop: '8px',
              marginTop: '4px'
            }}>
              Why it matters: {t.whyItMatters}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
