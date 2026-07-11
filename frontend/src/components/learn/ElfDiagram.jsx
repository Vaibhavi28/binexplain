import React, { useState } from 'react';

export default function ElfDiagram() {
  const [expanded, setExpanded] = useState(null);

  const sections = [
    {
      id: 'text',
      label: '.text',
      sublabel: 'Program code',
      color: '#1c2d4a',
      border: '#388bfd',
      textColor: '#79c0ff',
      explanation: 'This is where the actual program instructions live. When you run a program, the CPU reads and executes instructions from here. This section is readable and executable but not writable — the OS prevents you from changing the code while it runs.',
      example: 'The main() function, vuln(), win() — all of these functions live in .text. When BinExplain disassembles the main function using Capstone, it is reading from this section.',
      attack: 'ret2win attacks jump to a function in .text'
    },
    {
      id: 'rodata',
      label: '.rodata',
      sublabel: 'Read-only data',
      color: '#271b3b',
      border: '#8957e5',
      textColor: '#d2a8ff',
      explanation: 'String constants that never change live here. Strings like \'Hello World\', flag file paths, and error messages. Read-only means an attacker cannot overwrite these without bypassing protections.',
      example: 'The string \'Oh right, here is the flag: %s\' lives in .rodata. When BinExplain detects flag-related strings, it found them here.',
      attack: ''
    },
    {
      id: 'data',
      label: '.data',
      sublabel: 'Initialized global variables',
      color: '#122c2b',
      border: '#1f8282',
      textColor: '#39c5cf',
      explanation: 'Global variables that have a starting value. Unlike .text this section is writable, so attackers who control what gets written here can change program behavior.',
      example: 'A global counter, a configuration flag, a global buffer.',
      attack: ''
    },
    {
      id: 'bss',
      label: '.bss',
      sublabel: 'Uninitialized global variables',
      color: '#122c2b',
      border: '#1f8282',
      textColor: '#39c5cf',
      explanation: 'Global variables with no starting value. The OS fills this with zeros when the program starts. Also writable.',
      example: 'A large global array declared but not filled with data yet.',
      attack: ''
    },
    {
      id: 'stack',
      label: 'STACK',
      sublabel: 'Function call frames',
      color: '#2b2214',
      border: '#d29922',
      textColor: '#f0e040',
      explanation: 'Every time your program calls a function, a new stack frame is pushed onto the stack. It contains: local variables, the saved return address (where to go when the function finishes), and function arguments. The stack grows downward in memory.',
      example: 'When vuln() is called, a stack frame is created. Your local buffer char buf[64] lives here. The return address tells the CPU to go back to main() when vuln() finishes — this is what buffer overflows target.',
      attack: 'Buffer overflows overwrite the return address on the stack'
    },
    {
      id: 'heap',
      label: 'HEAP',
      sublabel: 'Dynamic memory',
      color: '#2b1a14',
      border: '#db6d28',
      textColor: '#ff8b4d',
      explanation: 'Memory your program requests at runtime using malloc(). Unlike the stack, the heap grows upward. The heap manager tracks free and used chunks using metadata stored between allocations.',
      example: 'When a program does malloc(32), a 32-byte chunk appears on the heap. The chunk has hidden metadata before it storing its size. Heap exploitation corrupts this metadata.',
      attack: 'Heap exploitation targets malloc/free metadata'
    },
    {
      id: 'got_plt',
      label: 'GOT/PLT',
      sublabel: 'Function pointers',
      color: '#281515',
      border: '#f85149',
      textColor: '#ff7b72',
      explanation: 'When your program calls printf() or system(), it does not know their exact address until runtime. The GOT (Global Offset Table) stores the real addresses of external functions. The PLT (Procedure Linkage Table) is the stub that looks up the GOT.',
      example: 'The first time printf() is called, the dynamic linker finds its real address in libc and writes it to the GOT. After that, every printf() call reads the GOT to find where to jump.',
      attack: 'GOT overwrites replace function pointers with malicious addresses'
    }
  ];

  return (
    <div style={{ maxWidth: '600px', margin: '0 auto' }}>
      <h2 style={{ color: 'var(--text-primary)', fontSize: '20px',
        fontWeight: 600, marginBottom: '8px', textAlign: 'center' }}>
        Anatomy of an ELF Binary
      </h2>
      <p style={{ color: 'var(--text-secondary)', fontSize: '13px',
        textAlign: 'center', marginBottom: '24px' }}>
        Click any section to learn what lives there and how attackers target it
      </p>

      {sections.map((s) => (
        <div key={s.id} style={{ marginBottom: '6px' }}>
          {/* Section bar */}
          <div
            onClick={() => setExpanded(expanded === s.id ? null : s.id)}
            style={{
              background: expanded === s.id ? s.color : '#161b22',
              border: `1px solid ${s.border}`,
              borderRadius: expanded === s.id ? '8px 8px 0 0' : '8px',
              padding: '12px 20px', cursor: 'pointer',
              display: 'flex', justifyContent: 'space-between',
              alignItems: 'center', transition: 'all 0.15s',
            }}
          >
            <div>
              <span style={{
                fontFamily: 'monospace', fontSize: '15px',
                fontWeight: 700, color: s.textColor
              }}>
                {s.label}
              </span>
              <span style={{
                fontSize: '12px', color: '#8b949e', marginLeft: '12px'
              }}>
                {s.sublabel}
              </span>
            </div>
            <span style={{ color: '#8b949e', fontSize: '16px' }}>
              {expanded === s.id ? '▲' : '▼'}
            </span>
          </div>

          {/* Expanded content */}
          {expanded === s.id && (
            <div style={{
              background: '#0d1117',
              border: `1px solid ${s.border}`,
              borderTop: 'none',
              borderRadius: '0 0 8px 8px',
              padding: '16px 20px'
            }}>
              <p style={{
                color: '#c9d1d9', fontSize: '14px',
                lineHeight: '1.6', margin: '0 0 12px'
              }}>
                {s.explanation}
              </p>
              <div style={{
                background: '#161b22', borderRadius: '6px',
                padding: '10px 14px', borderLeft: '3px solid #e3b341',
                marginBottom: '10px'
              }}>
                <div style={{
                  fontSize: '10px', color: '#e3b341',
                  fontWeight: 600, textTransform: 'uppercase',
                  letterSpacing: '0.08em', marginBottom: '4px'
                }}>
                  Example
                </div>
                <p style={{
                  color: '#c9d1d9', fontSize: '13px',
                  lineHeight: '1.5', margin: 0
                }}>
                  {s.example}
                </p>
              </div>
              {s.attack && (
                <div style={{
                  background: '#1a0d0d', borderRadius: '6px',
                  padding: '8px 14px', borderLeft: '3px solid #f85149'
                }}>
                  <span style={{
                    fontSize: '10px', color: '#f85149',
                    fontWeight: 600, textTransform: 'uppercase',
                    letterSpacing: '0.08em'
                  }}>
                    Attack relevance:{' '}
                  </span>
                  <span style={{ color: '#ffa198', fontSize: '13px' }}>
                    {s.attack}
                  </span>
                </div>
              )}
            </div>
          )}
        </div>
      ))}
    </div>
  );
}
