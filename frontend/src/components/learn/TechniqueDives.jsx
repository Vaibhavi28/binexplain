import React, { useState } from 'react';

export default function TechniqueDives() {
  const [expandedCard, setExpandedCard] = useState(null);

  const toggleCard = (id) => {
    setExpandedCard(expandedCard === id ? null : id);
  };

  const dives = [
    {
      id: 'ret2win',
      label: 'ret2win',
      description: 'A secret function exists. Overflow the buffer and jump to it.',
      steps: [
        'Find the win function address in the symbol table: `nm -a ./binary | grep win`',
        'Find the overflow offset: use a cyclic pattern or predict from disassembly disassembly',
        'Craft your exploit payload: `\'A\' * offset + p64(win_address)`',
        'Send the payload: piping directly `payload | ./binary` or via a socket using pwntools'
      ],
      layout: (
        <div style={{ fontFamily: 'monospace', fontSize: '12px', color: '#c9d1d9', background: '#0d1117', border: '1px solid #30363d', borderRadius: '6px', overflow: 'hidden', width: '100%', maxWidth: '450px', margin: '0 auto 16px' }}>
          <div style={{ background: '#21262d', padding: '6px 12px', borderBottom: '1px solid #30363d', fontWeight: 600, fontSize: '11px', textTransform: 'uppercase', color: '#8b949e' }}>Memory Layout (Stack grows down)</div>
          <div style={{ display: 'flex', flexDirection: 'column' }}>
            <div style={{ padding: '10px 14px', borderBottom: '1px solid #21262d', background: '#3c1e1e', display: 'flex', justifyContent: 'space-between' }}>
              <span>[Return Address]</span>
              <span style={{ color: '#ff7b72' }}>➔ Overwritten with win() addr</span>
            </div>
            <div style={{ padding: '10px 14px', borderBottom: '1px solid #21262d', background: '#161b22', display: 'flex', justifyContent: 'space-between' }}>
              <span>[Saved RBP]</span>
              <span style={{ color: '#8b949e' }}>8 Bytes (A\'s)</span>
            </div>
            <div style={{ padding: '10px 14px', borderBottom: '1px solid #21262d', background: '#161b22', display: 'flex', justifyContent: 'space-between' }}>
              <span>[Buffer Padding]</span>
              <span style={{ color: '#8b949e' }}>N Bytes (A\'s)</span>
            </div>
            <div style={{ padding: '10px 14px', background: '#1c2d4a', display: 'flex', justifyContent: 'space-between' }}>
              <span>[Local Buffer (64B)]</span>
              <span style={{ color: '#79c0ff' }}>➔ Your Input Starts Here</span>
            </div>
          </div>
        </div>
      )
    },
    {
      id: 'format_string',
      label: 'Format String Attack',
      description: 'printf(your_input) lets you read and write arbitrary memory.',
      steps: [
        'Confirm the vulnerability: supply format parameters `python3 -c \'print("%p."*20)\' | ./binary`',
        'Find which stack position maps to your input: look for the ASCII representation pattern `0x70252e70` ("%p.")',
        'Leak sensitive stack data or address pointers: use specific selector position indices `%Ns$p`',
        'Overwrite dynamic link tables or target addresses: use pwntools helper function `fmtstr_payload`'
      ],
      layout: (
        <div style={{ fontFamily: 'monospace', fontSize: '12px', color: '#c9d1d9', background: '#0d1117', border: '1px solid #30363d', borderRadius: '6px', overflow: 'hidden', width: '100%', maxWidth: '450px', margin: '0 auto 16px' }}>
          <div style={{ background: '#21262d', padding: '6px 12px', borderBottom: '1px solid #30363d', fontWeight: 600, fontSize: '11px', textTransform: 'uppercase', color: '#8b949e' }}>Stack Frame Arguments Mapping</div>
          <div style={{ display: 'flex', flexDirection: 'column' }}>
            <div style={{ padding: '10px 14px', borderBottom: '1px solid #21262d', background: '#161b22', display: 'flex', justifyContent: 'space-between' }}>
              <span>printf(buf)</span>
              <span style={{ color: '#58a6ff' }}>vulnerable printf call</span>
            </div>
            <div style={{ padding: '10px 14px', borderBottom: '1px solid #21262d', background: '#271b3b', display: 'flex', justifyContent: 'space-between' }}>
              <span>Stack Index 1</span>
              <span style={{ color: '#d2a8ff' }}>Format specifier arg 1 (%p)</span>
            </div>
            <div style={{ padding: '10px 14px', background: '#271b3b', display: 'flex', justifyContent: 'space-between' }}>
              <span>Stack Index N</span>
              <span style={{ color: '#d2a8ff' }}>Location of format string "buf" (0x70252e70 = "%p.")</span>
            </div>
          </div>
        </div>
      )
    },
    {
      id: 'heap_exploitation',
      label: 'Heap Exploitation',
      description: 'Corrupt malloc()/free() metadata to control what malloc() returns.',
      steps: [
        'Identify the heap vulnerability type: look for use-after-free, double-free, or heap overflow bounds issues',
        'Trigger the bug to corrupt freelist structures: target the fastbin or tcache forward links (fd pointers)',
        'Call malloc() to trigger allocation: the heap allocator returns your poisoned target pointer',
        'Overwrite target pointers or values: write control blocks to hijack program execution flow'
      ],
      layout: (
        <div style={{ fontFamily: 'monospace', fontSize: '12px', color: '#c9d1d9', background: '#0d1117', border: '1px solid #30363d', borderRadius: '6px', overflow: 'hidden', width: '100%', maxWidth: '450px', margin: '0 auto 16px' }}>
          <div style={{ background: '#21262d', padding: '6px 12px', borderBottom: '1px solid #30363d', fontWeight: 600, fontSize: '11px', textTransform: 'uppercase', color: '#8b949e' }}>Heap Chunk Layout</div>
          <div style={{ display: 'flex', flexDirection: 'column' }}>
            <div style={{ padding: '10px 14px', borderBottom: '1px solid #21262d', background: '#161b22', display: 'flex', justifyContent: 'space-between' }}>
              <span>prev_size</span>
              <span style={{ color: '#8b949e' }}>Previous chunk size (if free)</span>
            </div>
            <div style={{ padding: '10px 14px', borderBottom: '1px solid #21262d', background: '#281515', display: 'flex', justifyContent: 'space-between' }}>
              <span>size + flags</span>
              <span style={{ color: '#ff7b72' }}>Metadata showing chunk size and flags</span>
            </div>
            <div style={{ padding: '10px 14px', background: '#2b1a14', display: 'flex', justifyContent: 'space-between' }}>
              <span>user data (buffer)</span>
              <span style={{ color: '#ff8b4d' }}>Where actual variable data lives</span>
            </div>
          </div>
        </div>
      )
    },
    {
      id: 'ret2libc',
      label: 'ret2libc',
      description: 'No win function? Use system(\'/bin/sh\') from libc instead.',
      steps: [
        'Leak a libc code address: use dynamic loader resolver entries (GOT) via standard functions like `puts` or `printf`',
        'Calculate library base offset: subtract the known libc static function offset from your dynamic leak address',
        'Calculate target function address: libc base address + system address offset',
        'Locate matching payload command argument: find "/bin/sh" string address inside the library mapped boundaries',
        'Construct and deliver call sequence: hijack return address to launch system(\'/bin/sh\')'
      ],
      layout: (
        <div style={{ fontFamily: 'monospace', fontSize: '12px', color: '#c9d1d9', background: '#0d1117', border: '1px solid #30363d', borderRadius: '6px', overflow: 'hidden', width: '100%', maxWidth: '450px', margin: '0 auto 16px' }}>
          <div style={{ background: '#21262d', padding: '6px 12px', borderBottom: '1px solid #30363d', fontWeight: 600, fontSize: '11px', textTransform: 'uppercase', color: '#8b949e' }}>ret2libc Stack Layout</div>
          <div style={{ display: 'flex', flexDirection: 'column' }}>
            <div style={{ padding: '10px 14px', borderBottom: '1px solid #21262d', background: '#162c1e', display: 'flex', justifyContent: 'space-between' }}>
              <span>[Argument]</span>
              <span style={{ color: '#56d364' }}>Address of "/bin/sh" string</span>
            </div>
            <div style={{ padding: '10px 14px', borderBottom: '1px solid #21262d', background: '#2b2214', display: 'flex', justifyContent: 'space-between' }}>
              <span>[Dummy Return]</span>
              <span style={{ color: '#f0e042' }}>Address to return after system() (4/8 bytes)</span>
            </div>
            <div style={{ padding: '10px 14px', background: '#3c1e1e', display: 'flex', justifyContent: 'space-between' }}>
              <span>[Return Address]</span>
              <span style={{ color: '#ff7b72' }}>Address of system() function</span>
            </div>
          </div>
        </div>
      )
    },
    {
      id: 'rop_chain',
      label: 'ROP Chain',
      description: 'NX enabled? Chain existing code snippets (gadgets) instead.',
      steps: [
        'Find available assembly execution blocks: run tools like `ROPgadget --binary ./binary --rop`',
        'Identify target addresses: locate library base system() addresses and load parameter register gadgets',
        'Chain multiple parameters load gadgets: pop values into registers (e.g. pop rdi; ret to set first argument)',
        'Hijack stack return pointer: arrange gadget address chain followed by target execution systems'
      ],
      layout: (
        <div style={{ fontFamily: 'monospace', fontSize: '12px', color: '#c9d1d9', background: '#0d1117', border: '1px solid #30363d', borderRadius: '6px', overflow: 'hidden', width: '100%', maxWidth: '450px', margin: '0 auto 16px' }}>
          <div style={{ background: '#21262d', padding: '6px 12px', borderBottom: '1px solid #30363d', fontWeight: 600, fontSize: '11px', textTransform: 'uppercase', color: '#8b949e' }}>ROP Gadgets Sequence</div>
          <div style={{ display: 'flex', flexDirection: 'column' }}>
            <div style={{ padding: '10px 14px', borderBottom: '1px solid #21262d', background: '#1c2d4a', display: 'flex', justifyContent: 'space-between' }}>
              <span>0x401234: pop rdi ; ret</span>
              <span style={{ color: '#79c0ff' }}>Pulls "/bin/sh" into RDI</span>
            </div>
            <div style={{ padding: '10px 14px', borderBottom: '1px solid #21262d', background: '#161b22', display: 'flex', justifyContent: 'space-between' }}>
              <span>[bin_sh Address]</span>
              <span style={{ color: '#8b949e' }}>Argument value loading into register</span>
            </div>
            <div style={{ padding: '10px 14px', background: '#3c1e1e', display: 'flex', justifyContent: 'space-between' }}>
              <span>[system Address]</span>
              <span style={{ color: '#ff7b72' }}>Executes system("/bin/sh")</span>
            </div>
          </div>
        </div>
      )
    },
    {
      id: 'shellcode',
      label: 'Shellcode Injection',
      description: 'NX disabled? Write your own code into memory and execute it.',
      steps: [
        'Confirm No-Execute is disabled: run verification checks using `checksec ./binary`',
        'Find target buffer addresses: extract stack address pointers or utilize known non-PIE stack structures',
        'Generate code machine instructions: create assembly payload (e.g. pwntools shellcraft.sh())',
        'Deliver payload: write shellcode to the target buffer and overwrite the stack return address to jump to it'
      ],
      layout: (
        <div style={{ fontFamily: 'monospace', fontSize: '12px', color: '#c9d1d9', background: '#0d1117', border: '1px solid #30363d', borderRadius: '6px', overflow: 'hidden', width: '100%', maxWidth: '450px', margin: '0 auto 16px' }}>
          <div style={{ background: '#21262d', padding: '6px 12px', borderBottom: '1px solid #30363d', fontWeight: 600, fontSize: '11px', textTransform: 'uppercase', color: '#8b949e' }}>Executable Buffer Stack Layout</div>
          <div style={{ display: 'flex', flexDirection: 'column' }}>
            <div style={{ padding: '10px 14px', borderBottom: '1px solid #21262d', background: '#3c1e1e', display: 'flex', justifyContent: 'space-between' }}>
              <span>[Return Address]</span>
              <span style={{ color: '#ff7b72' }}>Points to Start of Shellcode (below)</span>
            </div>
            <div style={{ padding: '10px 14px', borderBottom: '1px solid #21262d', background: '#161b22', display: 'flex', justifyContent: 'space-between' }}>
              <span>[Saved RBP + Padding]</span>
              <span style={{ color: '#8b949e' }}>Overflow padding bytes</span>
            </div>
            <div style={{ padding: '10px 14px', background: '#162c1e', display: 'flex', justifyContent: 'space-between' }}>
              <span>[Shellcode (23B)]</span>
              <span style={{ color: '#56d364' }}>Executes execve("/bin/sh")</span>
            </div>
          </div>
        </div>
      )
    }
  ];

  return (
    <div style={{ maxWidth: '100%', margin: '0 auto' }}>
      <h2 style={{ color: 'var(--text-primary)', fontSize: '20px',
        fontWeight: 600, marginBottom: '8px', textAlign: 'center' }}>
        Technique Deep Dives
      </h2>
      <p style={{ color: 'var(--text-secondary)', fontSize: '14px',
        textAlign: 'center', marginBottom: '24px' }}>
        Explore deep exploit mechanics, step-by-step procedures, and visual stack/heap memory layout diagrams
      </p>

      <div className="learn-card-grid">
        {dives.map((d) => {
          const isExpanded = expandedCard === d.id;
          return (
            <div
              key={d.id}
              style={{
                background: '#161b22',
                border: '1px solid #30363d',
                borderRadius: '8px',
                overflow: 'hidden',
                transition: 'border-color 0.15s'
              }}
            >
              {/* Header */}
              <div
                onClick={() => toggleCard(d.id)}
                style={{
                  padding: '16px 20px',
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  cursor: 'pointer',
                  userSelect: 'none'
                }}
              >
                <div>
                  <h3 style={{ color: '#f0f6fc', fontSize: '16px', fontWeight: 600, margin: 0 }}>
                    {d.label}
                  </h3>
                  <p style={{ color: '#8b949e', fontSize: '12px', margin: '4px 0 0' }}>
                    {d.description}
                  </p>
                </div>
                <span style={{ color: '#8b949e', fontSize: '16px' }}>
                  {isExpanded ? '▲' : '▼'}
                </span>
              </div>

              {/* Collapsible content */}
              {isExpanded && (
                <div style={{
                  padding: '20px',
                  background: '#0d1117',
                  borderTop: '1px solid #30363d'
                }}>
                  {/* Memory layout */}
                  {d.layout}

                  {/* Steps */}
                  <h4 style={{ color: '#f0f6fc', fontSize: '14px', fontWeight: 600, margin: '0 0 10px', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                    Exploitation Steps
                  </h4>
                  <ol style={{ paddingLeft: '20px', margin: 0, display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    {d.steps.map((step, idx) => (
                      <li key={idx} style={{ color: '#c9d1d9', fontSize: '14px', lineHeight: '1.5' }}>
                        {step}
                      </li>
                    ))}
                  </ol>

                  <a href="/" style={{
                    display: 'inline-block', marginTop: '16px',
                    padding: '10px 20px', background: '#238636',
                    border: '1px solid #2ea043', color: 'white',
                    borderRadius: '6px', textDecoration: 'none',
                    fontSize: '14px', fontWeight: 600
                  }}>
                    Try this on a real binary →
                  </a>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
