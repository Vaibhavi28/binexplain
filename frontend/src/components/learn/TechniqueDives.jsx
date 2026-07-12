import React, { useState } from 'react';
import RetwinMemoryAnimation from './RetwinMemoryAnimation';
import RetwinAnimation from './animations/RetwinAnimation';
import FormatStringAnimation from './animations/FormatStringAnimation';
import HeapAnimation from './animations/HeapAnimation';
import Ret2libcAnimation from './animations/Ret2libcAnimation';
import RopChainAnimation from './animations/RopChainAnimation';
import ShellcodeAnimation from './animations/ShellcodeAnimation';

function Ret2winContent({ setActiveSection, setExpandedCard }) {
  const [expandedSteps, setExpandedSteps] = useState({});
  const [expandedMistakes, setExpandedMistakes] = useState({});

  const toggleStep = (idx) => {
    setExpandedSteps(prev => ({ ...prev, [idx]: !prev[idx] }));
  };

  const toggleMistake = (idx) => {
    setExpandedMistakes(prev => ({ ...prev, [idx]: !prev[idx] }));
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px', textAlign: 'left' }}>
      {/* SECTION 1 — DECISION RULE (when to use ret2win) */}
      <div>
        <h4 style={{ color: '#f0f6fc', fontSize: '14px', fontWeight: 600, margin: '0 0 10px', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
          Decision Rule: When to use ret2win
        </h4>
        <div style={{ background: '#161b22', border: '1px solid #30363d', borderRadius: '8px', padding: '16px', display: 'flex', flexDirection: 'column', gap: '10px' }}>
          <div style={{ display: 'flex', alignItems: 'flex-start', gap: '8px', fontSize: '14px', color: '#c9d1d9' }}>
            <span style={{ color: '#56d364', fontWeight: 'bold' }}>✓</span>
            <span>
              <code>nm -a ./binary | grep -i win</code> shows a function like <code>win()</code>, <code>flag()</code>, <code>shell()</code>, or <code>backdoor()</code> that is never called from main
            </span>
          </div>
          <div style={{ display: 'flex', alignItems: 'flex-start', gap: '8px', fontSize: '14px', color: '#c9d1d9' }}>
            <span style={{ color: '#56d364', fontWeight: 'bold' }}>✓</span>
            <span>
              The binary has a buffer overflow reachable from user input (<code>gets()</code>, unbounded <code>strcpy()</code>, or <code>scanf</code> with too-large size)
            </span>
          </div>
          <div style={{ display: 'flex', alignItems: 'flex-start', gap: '8px', fontSize: '14px', color: '#c9d1d9' }}>
            <span style={{ color: '#56d364', fontWeight: 'bold' }}>✓</span>
            <span>
              PIE is disabled OR you already have a leaked base address
            </span>
          </div>

          <div style={{ borderTop: '1px solid #30363d', paddingTop: '10px', marginTop: '6px', fontSize: '13px', color: '#8b949e', display: 'flex', flexDirection: 'column', gap: '4px' }}>
            <div>
              If no win function exists ➔{' '}
              <button
                onClick={() => {
                  if (setActiveSection) setActiveSection('techniques');
                  if (setExpandedCard) setExpandedCard('ret2libc');
                }}
                style={{ background: 'none', border: 'none', color: '#388bfd',
                  textDecoration: 'underline', cursor: 'pointer', fontSize: 'inherit', padding: 0}}
              >
                go to ret2libc card
              </button>
            </div>
            <div>If PIE is enabled and you have no leak ➔ you need a leak first</div>
          </div>
        </div>
      </div>

      {/* SECTION 2 — MEMORY LAYOUT DIAGRAM */}
      <RetwinMemoryAnimation />

      {/* SECTION 3 — EXPLOITATION STEPS */}
      <div>
        <h4 style={{ color: '#f0f6fc', fontSize: '14px', fontWeight: 600, margin: '0 0 10px', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
          Exploitation Steps
        </h4>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
          {/* Step 1 */}
          <div style={{ border: '1px solid #30363d', borderRadius: '8px', overflow: 'hidden' }}>
            <button
              onClick={() => toggleStep(1)}
              style={{ width: '100%', padding: '14px 20px', background: '#161b22', border: 'none', color: '#f0f6fc', textAlign: 'left', fontSize: '14px', fontWeight: 600, cursor: 'pointer', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}
            >
              <span>Step 1: Find the win function address</span>
              <span>{expandedSteps[1] ? '▲' : '▼'}</span>
            </button>
            {expandedSteps[1] && (
              <div style={{ padding: '16px 20px', background: '#0d1117', borderTop: '1px solid #30363d', color: '#c9d1d9', fontSize: '14px', lineHeight: '1.6' }}>
                <div>Command:</div>
                <pre style={{ background: '#161b22', padding: '10px', borderRadius: '6px', fontFamily: 'monospace', fontSize: '13px', margin: '6px 0 12px', overflowX: 'auto' }}>
                  nm -a ./binary | grep -i win
                </pre>
                <div>What to look for:</div>
                <div style={{ color: '#58a6ff', margin: '4px 0 12px' }}>
                  A line like <code>"0000000000401196 T win"</code>
                </div>
                <div>The address (0x401196) is what you will write to the return address.</div>
              </div>
            )}
          </div>

          {/* Step 2 */}
          <div style={{ border: '1px solid #30363d', borderRadius: '8px', overflow: 'hidden' }}>
            <button
              onClick={() => toggleStep(2)}
              style={{ width: '100%', padding: '14px 20px', background: '#161b22', border: 'none', color: '#f0f6fc', textAlign: 'left', fontSize: '14px', fontWeight: 600, cursor: 'pointer', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}
            >
              <span>Step 2: Find the overflow offset</span>
              <span>{expandedSteps[2] ? '▲' : '▼'}</span>
            </button>
            {expandedSteps[2] && (
              <div style={{ padding: '16px 20px', background: '#0d1117', borderTop: '1px solid #30363d', color: '#c9d1d9', fontSize: '14px', lineHeight: '1.6' }}>
                <div>Command:</div>
                <pre style={{ background: '#161b22', padding: '10px', borderRadius: '6px', fontFamily: 'monospace', fontSize: '13px', margin: '6px 0 12px', overflowX: 'auto' }}>
                  python3 -c "from pwn import *; print(cyclic(200))" | ./binary
                </pre>
                <div>Then check the crash address and run:</div>
                <code style={{ background: '#161b22', padding: '4px 8px', borderRadius: '4px', display: 'inline-block', margin: '6px 0 12px' }}>cyclic_find(crash_address)</code>
                <div>BinExplain already predicted this — check the "Overflow Offset" card.</div>
              </div>
            )}
          </div>

          {/* Step 3 */}
          <div style={{ border: '1px solid #30363d', borderRadius: '8px', overflow: 'hidden' }}>
            <button
              onClick={() => toggleStep(3)}
              style={{ width: '100%', padding: '14px 20px', background: '#161b22', border: 'none', color: '#f0f6fc', textAlign: 'left', fontSize: '14px', fontWeight: 600, cursor: 'pointer', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}
            >
              <span>Step 3: Build the payload</span>
              <span>{expandedSteps[3] ? '▲' : '▼'}</span>
            </button>
            {expandedSteps[3] && (
              <div style={{ padding: '16px 20px', background: '#0d1117', borderTop: '1px solid #30363d', color: '#c9d1d9', fontSize: '14px', lineHeight: '1.6' }}>
                <div>Command:</div>
                <pre style={{ background: '#161b22', padding: '10px', borderRadius: '6px', fontFamily: 'monospace', fontSize: '13px', margin: '6px 0', overflowX: 'auto' }}>
{`python3 -c "
from pwn import *
payload = b'A' * OFFSET + p64(WIN_ADDR)
print(payload)
" | ./binary`}
                </pre>
                <div style={{ marginTop: '12px' }}>Replace <code>OFFSET</code> with your offset number and <code>WIN_ADDR</code> with win() address.</div>
              </div>
            )}
          </div>

          {/* Step 4 */}
          <div style={{ border: '1px solid #30363d', borderRadius: '8px', overflow: 'hidden' }}>
            <button
              onClick={() => toggleStep(4)}
              style={{ width: '100%', padding: '14px 20px', background: '#161b22', border: 'none', color: '#f0f6fc', textAlign: 'left', fontSize: '14px', fontWeight: 600, cursor: 'pointer', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}
            >
              <span>Step 4: Run the pwntools template</span>
              <span>{expandedSteps[4] ? '▲' : '▼'}</span>
            </button>
            {expandedSteps[4] && (
              <div style={{ padding: '16px 20px', background: '#0d1117', borderTop: '1px solid #30363d', color: '#c9d1d9', fontSize: '14px', lineHeight: '1.6' }}>
                <div>Your template <code>exploit_BINARY.py</code> is already generated by BinExplain.</div>
                <div style={{ marginTop: '8px' }}>Command:</div>
                <pre style={{ background: '#161b22', padding: '10px', borderRadius: '6px', fontFamily: 'monospace', fontSize: '13px', margin: '6px 0 12px', overflowX: 'auto' }}>
                  python3 exploit_BINARY.py
                </pre>
                <div>Modify the offset and win_addr lines if needed.</div>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* SECTION 4 — COMMON MISTAKES */}
      <div>
        <h4 style={{ color: '#f0f6fc', fontSize: '14px', fontWeight: 600, margin: '0 0 10px', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
          Common Mistakes
        </h4>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
          {/* Mistake 1 */}
          <div style={{ border: '1px solid #30363d', borderRadius: '8px', overflow: 'hidden' }}>
            <button
              onClick={() => toggleMistake(1)}
              style={{ width: '100%', padding: '14px 20px', background: '#161b22', border: 'none', color: '#f0f6fc', textAlign: 'left', fontSize: '14px', fontWeight: 600, cursor: 'pointer', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}
            >
              <span>MISTAKE 1: Wrong offset (too short)</span>
              <span>{expandedMistakes[1] ? '▲' : '▼'}</span>
            </button>
            {expandedMistakes[1] && (
              <div style={{ padding: '16px 20px', background: '#0d1117', borderTop: '1px solid #30363d', color: '#c9d1d9', fontSize: '14px', lineHeight: '1.6' }}>
                <div><strong>Symptom:</strong> Program runs normally, exits cleanly, no flag printed.</div>
                <div><strong>Cause:</strong> Padding did not reach the return address.</div>
                <div><strong>Fix:</strong> Increase offset. Use cyclic pattern instead of guessing.</div>
              </div>
            )}
          </div>

          {/* Mistake 2 */}
          <div style={{ border: '1px solid #30363d', borderRadius: '8px', overflow: 'hidden' }}>
            <button
              onClick={() => toggleMistake(2)}
              style={{ width: '100%', padding: '14px 20px', background: '#161b22', border: 'none', color: '#f0f6fc', textAlign: 'left', fontSize: '14px', fontWeight: 600, cursor: 'pointer', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}
            >
              <span>MISTAKE 2: Wrong offset (too long)</span>
              <span>{expandedMistakes[2] ? '▲' : '▼'}</span>
            </button>
            {expandedMistakes[2] && (
              <div style={{ padding: '16px 20px', background: '#0d1117', borderTop: '1px solid #30363d', color: '#c9d1d9', fontSize: '14px', lineHeight: '1.6' }}>
                <div><strong>Symptom:</strong> Segmentation fault immediately, or "stack smashing detected"</div>
                <div><strong>Cause:</strong> Wrote past the return address into unrelated memory.</div>
                <div><strong>Fix:</strong> Use <code>cyclic_find()</code> for the exact number.</div>
              </div>
            )}
          </div>

          {/* Mistake 3 */}
          <div style={{ border: '1px solid #30363d', borderRadius: '8px', overflow: 'hidden' }}>
            <button
              onClick={() => toggleMistake(3)}
              style={{ width: '100%', padding: '14px 20px', background: '#161b22', border: 'none', color: '#f0f6fc', textAlign: 'left', fontSize: '14px', fontWeight: 600, cursor: 'pointer', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}
            >
              <span>MISTAKE 3: Wrong address format</span>
              <span>{expandedMistakes[3] ? '▲' : '▼'}</span>
            </button>
            {expandedMistakes[3] && (
              <div style={{ padding: '16px 20px', background: '#0d1117', borderTop: '1px solid #30363d', color: '#c9d1d9', fontSize: '14px', lineHeight: '1.6' }}>
                <div><strong>Symptom:</strong> Segfault at a weird address like 0x4100 or 0x0000...196</div>
                <div><strong>Cause:</strong> Used <code>p32()</code> on a 64-bit binary or wrong endianness.</div>
                <div><strong>Fix:</strong> Check <code>file ./binary</code> — use <code>p64()</code> for 64-bit, <code>p32()</code> for 32-bit.</div>
              </div>
            )}
          </div>

          {/* Mistake 4 */}
          <div style={{ border: '1px solid #30363d', borderRadius: '8px', overflow: 'hidden' }}>
            <button
              onClick={() => toggleMistake(4)}
              style={{ width: '100%', padding: '14px 20px', background: '#161b22', border: 'none', color: '#f0f6fc', textAlign: 'left', fontSize: '14px', fontWeight: 600, cursor: 'pointer', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}
            >
              <span>MISTAKE 4: PIE is enabled</span>
              <span>{expandedMistakes[4] ? '▲' : '▼'}</span>
            </button>
            {expandedMistakes[4] && (
              <div style={{ padding: '16px 20px', background: '#0d1117', borderTop: '1px solid #30363d', color: '#c9d1d9', fontSize: '14px', lineHeight: '1.6' }}>
                <div><strong>Symptom:</strong> Exploit works once then fails randomly every other run.</div>
                <div><strong>Cause:</strong> PIE randomizes the binary base address each run.</div>
                <div><strong>Fix:</strong> Check checksec output. If PIE=Enabled you need a leak first.</div>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* SECTION 5 — DIFFICULTY TIERS */}
      <div>
        <h4 style={{ color: '#f0f6fc', fontSize: '14px', fontWeight: 600, margin: '0 0 10px', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
          Difficulty Tiers
        </h4>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '16px' }}>
          {/* Tier 1 */}
          <div style={{ background: '#161b22', border: '1px solid #30363d', borderRadius: '8px', padding: '16px', display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
            <div>
              <div style={{ fontSize: '12px', fontWeight: 700, color: '#56d364', textTransform: 'uppercase', marginBottom: '8px' }}>Tier 1 — No protections (Easy)</div>
              <p style={{ color: '#c9d1d9', fontSize: '13px', margin: '0 0 12px', lineHeight: '1.5' }}>
                NX: disabled, PIE: disabled, Canary: none
              </p>
            </div>
            <div style={{ fontSize: '12px', color: '#8b949e', fontStyle: 'italic' }}>
              Just find offset + overwrite return address. Done.
            </div>
          </div>

          {/* Tier 2 */}
          <div style={{ background: '#161b22', border: '1px solid #30363d', borderRadius: '8px', padding: '16px', display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
            <div>
              <div style={{ fontSize: '12px', fontWeight: 700, color: '#f0e042', textTransform: 'uppercase', marginBottom: '8px' }}>Tier 2 — Canary enabled (Medium)</div>
              <p style={{ color: '#c9d1d9', fontSize: '13px', margin: '0 0 12px', lineHeight: '1.5' }}>
                Must leak or bypass the canary first.
              </p>
            </div>
            <div style={{ fontSize: '12px', color: '#8b949e', fontStyle: 'italic' }}>
              Often done via a format string bug in the same binary.
            </div>
          </div>

          {/* Tier 3 */}
          <div style={{ background: '#161b22', border: '1px solid #30363d', borderRadius: '8px', padding: '16px', display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
            <div>
              <div style={{ fontSize: '12px', fontWeight: 700, color: '#ff7b72', textTransform: 'uppercase', marginBottom: '8px' }}>Tier 3 — Canary + PIE (Hard)</div>
              <p style={{ color: '#c9d1d9', fontSize: '13px', margin: '0 0 12px', lineHeight: '1.5' }}>
                Need two leaks: one for canary, one for binary base address.
              </p>
            </div>
            <div style={{ fontSize: '12px', color: '#8b949e', fontStyle: 'italic' }}>
              Format string or other info leak primitive needed first.
            </div>
          </div>

          {/* Tier 4 */}
          <div style={{ background: '#161b22', border: '1px solid #30363d', borderRadius: '8px', padding: '16px', display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
            <div>
              <div style={{ fontSize: '12px', fontWeight: 700, color: '#bc8cff', textTransform: 'uppercase', marginBottom: '8px' }}>Tier 4 — Full RELRO + Canary + PIE + NX (Very Hard)</div>
              <p style={{ color: '#c9d1d9', fontSize: '13px', margin: '0 0 12px', lineHeight: '1.5' }}>
                Same as Tier 3 but GOT overwrite is also blocked.
              </p>
            </div>
            <div style={{ fontSize: '12px', color: '#8b949e', fontStyle: 'italic' }}>
              Consider{' '}
              <button
                onClick={() => {
                  if (setActiveSection) setActiveSection('techniques');
                  if (setExpandedCard) setExpandedCard('rop_chain');
                }}
                style={{ background: 'none', border: 'none', color: '#388bfd',
                  textDecoration: 'underline', cursor: 'pointer', fontSize: 'inherit', padding: 0}}
              >
                ROP chain
              </button>
              {' or '}
              <button
                onClick={() => {
                  if (setActiveSection) setActiveSection('techniques');
                  if (setExpandedCard) setExpandedCard('ret2libc');
                }}
                style={{ background: 'none', border: 'none', color: '#388bfd',
                  textDecoration: 'underline', cursor: 'pointer', fontSize: 'inherit', padding: 0}}
              >
                ret2libc
              </button>
              {' instead.'}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export default function TechniqueDives({ setActiveSection }) {
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
      layout: <RetwinAnimation />
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
      layout: <FormatStringAnimation />
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
      layout: <HeapAnimation />
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
      layout: <Ret2libcAnimation />
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
      layout: <RopChainAnimation />
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
      layout: <ShellcodeAnimation />
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
                  {d.id === 'ret2win' ? (
                    <Ret2winContent setActiveSection={setActiveSection} setExpandedCard={setExpandedCard} />
                  ) : (
                    <>
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
                    </>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
