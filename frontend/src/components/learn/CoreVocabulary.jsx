import React, { useState } from 'react';

export default function CoreVocabulary() {
  const [viewMode, setViewMode] = useState('definition');

  const terms = [
    {
      title: '1. STACK',
      definition: 'A pile of memory where your program keeps track of what function called what, and what to do next.',
      storyPartA: 'The stack is a region of memory that keeps track of which function called which, in order, like a stack of trays.',
      storyPartB: 'Picture an apartment building where every time a function is called, a new tenant moves onto the next floor up. They unpack their things, do their work, then move out — and the floor below them becomes the active one again.',
      storyPartC: 'In the story, each floor is one function call, and moving out is the function finishing and control returning to whoever called it.',
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
      storyPartA: 'The return address is a stored memory location telling the program exactly where to continue running once the current function ends.',
      storyPartB: 'Before a tenant leaves their apartment, they leave a note on the door saying exactly which floor to send mail back to. Whoever reads that note later knows precisely where to go next.',
      storyPartC: 'In the story, the note on the door is the return address — and if someone rewrites that note, they control where execution goes next.',
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
      storyPartA: 'A buffer overflow happens when a program writes more data into a fixed-size memory space than it was designed to hold, and the extra data spills into neighboring memory.',
      storyPartB: "Imagine a tenant's mailbox that only fits one envelope. Someone stuffs in a huge stack of paper instead, and since mailboxes sit right next to each other, the overflow spills onto the neighboring mailbox and covers up whatever note was sitting there.",
      storyPartC: 'In the story, the neighboring mailbox is the return address, and the spilled paper is attacker-controlled data overwriting it.',
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
      storyPartA: "NX is a security setting that marks certain memory as 'data only' — the computer will refuse to run anything stored there as code.",
      storyPartB: 'The building manager makes a rule: nothing dropped in a mailbox can ever be treated as a work order for staff to carry out — it can only ever be read as a letter, never acted on as an instruction.',
      storyPartC: 'In the story, the mailbox is memory like the buffer, and the rule against acting on its contents is what NX enforces in real memory.',
      visual: (
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%' }}>
          <div style={{ position: 'relative', border: '1px solid #30363d', background: '#21262d', padding: '8px 16px', borderRadius: '6px', fontSize: '11px', color: '#c9d1d9', fontFamily: 'monospace' }}>
            [ STACK MEMORY ]
            <span style={{ position: 'absolute', top: '-10px', right: '-10px', background: '#f85149', color: '#fff', fontSize: '9px', fontWeight: 'bold', padding: '2px 6px', borderRadius: '10px', border: '1px solid #fff' }}>
              NO RUN
            </span>
          </div>
        </div>
      ),
      whyItMatters: "If NX is on, you can't just inject your own code — you have to reuse code that's already there (ROP).",
    },
    {
      title: '5. GADGET',
      definition: "A tiny 2-3 instruction fragment already inside the program's own code, ending in 'return.'",
      storyPartA: 'A gadget is a small, already-existing sequence of instructions inside a program that an attacker can reuse, rather than writing new code.',
      storyPartB: "Since you're not allowed to bring in new tools, you look around the lobby and notice small useful notes already lying around — each one says a short, specific instruction, like 'pick up the phone.'",
      storyPartC: 'In the story, each lying-around note is one gadget — a small borrowed instruction that already existed in the building (the program) before you arrived.',
      visual: (
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%' }}>
          <div style={{ border: '1px solid #bc8cff', background: '#bc8cff15', padding: '6px 12px', borderRadius: '6px', fontFamily: 'monospace', fontSize: '11px', color: '#d2a8ff' }}>
            <span style={{ color: '#ff7b72' }}>pop</span> rdi ; <span style={{ color: '#ff7b72' }}>ret</span>
          </div>
        </div>
      ),
      whyItMatters: 'You chain gadgets together to build actions out of code that already exists.',
    },
    {
      title: '6. ROP (Return-Oriented Programming)',
      definition: 'Chaining multiple gadgets together, one after another, to make the CPU do something useful — without injecting any new code.',
      storyPartA: 'ROP means chaining several of these small borrowed instructions together, one after another, to make the computer do something the original program never intended.',
      storyPartB: "You collect several of those short notes and arrange them in a specific order, so that each one's instruction leads naturally into the next, forming one longer combined plan out of pieces that were never meant to be used together.",
      storyPartC: 'In the story, the arranged sequence of notes is the ROP chain — none of it is new writing, only existing pieces reordered.',
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
      storyPartA: 'PIE means the program loads at a different, random memory address every single time it runs, instead of always the same place.',
      storyPartB: 'Imagine the entire apartment building relocates to a different street every morning. The rooms inside stay arranged exactly the same relative to each other, but the actual street address is new each day.',
      storyPartC: "In the story, the changing street address is the randomized memory location — you need to find out today's address before you can find anything inside.",
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
      storyPartA: 'A stack canary is a secret value placed in memory that gets checked right before a function returns, to detect if an overflow happened.',
      storyPartB: 'The manager places a fragile glass ornament right next to every mailbox. If mail ever overflows the box, the ornament is knocked over first. Before continuing, staff always check if the ornament is still standing.',
      storyPartC: 'In the story, the ornament is the canary value, and it being knocked over is how the program detects an overflow happened before trusting the return address.',
      visual: (
        <div style={{ display: 'flex', gap: '6px', alignItems: 'center', justifyContent: 'center', height: '100%' }}>
          <div style={{ border: '1px solid #e3b341', background: '#e3b34118', padding: '4px 8px', borderRadius: '4px', fontSize: '10px', color: '#e3b341', display: 'flex', alignItems: 'center', gap: '3px' }}>
            canary
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
      storyPartA: 'The GOT is a lookup table a running program uses to find the real memory address of shared functions it calls, like printf.',
      storyPartB: "Whenever a tenant wants to call someone outside the building, they don't dial directly — they ask the front desk, who looks up the current phone number in a shared phone book and connects the call.",
      storyPartC: 'In the story, the shared phone book is the GOT, and the number it looks up is the real address of the function being called.',
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
      storyPartA: 'RELRO is a setting that makes that lookup table read-only after the program starts, so it can never be changed again while running.',
      storyPartB: 'To stop anyone from secretly changing numbers in the phone book, the manager seals it in a locked glass case the moment the building opens for the day. Staff can still read it, but no one can edit it.',
      storyPartC: 'In the story, the locked glass case is Full RELRO — the phone book (GOT) becomes permanently read-only.',
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
      storyPartA: "The heap is a separate area of memory a program can request extra space from while it's running, and give back when done.",
      storyPartB: "Across the street from the apartment building is a self-storage facility. Whenever you need extra space, you ask the front desk for a unit, and when you're finished, you return the key.",
      storyPartC: 'In the story, renting a unit is calling malloc(), and returning the key is calling free().',
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
      storyPartA: 'libc is a shared library of common, ready-made functions — like printing text or running a system command — that almost every program relies on.',
      storyPartB: 'The building already has a fully stocked utility room with tools everyone shares — a working phone line, a printer, a set of master keys. Nobody needs to bring their own version of these things.',
      storyPartC: 'In the story, the shared utility room is libc — a common set of tools already present and available to any program that needs them.',
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
      {/* Intro explain line */}
      <p style={{ textAlign: 'center', fontSize: '13px', color: '#8b949e', marginBottom: '10px' }}>
        Prefer a quick fact, or a story that makes it stick? Either way works — try the story mode if the quick version didn't quite land.
      </p>

      {/* Mode selector toggle */}
      <div style={{ display: 'flex', gap: '8px', marginBottom: '20px', justifyContent: 'center' }}>
        <button onClick={() => setViewMode('definition')} style={{
          padding: '8px 18px', borderRadius: '20px', fontSize: '13px',
          background: viewMode === 'definition' ? '#388bfd' : '#21262d',
          color: viewMode === 'definition' ? '#fff' : '#8b949e',
          border: '1px solid #30363d', cursor: 'pointer',
          fontWeight: viewMode === 'definition' ? 600 : 400,
          transition: 'all 0.15s'
        }}>
          Quick Definitions
        </button>
        <button onClick={() => setViewMode('story')} style={{
          padding: '8px 18px', borderRadius: '20px', fontSize: '13px',
          background: viewMode === 'story' ? '#388bfd' : '#21262d',
          color: viewMode === 'story' ? '#fff' : '#8b949e',
          border: '1px solid #30363d', cursor: 'pointer',
          fontWeight: viewMode === 'story' ? 600 : 400,
          transition: 'all 0.15s'
        }}>
          Tell Me a Story
        </button>
      </div>

      {/* Grid container */}
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
              minHeight: viewMode === 'story' ? '320px' : '220px',
              display: 'flex',
              flexDirection: 'column',
              gap: '10px',
              boxSizing: 'border-box',
              transition: 'min-height 0.2s'
            }}
          >
            <div style={{ fontSize: '16px', fontWeight: 700, color: '#79c0ff' }}>
              {t.title}
            </div>
            <div style={{ flexGrow: 1 }}>
              {viewMode === 'story' ? (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                  <div>
                    <div style={{ fontSize: '10px', fontWeight: 800, color: '#8b949e', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: '3px' }}>
                      IN REAL LIFE
                    </div>
                    <div style={{ fontSize: '13px', color: '#c9d1d9', lineHeight: 1.5 }}>
                      {t.storyPartA}
                    </div>
                  </div>
                  <div>
                    <div style={{ fontSize: '10px', fontWeight: 800, color: '#8b949e', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: '3px' }}>
                      PICTURE IT LIKE THIS
                    </div>
                    <div style={{ fontSize: '13px', color: '#c9d1d9', lineHeight: 1.5 }}>
                      {t.storyPartB}
                    </div>
                  </div>
                  <div>
                    <div style={{ fontSize: '10px', fontWeight: 800, color: '#58a6ff', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: '3px' }}>
                      TRANSLATED BACK
                    </div>
                    <div style={{ fontSize: '13px', color: '#c9d1d9', lineHeight: 1.5 }}>
                      {t.storyPartC}
                    </div>
                  </div>
                </div>
              ) : (
                <div style={{ fontSize: '13px', color: '#c9d1d9', lineHeight: 1.5 }}>
                  {t.definition}
                </div>
              )}
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
