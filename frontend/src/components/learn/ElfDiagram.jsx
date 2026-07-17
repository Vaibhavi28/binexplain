import React, { useState, useEffect } from 'react';

export default function ElfDiagram() {
  const [stage, setStage] = useState(1);
  const [showTranslation, setShowTranslation] = useState(false);
  const [selectedSection, setSelectedSection] = useState(null);
  const [selectedGap, setSelectedGap] = useState(null);
  const [prefersReducedMotion, setPrefersReducedMotion] = useState(false);

  // Check for prefers-reduced-motion setting
  useEffect(() => {
    const mediaQuery = window.matchMedia('(prefers-reduced-motion: reduce)');
    setPrefersReducedMotion(mediaQuery.matches);
    const listener = (e) => setPrefersReducedMotion(e.matches);
    mediaQuery.addEventListener('change', listener);
    return () => mediaQuery.removeEventListener('change', listener);
  }, []);

  const totalStages = 4;

  const handleNext = () => {
    if (stage < totalStages) {
      setStage(prev => prev + 1);
      resetStageInteractions();
    }
  };

  const handleBack = () => {
    if (stage > 1) {
      setStage(prev => prev - 1);
      resetStageInteractions();
    }
  };

  const resetStageInteractions = () => {
    setShowTranslation(false);
    setSelectedSection(null);
    setSelectedGap(null);
  };

  const stageStyle = {
    animation: prefersReducedMotion ? 'none' : 'fadeIn 0.5s ease-in-out',
    opacity: 1
  };

  return (
    <div style={{
      maxWidth: '750px',
      margin: '0 auto',
      background: '#161b22',
      border: '1px solid #30363d',
      borderRadius: '12px',
      padding: '32px',
      boxShadow: '0 8px 32px rgba(0, 0, 0, 0.4)',
      color: '#c9d1d9',
      fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif'
    }}>
      {/* CSS Keyframes for fade-in effect */}
      <style>{`
        @keyframes fadeIn {
          from { opacity: 0; transform: translateY(6px); }
          to { opacity: 1; transform: translateY(0); }
        }
        .stage-card-hover:hover {
          border-color: #388bfd !important;
          background: #1f242c !important;
          transform: translateY(-2px);
        }
        .gap-button-hover {
          transition: all 0.2s ease-in-out;
        }
        .gap-button-hover:hover {
          background: #21262d !important;
          border-color: #8b949e !important;
        }
      `}</style>

      {/* Progress Bar & Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '24px' }}>
        <span style={{
          fontSize: '11px',
          fontWeight: 700,
          color: '#58a6ff',
          textTransform: 'uppercase',
          letterSpacing: '0.1em'
        }}>
          Stage {stage} of {totalStages}
        </span>
        <div style={{ display: 'flex', gap: '6px' }}>
          {[1, 2, 3, 4].map(idx => (
            <div key={idx} style={{
              width: '28px',
              height: '5px',
              borderRadius: '3px',
              background: idx <= stage ? '#388bfd' : '#30363d',
              transition: 'background 0.3s ease'
            }} />
          ))}
        </div>
      </div>

      {/* ==================== STAGE 1 ==================== */}
      {stage === 1 && (
        <div style={stageStyle}>
          <h3 style={{ margin: '0 0 8px', fontSize: '22px', fontWeight: 700, color: '#f0f6fc' }}>
            What is a "binary file"?
          </h3>
          <p style={{ fontSize: '15px', lineHeight: '1.6', color: '#c9d1d9', marginBottom: '24px', maxWidth: '640px' }}>
            When you write code, it is human-readable. But computers only understand 0s and 1s (called "binary"). 
            A "compiler" is a tool that translates your human-readable code into raw "binary instructions" the CPU understands. 
            The finished product is called a "binary file" or "executable".
          </p>

          {/* Visual: Side-by-Side Code Translation */}
          <div style={{
            display: 'flex',
            flexDirection: 'column',
            gap: '16px',
            background: '#0d1117',
            border: '1px solid #30363d',
            borderRadius: '8px',
            padding: '24px',
            marginBottom: '24px'
          }}>
            <div style={{
              display: 'flex',
              justifyContent: 'space-around',
              alignItems: 'center',
              flexWrap: 'wrap',
              gap: '16px'
            }}>
              {/* Human-Readable Source */}
              <div style={{ textAlign: 'center', flex: 1, minWidth: '150px' }}>
                <div style={{ fontSize: '11px', color: '#8b949e', textTransform: 'uppercase', fontWeight: 600, marginBottom: '8px' }}>
                  C Source Code
                </div>
                <div style={{
                  background: '#161b22',
                  border: '1px solid #21262d',
                  borderRadius: '6px',
                  padding: '12px',
                  fontFamily: 'monospace',
                  fontSize: '13px',
                  color: '#79c0ff',
                  textAlign: 'left'
                }}>
                  int main() &#123;<br/>
                  &nbsp;&nbsp;return 0;<br/>
                  &#125;
                </div>
              </div>

              {/* Translation Indicator / Compiler Arrow */}
              <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
                <span style={{ fontSize: '20px' }}>⚙️</span>
                <span style={{ fontSize: '11px', color: '#8b949e', fontWeight: 500, margin: '4px 0' }}>"Compiler"</span>
                <span style={{ color: '#58a6ff', fontSize: '18px' }}>➔</span>
              </div>

              {/* Binary Machine Code */}
              <div style={{ textAlign: 'center', flex: 1, minWidth: '150px' }}>
                <div style={{ fontSize: '11px', color: '#8b949e', textTransform: 'uppercase', fontWeight: 600, marginBottom: '8px' }}>
                  "Binary File"
                </div>
                <div style={{
                  background: '#161b22',
                  border: '1px solid #21262d',
                  borderRadius: '6px',
                  padding: '12px',
                  fontFamily: 'monospace',
                  fontSize: '13px',
                  color: '#7ee787',
                  letterSpacing: '1px',
                  wordBreak: 'break-all'
                }}>
                  0111f30f 20000000 0000b800 000000c3
                </div>
              </div>
            </div>

            {/* Interactive Toggle */}
            <div style={{ textAlign: 'center', marginTop: '12px' }}>
              <button
                onClick={() => setShowTranslation(prev => !prev)}
                style={{
                  background: '#21262d',
                  border: '1px solid #30363d',
                  borderRadius: '6px',
                  color: '#58a6ff',
                  padding: '8px 16px',
                  fontSize: '13px',
                  fontWeight: 600,
                  cursor: 'pointer',
                  transition: 'all 0.15s'
                }}
              >
                {showTranslation ? 'Hide Real-World Translation' : 'See Real-World Translation'}
              </button>

              {showTranslation && (
                <div style={{
                  marginTop: '16px',
                  padding: '16px',
                  background: '#161b22',
                  border: '1px solid #30363d',
                  borderRadius: '6px',
                  textAlign: 'left',
                  animation: prefersReducedMotion ? 'none' : 'fadeIn 0.5s ease-out'
                }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', flexWrap: 'wrap', gap: '12px' }}>
                    <div style={{ flex: 1, minWidth: '200px' }}>
                      <div style={{ fontSize: '11px', color: '#8b949e', marginBottom: '4px' }}>C Statement:</div>
                      <code style={{ color: '#ff7b72', fontSize: '13px' }}>int x = 5;</code>
                    </div>
                    <div style={{ flex: 1, minWidth: '200px' }}>
                      <div style={{ fontSize: '11px', color: '#8b949e', marginBottom: '4px' }}>Hexadecimal CPU Instruction:</div>
                      <code style={{ color: '#7ee787', fontSize: '13px' }}>48 c7 45 fc 05 00 00 00</code>
                    </div>
                  </div>
                  <div style={{ fontSize: '12px', color: '#8b949e', marginTop: '12px', lineHeight: '1.4' }}>
                    This exact sequence of numbers tells the x86-64 CPU processor to load the value 5 into a spot in memory. 
                    This is what execution looks like at the lowest level.
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* ==================== STAGE 2 ==================== */}
      {stage === 2 && (
        <div style={stageStyle}>
          <h3 style={{ margin: '0 0 8px', fontSize: '22px', fontWeight: 700, color: '#f0f6fc' }}>
            What is inside a "binary file"?
          </h3>
          <p style={{ fontSize: '15px', lineHeight: '1.6', color: '#c9d1d9', marginBottom: '24px' }}>
            A "binary file" is not just a random blob of numbers. It is organized into named folders called "sections", 
            much like a book is organized into a table of contents, main text, and an appendix.
          </p>

          <div style={{ display: 'flex', gap: '24px', flexWrap: 'wrap' }}>
            {/* Left Column: book representation */}
            <div style={{
              flex: 1,
              minWidth: '240px',
              display: 'flex',
              flexDirection: 'column',
              gap: '8px'
            }}>
              <div style={{ fontSize: '12px', color: '#8b949e', textTransform: 'uppercase', fontWeight: 700, marginBottom: '4px' }}>
                Click a section to inspect it
              </div>

              {[
                { id: 'text', label: '▶ The Instructions (.text)', color: '#1c2d4a', border: '#388bfd' },
                { id: 'rodata', label: '📝 The Strings (.rodata)', color: '#271b3b', border: '#8957e5' },
                { id: 'data', label: '📦 The Data (.data / .bss)', color: '#122c2b', border: '#1f8282' },
                { id: 'stack', label: '📚 The Stack (scratchpad)', color: '#2b2214', border: '#d29922' },
                { id: 'heap', label: '🗃️ The Heap (dynamic)', color: '#2b1a14', border: '#db6d28' },
              ].map(sec => (
                <button
                  key={sec.id}
                  onClick={() => setSelectedSection(sec.id)}
                  style={{
                    background: selectedSection === sec.id ? sec.color : '#0d1117',
                    border: `1px solid ${selectedSection === sec.id ? sec.border : '#30363d'}`,
                    borderRadius: '6px',
                    padding: '12px 16px',
                    color: '#c9d1d9',
                    fontSize: '13px',
                    fontWeight: 600,
                    textAlign: 'left',
                    cursor: 'pointer',
                    transition: 'all 0.15s',
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center'
                  }}
                  className="stage-card-hover"
                >
                  <span>{sec.label}</span>
                  <span style={{ color: '#8b949e', fontSize: '11px' }}>
                    {selectedSection === sec.id ? 'Active' : 'Click'}
                  </span>
                </button>
              ))}
            </div>

            {/* Right Column: details panel */}
            <div style={{
              flex: 1.2,
              minWidth: '280px',
              background: '#0d1117',
              border: '1px solid #30363d',
              borderRadius: '8px',
              padding: '24px',
              display: 'flex',
              flexDirection: 'column',
              justifyContent: 'center',
              minHeight: '260px'
            }}>
              {!selectedSection ? (
                <div style={{ textAlign: 'center', color: '#8b949e' }}>
                  <span style={{ fontSize: '28px', display: 'block', marginBottom: '8px' }}>📂</span>
                  Select a section card on the left to learn what resides in that memory region.
                </div>
              ) : (
                <div style={{ animation: prefersReducedMotion ? 'none' : 'fadeIn 0.5s ease-out' }}>
                  {selectedSection === 'text' && (
                    <>
                      <h4 style={{ margin: '0 0 8px', color: '#58a6ff', fontSize: '16px' }}>The Instructions</h4>
                      <p style={{ margin: 0, fontSize: '14px', lineHeight: '1.6' }}>
                        <strong>.text section</strong> — This is the actual code. Every function you can call, every if/else statement, 
                        and every loop lives here. This is what the CPU reads and executes block-by-block. 
                        It is locked by the operating system so it cannot be overwritten while running.
                      </p>
                    </>
                  )}
                  {selectedSection === 'rodata' && (
                    <>
                      <h4 style={{ margin: '0 0 8px', color: '#d2a8ff', fontSize: '16px' }}>The Strings</h4>
                      <p style={{ margin: 0, fontSize: '14px', lineHeight: '1.6' }}>
                        <strong>.rodata section</strong> — Text and messages that never change. 
                        Error messages, flag file paths, and 'Hello World' strings. 
                        These are baked directly into the binary at compile time.
                      </p>
                    </>
                  )}
                  {selectedSection === 'data' && (
                    <>
                      <h4 style={{ margin: '0 0 8px', color: '#39c5cf', fontSize: '16px' }}>The Data</h4>
                      <p style={{ margin: 0, fontSize: '14px', lineHeight: '1.6' }}>
                        <strong>.data / .bss sections</strong> — Global variables. 
                        Variables and structures the program needs to remember while it runs. 
                        Unlike fixed strings, the values inside these sections can change during execution.
                      </p>
                    </>
                  )}
                  {selectedSection === 'stack' && (
                    <>
                      <h4 style={{ margin: '0 0 8px', color: '#f0e042', fontSize: '16px' }}>The Stack</h4>
                      <p style={{ margin: 0, fontSize: '14px', lineHeight: '1.6' }}>
                        <strong>The Stack</strong> — A scratchpad for each function call. 
                        Every time a function runs, it gets its own temporary workspace. Local variables live here. 
                        When the function ends, this space is reclaimed. 
                        <br/>
                        <span style={{ color: '#ff7b72', fontWeight: 600 }}>IMPORTANT:</span> This is where "buffer overflows" occur.
                      </p>
                    </>
                  )}
                  {selectedSection === 'heap' && (
                    <>
                      <h4 style={{ margin: '0 0 8px', color: '#ff8b4d', fontSize: '16px' }}>The Heap</h4>
                      <p style={{ margin: 0, fontSize: '14px', lineHeight: '1.6' }}>
                        <strong>The Heap</strong> — Memory your program requests while running. 
                        Used for things that do not fit neatly into function calls. 
                        <code>malloc()</code> and <code>free()</code> manage this. 
                        Heap vulnerabilities involve confusing the allocator about what memory is in use.
                      </p>
                    </>
                  )}
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* ==================== STAGE 3 ==================== */}
      {stage === 3 && (
        <div style={stageStyle}>
          <h3 style={{ margin: '0 0 8px', fontSize: '22px', fontWeight: 700, color: '#f0f6fc' }}>
            What makes a binary vulnerable?
          </h3>
          <p style={{ fontSize: '15px', lineHeight: '1.6', color: '#c9d1d9', marginBottom: '24px' }}>
            A "vulnerability" is a gap between what the programmer intended and what the code actually allows. 
            When these gaps exist, users can feed unexpected inputs that change the program's execution path.
          </p>

          {/* Scale balance representation */}
          <div style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            background: '#0d1117',
            border: '1px solid #30363d',
            borderRadius: '8px',
            padding: '16px 24px',
            marginBottom: '20px',
            gap: '12px'
          }}>
            <div style={{ flex: 1, textAlign: 'center', fontSize: '13px', color: '#79c0ff' }}>
              😇 Programmer's Intent
            </div>
            <div style={{ fontSize: '20px', display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
              ⚖️
              <span style={{ fontSize: '10px', color: '#ff7b72', marginTop: '2px' }}>Vulnerable Gap</span>
            </div>
            <div style={{ flex: 1, textAlign: 'center', fontSize: '13px', color: '#ff7b72' }}>
              😈 What Actually Happens
            </div>
          </div>

          {/* 3 Interactive Gaps list */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
            {[
              {
                id: 'gap1',
                title: 'Gap 1: Size Limit Forgotten',
                intent: 'Users will type a short name',
                actual: 'Users can type ANYTHING and gets() will read it all',
                result: 'Buffer Overflow'
              },
              {
                id: 'gap2',
                title: 'Gap 2: Format String Passed Directly',
                intent: 'I just want to print what the user typed',
                actual: 'printf(user_input) — user controls the formatting values',
                result: 'Format String Vulnerability'
              },
              {
                id: 'gap3',
                title: 'Gap 3: Memory Reused After Freeing',
                intent: 'I freed that memory, nobody uses it now',
                actual: 'The pointer still exists and the program uses it anyway',
                result: 'Use-After-Free'
              }
            ].map(gap => (
              <div key={gap.id} style={{
                background: '#0d1117',
                border: '1px solid #30363d',
                borderRadius: '8px',
                overflow: 'hidden'
              }}>
                <button
                  onClick={() => setSelectedGap(selectedGap === gap.id ? null : gap.id)}
                  style={{
                    width: '100%',
                    background: 'none',
                    border: 'none',
                    padding: '14px 20px',
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    color: '#f0f6fc',
                    fontSize: '14px',
                    fontWeight: 600,
                    cursor: 'pointer',
                    textAlign: 'left'
                  }}
                  className="gap-button-hover"
                >
                  <span>{gap.title}</span>
                  <span style={{ color: '#8b949e', fontSize: '12px' }}>
                    {selectedGap === gap.id ? 'Close' : 'Inspect'}
                  </span>
                </button>
                {selectedGap === gap.id && (
                  <div style={{
                    padding: '16px 20px',
                    borderTop: '1px solid #30363d',
                    background: '#161b22',
                    fontSize: '13px',
                    lineHeight: '1.6',
                    animation: prefersReducedMotion ? 'none' : 'fadeIn 0.5s ease-out'
                  }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', flexWrap: 'wrap', gap: '12px', marginBottom: '10px' }}>
                      <div style={{ flex: 1, minWidth: '180px' }}>
                        <span style={{ color: '#8b949e', fontSize: '11px', textTransform: 'uppercase', display: 'block' }}>Programmer Thought:</span>
                        <span style={{ color: '#88f' }}>"{gap.intent}"</span>
                      </div>
                      <div style={{ flex: 1, minWidth: '180px' }}>
                        <span style={{ color: '#8b949e', fontSize: '11px', textTransform: 'uppercase', display: 'block' }}>What Code Allows:</span>
                        <span style={{ color: '#ffa198' }}>"{gap.actual}"</span>
                      </div>
                    </div>
                    <div style={{
                      background: 'rgba(248, 81, 73, 0.1)',
                      border: '1px solid rgba(248, 81, 73, 0.2)',
                      borderRadius: '4px',
                      padding: '8px 12px',
                      color: '#ff7b72',
                      fontWeight: 600
                    }}>
                      Result: {gap.result}
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ==================== STAGE 4 ==================== */}
      {stage === 4 && (
        <div style={stageStyle}>
          <h3 style={{ margin: '0 0 8px', fontSize: '22px', fontWeight: 700, color: '#f0f6fc' }}>
            What does BinExplain look for?
          </h3>
          <p style={{ fontSize: '15px', lineHeight: '1.6', color: '#c9d1d9', marginBottom: '24px' }}>
            BinExplain performs "static analysis" — it reads the binary like a book without running it. 
            It scans the file structures to extract the metadata needed to explain how a vulnerability is triggered.
          </p>

          {/* Visual Representation of Analysis */}
          <div style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            gap: '24px',
            background: '#0d1117',
            border: '1px solid #30363d',
            borderRadius: '8px',
            padding: '24px',
            marginBottom: '24px',
            flexWrap: 'wrap'
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <span style={{ fontSize: '32px' }}>📄</span>
              <span style={{ fontSize: '11px', color: '#8b949e' }}>Binary File</span>
            </div>
            <div style={{ fontSize: '24px' }}>➔</div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <span style={{ fontSize: '40px' }}>🔍</span>
              <span style={{ fontSize: '11px', color: '#8b949e' }}>BinExplain Scanner</span>
            </div>
            <div style={{ fontSize: '24px' }}>➔</div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <span style={{ fontSize: '32px' }}>📊</span>
              <span style={{ fontSize: '11px', color: '#8b949e' }}>Security Walkthrough</span>
            </div>
          </div>

          {/* 6 Scanner Outputs Cards */}
          <div style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))',
            gap: '12px'
          }}>
            {[
              { title: 'Dangerous functions', desc: 'gets, printf, malloc/free' },
              { title: 'Security protections', desc: 'NX, PIE, canary, RELRO' },
              { title: 'Hidden functions', desc: 'win(), flag(), shell()' },
              { title: 'Function gadgets', desc: 'Used for ROP chains' },
              { title: 'String patterns', desc: 'Flag formats, file paths' },
              { title: 'Data flow', desc: 'Can input reach a vulnerability?' }
            ].map((out, idx) => (
              <div key={idx} style={{
                background: '#0d1117',
                border: '1px solid #30363d',
                borderRadius: '6px',
                padding: '14px'
              }}>
                <div style={{ color: '#58a6ff', fontSize: '13px', fontWeight: 700, marginBottom: '4px' }}>
                  ✓ {out.title}
                </div>
                <div style={{ color: '#8b949e', fontSize: '12px', lineHeight: '1.4' }}>
                  {out.desc}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Navigation Buttons */}
      <div style={{
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        marginTop: '32px',
        paddingTop: '20px',
        borderTop: '1px solid #30363d'
      }}>
        <button
          onClick={handleBack}
          disabled={stage === 1}
          style={{
            background: 'transparent',
            border: '1px solid #30363d',
            borderRadius: '6px',
            color: stage === 1 ? '#8b949e' : '#c9d1d9',
            padding: '8px 16px',
            fontSize: '13px',
            fontWeight: 600,
            cursor: stage === 1 ? 'not-allowed' : 'pointer',
            transition: 'all 0.15s',
            opacity: stage === 1 ? 0.5 : 1
          }}
        >
          Back
        </button>

        <span style={{ fontSize: '12px', color: '#8b949e' }}>
          Concept {stage} of {totalStages}
        </span>

        {stage < totalStages ? (
          <button
            onClick={handleNext}
            style={{
              background: '#238636',
              border: '1px solid #2ea043',
              borderRadius: '6px',
              color: '#fff',
              padding: '8px 20px',
              fontSize: '13px',
              fontWeight: 600,
              cursor: 'pointer',
              transition: 'all 0.15s'
            }}
          >
            Next
          </button>
        ) : (
          <span style={{
            color: '#7ee787',
            fontSize: '13px',
            fontWeight: 700,
            padding: '8px 12px'
          }}>
            Ready to explore! 🎉
          </span>
        )}
      </div>
    </div>
  );
}
