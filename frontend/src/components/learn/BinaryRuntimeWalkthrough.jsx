import React, { useState, useEffect, useRef } from 'react';

export default function BinaryRuntimeWalkthrough({ onNavigate }) {
  const [step, setStep] = useState(1);
  const [prefersReducedMotion, setPrefersReducedMotion] = useState(false);
  const [autoAdvanceEnabled, setAutoAdvanceEnabled] = useState(true);
  const [isHovering, setIsHovering] = useState(false);
  const [timeLeft, setTimeLeft] = useState(7);
  const timerRef = useRef(null);
  const hoverTimeoutRef = useRef(null);

  // Check prefers-reduced-motion setting
  useEffect(() => {
    const mediaQuery = window.matchMedia('(prefers-reduced-motion: reduce)');
    setPrefersReducedMotion(mediaQuery.matches);
    const listener = (e) => setPrefersReducedMotion(e.matches);
    mediaQuery.addEventListener('change', listener);
    return () => mediaQuery.removeEventListener('change', listener);
  }, []);

  // Auto-advance timer (7 seconds)
  useEffect(() => {
    if (timerRef.current) clearInterval(timerRef.current);
    
    if (autoAdvanceEnabled && !isHovering) {
      timerRef.current = setInterval(() => {
        setStep(prev => (prev < 6 ? prev + 1 : 1));
      }, 7000);
    }

    return () => {
      if (timerRef.current) clearInterval(timerRef.current);
    };
  }, [step, autoAdvanceEnabled, isHovering]);

  // Countdown indicator timer
  useEffect(() => {
    if (!autoAdvanceEnabled || isHovering) {
      return;
    }
    setTimeLeft(7);
    const id = setInterval(() => {
      setTimeLeft(prev => {
        if (prev <= 1) return 7;
        return prev - 1;
      });
    }, 1000);
    return () => clearInterval(id);
  }, [step, autoAdvanceEnabled, isHovering]);

  useEffect(() => {
    return () => {
      if (hoverTimeoutRef.current) clearTimeout(hoverTimeoutRef.current);
    };
  }, []);

  const resetTimer = () => {
    setTimeLeft(7);
  };

  const handleNext = () => {
    setStep(prev => (prev < 6 ? prev + 1 : 1));
    resetTimer();
  };

  const handlePrev = () => {
    setStep(prev => (prev > 1 ? prev - 1 : 6));
    resetTimer();
  };

  const selectStep = (s) => {
    setStep(s);
    resetTimer();
  };

  // Styles for the animations
  const animationStyles = `
    @keyframes pulse-glow {
      0% { box-shadow: 0 0 5px rgba(56, 139, 253, 0.4); transform: scale(1); }
      50% { box-shadow: 0 0 25px rgba(56, 139, 253, 0.8); transform: scale(1.05); }
      100% { box-shadow: 0 0 5px rgba(56, 139, 253, 0.4); transform: scale(1); }
    }
    @keyframes fade-in-os {
      0% { opacity: 0; transform: scale(0.8); }
      100% { opacity: 1; transform: scale(1); }
    }
    @keyframes flow-section {
      0% { transform: translateY(-40px); opacity: 0; }
      100% { transform: translateY(0); opacity: 1; }
    }
    @keyframes cpu-cursor {
      0% { transform: translateY(0); }
      40% { transform: translateY(32px); }
      80% { transform: translateY(64px); }
      100% { transform: translateY(64px); }
    }
    @keyframes stack-build {
      0% { height: 0; opacity: 0; }
      100% { height: 100%; opacity: 1; }
    }
    @keyframes typing {
      0% { width: 0; }
      100% { width: 100%; }
    }
    @keyframes fill-and-overflow {
      0% { height: 0; background: #388bfd; }
      50% { height: 50px; background: #388bfd; }
      75% { height: 90px; background: #e3b341; }
      100% { height: 130px; background: #f85149; }
    }
    .anim-pulse {
      animation: pulse-glow 2s infinite ease-in-out;
    }
    .anim-fade-os {
      animation: fade-in-os 0.8s 1s forwards ease-out;
      opacity: 0;
    }
    .anim-flow-1 {
      animation: flow-section 0.8s 0.2s forwards ease-out;
      opacity: 0;
    }
    .anim-flow-2 {
      animation: flow-section 0.8s 0.8s forwards ease-out;
      opacity: 0;
    }
    .anim-flow-3 {
      animation: flow-section 0.8s 1.4s forwards ease-out;
      opacity: 0;
    }
    .anim-cpu {
      animation: cpu-cursor 3s infinite steps(1) ease-in-out;
    }
    .anim-stack-1 {
      animation: flow-section 0.8s 0.2s forwards ease-out;
      opacity: 0;
    }
    .anim-stack-2 {
      animation: flow-section 0.8s 0.7s forwards ease-out;
      opacity: 0;
    }
    .anim-stack-3 {
      animation: flow-section 0.8s 1.2s forwards ease-out;
      opacity: 0;
    }
    .anim-type {
      overflow: hidden;
      white-space: nowrap;
      border-right: 2px solid #58a6ff;
      animation: typing 1.89s steps(54, end) infinite;
    }
    .anim-overflow {
      animation: fill-and-overflow 3.5s infinite linear;
    }
  `;

  return (
    <div 
      onMouseEnter={() => {
        if (hoverTimeoutRef.current) clearTimeout(hoverTimeoutRef.current);
        setIsHovering(true);
        if (timerRef.current) clearInterval(timerRef.current);
      }}
      onMouseLeave={() => {
        if (hoverTimeoutRef.current) clearTimeout(hoverTimeoutRef.current);
        hoverTimeoutRef.current = setTimeout(() => {
          setIsHovering(false);
        }, 2000);
      }}
      style={{
        background: '#161b22',
        border: '1px solid #30363d',
        borderRadius: '12px',
        padding: '28px',
        color: '#c9d1d9',
        boxShadow: '0 8px 32px rgba(0, 0, 0, 0.3)',
        maxWidth: '850px',
        margin: '0 auto'
      }}
    >
      <style>{animationStyles}</style>

      {/* Progress & Navigation Bar */}
      <div style={{
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        marginBottom: '20px',
        borderBottom: '1px solid #21262d',
        paddingBottom: '16px'
      }}>
        <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
          {[1, 2, 3, 4, 5, 6].map(s => (
            <button
              key={s}
              onClick={() => selectStep(s)}
              style={{
                width: '32px',
                height: '32px',
                borderRadius: '50%',
                background: step === s ? '#388bfd' : '#21262d',
                border: `1px solid ${step === s ? '#58a6ff' : '#30363d'}`,
                color: step === s ? '#fff' : '#8b949e',
                fontSize: '12px',
                fontWeight: 700,
                cursor: 'pointer',
                transition: 'all 0.2s',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center'
              }}
            >
              {s}
            </button>
          ))}
        </div>
        <span style={{ fontSize: '13px', color: '#8b949e', fontWeight: 600 }}>
          Step {step} of 6
        </span>
      </div>

      {/* Visual Canvas Area (300px tall) */}
      <div style={{
        height: '300px',
        background: '#0d1117',
        border: '1px solid #30363d',
        borderRadius: '8px',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        position: 'relative',
        overflow: 'hidden',
        marginBottom: '20px'
      }}>
        
        {/* STEP 1: Double Click File */}
        {step === 1 && (
          <div style={{ textAlign: 'center', width: '100%' }}>
            <div style={{ display: 'inline-block', position: 'relative' }}>
              <div 
                className={prefersReducedMotion ? '' : 'anim-pulse'}
                style={{
                  fontSize: '64px',
                  padding: '24px',
                  background: '#161b22',
                  border: '2px solid #388bfd',
                  borderRadius: '12px',
                  cursor: 'pointer'
                }}
              >
                
                <div style={{ fontSize: '11px', color: '#58a6ff', marginTop: '6px', fontFamily: 'monospace' }}>
                  ./program
                </div>
              </div>
              <span style={{
                position: 'absolute',
                bottom: '-10px',
                right: '-10px',
                fontSize: '28px'
              }}>
                ️
              </span>
            </div>
            
            {/* Linux OS Logo loading */}
            <div 
              className={prefersReducedMotion ? '' : 'anim-fade-os'}
              style={{
                marginTop: '20px',
                color: '#ffc107',
                fontSize: '14px',
                fontWeight: 700,
                display: 'flex',
                justifyContent: 'center',
                alignItems: 'center',
                gap: '8px',
                opacity: prefersReducedMotion ? 1 : 0
              }}
            >
              <span></span>
              <span>Linux OS Activated</span>
            </div>
          </div>
        )}

        {/* STEP 2: OS Loads Binary into Memory */}
        {step === 2 && (
          <div style={{
            display: 'flex',
            justifyContent: 'space-around',
            alignItems: 'center',
            width: '100%',
            padding: '0 40px'
          }}>
            {/* Source Binary */}
            <div style={{ textAlign: 'center' }}>
              <div style={{ fontSize: '11px', color: '#8b949e', marginBottom: '8px' }}>ELF Binary File</div>
              <div style={{
                background: '#161b22',
                border: '1px solid #30363d',
                borderRadius: '6px',
                padding: '16px',
                fontFamily: 'monospace',
                fontSize: '11px',
                display: 'flex',
                flexDirection: 'column',
                gap: '4px'
              }}>
                <div style={{ color: '#58a6ff' }}>.text (code)</div>
                <div style={{ color: '#d2a8ff' }}>.rodata (strings)</div>
                <div style={{ color: '#39c5cf' }}>.data (global)</div>
              </div>
            </div>

            {/* Flows indicator */}
            <div style={{ fontSize: '24px', color: '#58a6ff' }}>➔</div>

            {/* RAM map */}
            <div style={{ textAlign: 'center', width: '180px' }}>
              <div style={{ fontSize: '11px', color: '#8b949e', marginBottom: '8px' }}>System RAM Memory</div>
              <div style={{
                border: '2px dashed #8b949e',
                borderRadius: '8px',
                padding: '8px',
                display: 'flex',
                flexDirection: 'column',
                gap: '6px',
                background: '#161b22'
              }}>
                <div 
                  className={prefersReducedMotion ? '' : 'anim-flow-1'}
                  style={{ background: 'rgba(56, 139, 253, 0.2)', border: '1px solid #388bfd', borderRadius: '4px', padding: '6px', fontSize: '10px', color: '#79c0ff', opacity: prefersReducedMotion ? 1 : 0 }}
                >
                  Code (.text) [Read-Only]
                </div>
                <div 
                  className={prefersReducedMotion ? '' : 'anim-flow-2'}
                  style={{ background: 'rgba(210, 168, 255, 0.2)', border: '1px solid #8957e5', borderRadius: '4px', padding: '6px', fontSize: '10px', color: '#d2a8ff', opacity: prefersReducedMotion ? 1 : 0 }}
                >
                  Heap [Dynamic]
                </div>
                <div 
                  className={prefersReducedMotion ? '' : 'anim-flow-3'}
                  style={{ background: 'rgba(240, 224, 66, 0.2)', border: '1px solid #d29922', borderRadius: '4px', padding: '6px', fontSize: '10px', color: '#f0e042', opacity: prefersReducedMotion ? 1 : 0 }}
                >
                  Stack [Function Frames]
                </div>
              </div>
            </div>
          </div>
        )}

        {/* STEP 3: CPU Starts executing at main() */}
        {step === 3 && (
          <div style={{ display: 'flex', gap: '32px', alignItems: 'center' }}>
            {/* CPU representation */}
            <div style={{
              background: '#161b22',
              border: '2px solid #ff7b72',
              borderRadius: '8px',
              padding: '20px',
              textAlign: 'center',
              width: '120px'
            }}>
              <span style={{ fontSize: '28px' }}>️</span>
              <div style={{ fontSize: '12px', fontWeight: 700, color: '#ff7b72', marginTop: '6px' }}>CPU Processor</div>
            </div>

            {/* Pointer arrows */}
            <div style={{ position: 'relative', width: '30px', height: '80px' }}>
              <div 
                className={prefersReducedMotion ? '' : 'anim-cpu'}
                style={{
                  fontSize: '24px',
                  position: 'absolute',
                  top: prefersReducedMotion ? '64px' : '0',
                  left: 0
                }}
              >
                ➔
              </div>
            </div>

            {/* Instruction list */}
            <div style={{
              background: '#0d1117',
              border: '1px solid #30363d',
              borderRadius: '6px',
              padding: '16px',
              fontFamily: 'monospace',
              fontSize: '13px',
              display: 'flex',
              flexDirection: 'column',
              gap: '12px',
              width: '180px'
            }}>
              <div style={{ color: '#8b949e' }}>1. main() entry</div>
              <div style={{ color: '#58a6ff' }}>2. vuln() called</div>
              <div style={{ color: '#7ee787' }}>3. gets(buf) prompt</div>
            </div>
          </div>
        )}

        {/* STEP 4: Stack Frame created */}
        {step === 4 && (
          <div style={{ width: '220px', display: 'flex', flexDirection: 'column' }}>
            <div style={{ fontSize: '11px', color: '#8b949e', textAlign: 'center', marginBottom: '8px' }}>
              vuln() Stack Frame in RAM
            </div>
            
            <div style={{
              border: '2px solid #d29922',
              borderRadius: '8px',
              background: '#161b22',
              display: 'flex',
              flexDirection: 'column',
              overflow: 'hidden'
            }}>
              {/* Return Address (top of stack) */}
              <div 
                className={prefersReducedMotion ? '' : 'anim-stack-3'}
                style={{
                  background: 'rgba(248, 81, 73, 0.15)',
                  borderBottom: '1px solid #f85149',
                  padding: '12px',
                  textAlign: 'center',
                  fontSize: '11px',
                  color: '#ff7b72',
                  opacity: prefersReducedMotion ? 1 : 0
                }}
              >
                Return Address (8 bytes)
              </div>

              {/* Saved RBP */}
              <div 
                className={prefersReducedMotion ? '' : 'anim-stack-2'}
                style={{
                  background: 'rgba(240, 224, 66, 0.15)',
                  borderBottom: '1px solid #d29922',
                  padding: '12px',
                  textAlign: 'center',
                  fontSize: '11px',
                  color: '#f0e042',
                  opacity: prefersReducedMotion ? 1 : 0
                }}
              >
                Saved RBP / Frame Pointer (8 bytes)
              </div>

              {/* Local Buffer */}
              <div 
                className={prefersReducedMotion ? '' : 'anim-stack-1'}
                style={{
                  background: 'rgba(56, 139, 253, 0.15)',
                  padding: '18px',
                  textAlign: 'center',
                  fontSize: '11px',
                  color: '#79c0ff',
                  opacity: prefersReducedMotion ? 1 : 0
                }}
              >
                Local Buffer "buf" (64 bytes)
              </div>
            </div>
          </div>
        )}

        {/* STEP 5: Enter Input */}
        {step === 5 && (
          <div style={{ width: '80%', maxWidth: '440px' }}>
            <div style={{
              background: '#161b22',
              border: '1px solid #30363d',
              borderRadius: '6px 6px 0 0',
              padding: '8px 12px',
              fontSize: '12px',
              color: '#8b949e',
              borderBottom: 'none',
              fontFamily: 'monospace'
            }}>
              Terminal Console — vuln() Prompt
            </div>
            
            <div style={{
              background: '#0d1117',
              border: '1px solid #30363d',
              borderRadius: '0 0 6px 6px',
              padding: '24px',
              fontFamily: 'monospace',
              fontSize: '15px',
              minHeight: '120px',
              textAlign: 'left'
            }}>
              <div style={{ color: '#7ee787', marginBottom: '12px' }}>$ ./program</div>
              <div style={{ color: '#c9d1d9', marginBottom: '8px' }}>Enter your name:</div>
              
              {/* Animated Text Typing */}
              <div style={{ display: 'inline-block' }}>
                <span 
                  className={prefersReducedMotion ? '' : 'anim-type'}
                  style={{
                    color: '#58a6ff',
                    fontWeight: 'bold',
                    display: 'block'
                  }}
                >
                  {prefersReducedMotion 
                    ? 'Alice' 
                    : 'AliceAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
                  }
                </span>
              </div>
            </div>
          </div>
        )}

        {/* STEP 6: Input Overflow */}
        {step === 6 && (
          <div style={{ display: 'flex', gap: '32px', alignItems: 'center' }}>
            {/* Exploding / Overflowing Stack */}
            <div style={{
              width: '180px',
              border: '2px solid #f85149',
              borderRadius: '8px',
              background: '#161b22',
              display: 'flex',
              flexDirection: 'column',
              position: 'relative',
              overflow: 'hidden'
            }}>
              {/* Overlay fill representing overflow */}
              <div 
                className={prefersReducedMotion ? '' : 'anim-overflow'}
                style={{
                  position: 'absolute',
                  bottom: 0,
                  left: 0,
                  width: '100%',
                  opacity: 0.4,
                  height: prefersReducedMotion ? '130px' : '0px',
                  background: prefersReducedMotion ? '#f85149' : '#388bfd',
                  zIndex: 1
                }}
              />

              <div style={{ padding: '12px', textAlign: 'center', fontSize: '11px', color: '#ff7b72', zIndex: 2 }}>
                Return Address
              </div>
              <div style={{ padding: '12px', borderTop: '1px solid #30363d', borderBottom: '1px solid #30363d', textAlign: 'center', fontSize: '11px', color: '#f0e042', zIndex: 2 }}>
                Saved RBP
              </div>
              <div style={{ padding: '18px', textAlign: 'center', fontSize: '11px', color: '#79c0ff', zIndex: 2 }}>
                Buffer (64 bytes)
              </div>
            </div>

            {/* Explaining arrow */}
            <div style={{ maxWidth: '180px' }}>
              <div style={{ fontSize: '24px', color: '#f85149', marginBottom: '8px' }}>⬆ OVERFLOW!</div>
              <div style={{ fontSize: '12px', color: '#8b949e', lineHeight: '1.4' }}>
                Extra inputs overwrite the saved RBP and leak directly into the return address.
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Story Text Area Below */}
      <div style={{
        background: '#0d1117',
        border: '1px solid #30363d',
        borderRadius: '8px',
        padding: '20px',
        minHeight: '110px',
        marginBottom: '24px',
        position: 'relative'
      }}>
        {step === 1 && (
          <div>
            <h4 style={{ margin: '0 0 6px', color: '#58a6ff', fontSize: '15px' }}>
              STEP 1: Run the Executable
            </h4>
            <p style={{ margin: 0, fontSize: '14px', lineHeight: '1.6' }}>
              The Operating System (OS) — Linux in CTF challenges — receives your launch request. 
              It reads the binary file's structure and begins preparing the memory layout to support execution.
            </p>
          </div>
        )}
        {step === 2 && (
          <div>
            <h4 style={{ margin: '0 0 6px', color: '#d2a8ff', fontSize: '15px' }}>
              STEP 2: Load into memory
            </h4>
            <p style={{ margin: 0, fontSize: '14px', lineHeight: '1.6' }}>
              The OS maps each section of the binary file into RAM. 
              Code (<code>.text</code>) goes into read-only executable memory. 
              Stack space is allocated for function calls, and the heap is prepared.
            </p>
          </div>
        )}
        {step === 3 && (
          <div>
            <h4 style={{ margin: '0 0 6px', color: '#7ee787', fontSize: '15px' }}>
              STEP 3: CPU Starts executing at main()
            </h4>
            <p style={{ margin: 0, fontSize: '14px', lineHeight: '1.6' }}>
              Execution begins at the <code>main()</code> function. The CPU reads one instruction at a time and follows them. 
              When <code>main()</code> calls <code>vuln()</code>, a new stack frame is created.
            </p>
          </div>
        )}
        {step === 4 && (
          <div>
            <h4 style={{ margin: '0 0 6px', color: '#f0e042', fontSize: '15px' }}>
              STEP 4: Stack frame created
            </h4>
            <p style={{ margin: 0, fontSize: '14px', lineHeight: '1.6' }}>
              When <code>vuln()</code> is called, the CPU pushes a frame onto the stack. 
              This frame contains: the local buffer (64 bytes for your input), 
              the saved RBP (tells the CPU where the previous frame was), 
              and the return address (tells the CPU where to go when <code>vuln()</code> is done).
            </p>
          </div>
        )}
        {step === 5 && (
          <div>
            <h4 style={{ margin: '0 0 6px', color: '#39c5cf', fontSize: '15px' }}>
              STEP 5: You enter your input
            </h4>
            <p style={{ margin: 0, fontSize: '14px', lineHeight: '1.6' }}>
              The program waits for you to type something. <code>gets()</code> reads everything you type — 
              with no limit check — and stores it inside the 64-byte local buffer.
            </p>
          </div>
        )}
        {step === 6 && (
          <div>
            <h4 style={{ margin: '0 0 6px', color: '#ff7b72', fontSize: '15px' }}>
              STEP 6: Memory Overflow
            </h4>
            <p style={{ margin: 0, fontSize: '14px', lineHeight: '1.6' }}>
              If you type more than 64 characters, the extra bytes overflow into the memory above the buffer 
              — first the saved RBP, then the return address. You now control where the program goes next. 
              This is a buffer overflow.
            </p>
          </div>
        )}

        {/* Countdown / Auto-Advance Status */}
        <div style={{ 
          fontSize: '11px', 
          color: '#8b949e', 
          marginTop: '12px', 
          fontStyle: 'italic',
          borderTop: '1px solid #21262d',
          paddingTop: '8px',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center'
        }}>
          <span>{autoAdvanceEnabled ? (isHovering ? '⏸️ Auto-advance paused (hovering over area)' : `⏱️ Next step in ${timeLeft}s — hover to pause`) : '⏸️ Auto-advance turned off'}</span>
          <span style={{ fontSize: '10px', color: '#6e7681' }}>Auto-Advance Status</span>
        </div>
      </div>

      {/* Step Navigation Controls */}
      <div style={{
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        borderBottom: '1px solid #21262d',
        paddingBottom: '20px',
        marginBottom: '24px'
      }}>
        <button
          onClick={handlePrev}
          style={{
            background: 'transparent',
            border: '1px solid #30363d',
            borderRadius: '6px',
            color: '#c9d1d9',
            padding: '6px 14px',
            fontSize: '13px',
            fontWeight: 600,
            cursor: 'pointer'
          }}
        >
          ← Prev
        </button>

        <button
          onClick={() => setAutoAdvanceEnabled(p => !p)}
          style={{
            background: 'transparent',
            border: '1px solid #30363d',
            borderRadius: '6px',
            color: '#8b949e',
            padding: '6px 14px',
            fontSize: '12px',
            cursor: 'pointer',
            transition: 'all 0.15s'
          }}
          onMouseEnter={(e) => { e.currentTarget.style.borderColor = '#8b949e'; e.currentTarget.style.color = '#c9d1d9'; }}
          onMouseLeave={(e) => { e.currentTarget.style.borderColor = '#30363d'; e.currentTarget.style.color = '#8b949e'; }}
        >
          {autoAdvanceEnabled ? '⏸ Pause Auto-Advance' : '▶ Resume Auto-Advance'}
        </button>

        <button
          onClick={handleNext}
          style={{
            background: '#21262d',
            border: '1px solid #30363d',
            borderRadius: '6px',
            color: '#c9d1d9',
            padding: '6px 14px',
            fontSize: '13px',
            fontWeight: 600,
            cursor: 'pointer'
          }}
        >
          Next →
        </button>
      </div>

      {/* CTA: What happens next? */}
      <div style={{
        textAlign: 'center',
        padding: '8px 0 0'
      }}>
        <div style={{ fontSize: '13px', color: '#8b949e', marginBottom: '14px', fontWeight: 600 }}>
          What happens next? Explore further:
        </div>
        <div style={{
          display: 'flex',
          justifyContent: 'center',
          gap: '12px',
          flexWrap: 'wrap'
        }}>
          <button
            onClick={() => { if (onNavigate) onNavigate('flowchart'); }}
            style={{
              background: '#388bfd',
              border: 'none',
              borderRadius: '6px',
              color: '#fff',
              padding: '10px 18px',
              fontSize: '13px',
              fontWeight: 600,
              cursor: 'pointer',
              boxShadow: '0 2px 6px rgba(56, 139, 253, 0.3)',
              transition: 'background 0.15s'
            }}
          >
            See Exploitation Flowchart
          </button>
          <button
            onClick={() => { if (onNavigate) onNavigate('tryit'); }}
            style={{
              background: 'transparent',
              border: '1px solid #30363d',
              borderRadius: '6px',
              color: '#c9d1d9',
              padding: '10px 18px',
              fontSize: '13px',
              fontWeight: 600,
              cursor: 'pointer',
              transition: 'background 0.15s'
            }}
          >
            Try It on a Real Binary
          </button>
        </div>
      </div>
    </div>
  );
}
