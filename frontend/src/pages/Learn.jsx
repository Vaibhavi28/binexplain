import React, { useState } from 'react';
import { Helmet } from 'react-helmet-async';
import ElfDiagram from '../components/learn/ElfDiagram';
import BinaryRuntimeWalkthrough from '../components/learn/BinaryRuntimeWalkthrough';
import CTFOrientation from '../components/learn/CTFOrientation';
import ProtectionsMap from '../components/learn/ProtectionsMap';
import ExploitFlowchart from '../components/learn/ExploitFlowchart';
import TechniqueDives from '../components/learn/TechniqueDives';
import RelationshipMap from '../components/learn/RelationshipMap';
import LearnErrorBoundary from '../components/learn/LearnErrorBoundary';
import RealWorldMap from '../components/learn/RealWorldMap';
import TryItYourself from '../components/learn/TryItYourself';
import CoreVocabulary from '../components/learn/CoreVocabulary';

export default function Learn() {
  const [activeSection, setActiveSection] = useState('vocabulary');
  const [refOpen, setRefOpen] = useState(false);
  const [glossaryOpen, setGlossaryOpen] = useState(false);

  const sections = [
    { id: 'vocabulary',  label: '0. Key Terms First' },
    { id: 'binary',      label: '1. What is a Binary' },
    { id: 'protections', label: '2. Security Protections' },
    { id: 'flowchart',   label: '3. Exploitation Flowchart' },
    { id: 'techniques',  label: '4. Technique Deep Dives' },
    { id: 'relations',   label: '5. Wired Connection Map' },
    { id: 'realworld',   label: '6. Real World Impact' },
    { id: 'tryit',       label: '7. Try It Yourself' },
  ];

  return (
    <div style={{
      maxWidth: '1400px', margin: '0 auto',
      padding: '40px 24px 80px', minHeight: '100vh'
    }}>
      <CTFOrientation />
      <Helmet>
        <title>Binary Exploitation Learning Map — BinExplain</title>
        <meta name="description" content="Interactive visual guide to binary exploitation. Learn how ELF binaries work, what each security protection does, and which exploit technique applies to your challenge. Free, visual, beginner-friendly." />
        <meta name="keywords" content="binary exploitation tutorial, how does buffer overflow work, elf binary structure, NX PIE canary explained, ret2win tutorial, format string exploit beginner, heap exploitation explained, rop chain tutorial" />
        <link rel="canonical" href="https://binexplain.com/learn" />
      </Helmet>

      {/* Page header */}
      <div style={{ marginBottom: '40px', textAlign: 'center' }}>
        <h1 style={{
          fontSize: '32px', fontWeight: 700,
          color: 'var(--text-primary)', marginBottom: '12px'
        }}>
          Binary Exploitation Learning Map
        </h1>
        <p style={{
          fontSize: '16px', color: 'var(--text-secondary)',
          maxWidth: '600px', margin: '0 auto', lineHeight: '1.6'
        }}>
          <span>How do binaries work? What makes them exploitable? What changes when you add a security protection? Click anything to learn more. Hover over highlighted terms for definitions.</span>
        </p>
      </div>

      {/* Section navigation pills */}
      <div style={{
        display: 'flex', gap: '8px', flexWrap: 'wrap',
        justifyContent: 'center', marginBottom: '24px'
      }}>
        {sections.map(s => (
          <button
            key={s.id}
            onClick={() => setActiveSection(s.id)}
            style={{
              padding: '8px 18px', borderRadius: '20px', fontSize: '13px',
              fontWeight: activeSection === s.id ? 600 : 400,
              background: activeSection === s.id ? '#388bfd' : '#21262d',
              color: activeSection === s.id ? '#fff' : '#8b949e',
              border: activeSection === s.id
                ? '1px solid #388bfd' : '1px solid #30363d',
              cursor: 'pointer', transition: 'all 0.15s'
            }}
          >
            {s.label}
          </button>
        ))}
      </div>



      {/* Section content */}
      <div>
        {activeSection === 'vocabulary' && (
          <div id="section-vocabulary">
            <LearnErrorBoundary>
              <CoreVocabulary />
            </LearnErrorBoundary>
          </div>
        )}
        {activeSection === 'binary' && (
          <div id="section-binary">
            <LearnErrorBoundary>
              <div style={{ maxWidth: '900px', margin: '0 auto' }}>
                <ElfDiagram />
                <div style={{ borderTop: '1px solid #21262d', margin: '48px 0 32px' }} />
                <h3 style={{ color: '#f0f6fc', fontSize: '18px', fontWeight: 600,
                  marginBottom: '20px', textAlign: 'center' }}>
                  What Happens When You Run a Binary?
                </h3>
                <BinaryRuntimeWalkthrough onNavigate={setActiveSection} />
              </div>
            </LearnErrorBoundary>
          </div>
        )}
        {activeSection === 'protections' && (
          <div id="section-protections">
            <ProtectionsMap />
          </div>
        )}
        {activeSection === 'flowchart' && (
          <div id="section-flowchart">
            <ExploitFlowchart />
          </div>
        )}
        {activeSection === 'techniques' && (
          <div id="section-techniques">
            <TechniqueDives setActiveSection={setActiveSection} />
          </div>
        )}
        {activeSection === 'relations' && (
          <div id="section-relations">
            <LearnErrorBoundary>
              <RelationshipMap />
            </LearnErrorBoundary>
          </div>
        )}
        {activeSection === 'realworld' && (
          <div id="section-realworld">
            <RealWorldMap />
          </div>
        )}
        {activeSection === 'tryit' && (
          <div id="section-tryit">
            <TryItYourself onSectionChange={setActiveSection} />
          </div>
        )}

        {/* Section Navigation Arrows */}
        {(() => {
          const currentIndex = sections.findIndex(s => s.id === activeSection);
          const prevSection = currentIndex > 0 ? sections[currentIndex - 1] : null;
          const nextSection = currentIndex < sections.length - 1 ? sections[currentIndex + 1] : null;

          return (
            <div style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              marginTop: '48px',
              paddingTop: '24px',
              borderTop: '1px solid #21262d',
              flexWrap: 'wrap',
              gap: '12px'
            }}>
              {prevSection ? (
                <button
                  onClick={() => setActiveSection(prevSection.id)}
                  style={{
                    padding: '10px 20px', borderRadius: '8px', background: '#21262d',
                    border: '1px solid #30363d', color: '#c9d1d9', fontSize: '13px',
                    fontWeight: 600, cursor: 'pointer', transition: 'all 0.15s'
                  }}
                  onMouseEnter={(e) => { e.currentTarget.style.borderColor = '#8b949e'; }}
                  onMouseLeave={(e) => { e.currentTarget.style.borderColor = '#30363d'; }}
                >
                  ← Previous Section
                </button>
              ) : (
                <div />
              )}

              {nextSection ? (
                <button
                  onClick={() => setActiveSection(nextSection.id)}
                  style={{
                    padding: '10px 20px', borderRadius: '8px', background: '#388bfd',
                    border: 'none', color: '#fff', fontSize: '13px',
                    fontWeight: 600, cursor: 'pointer', transition: 'background 0.15s'
                  }}
                  onMouseEnter={(e) => { e.currentTarget.style.background = '#2575e6'; }}
                  onMouseLeave={(e) => { e.currentTarget.style.background = '#388bfd'; }}
                >
                  Next Section →
                </button>
              ) : (
                <div />
              )}
            </div>
          );
        })()}
      </div>

      {/* Floating Quick Reference Panel */}
      <div style={{
        position: 'fixed',
        bottom: '24px',
        right: '24px',
        zIndex: 1000,
        maxWidth: '320px',
        width: 'calc(100vw - 48px)',
        background: '#161b22',
        border: '1px solid #30363d',
        borderRadius: '12px',
        boxShadow: '0 8px 24px rgba(0, 0, 0, 0.5)',
        overflow: 'hidden',
        transition: 'all 0.2s ease-in-out'
      }}>
        {/* Header */}
        <div
          onClick={() => setRefOpen(!refOpen)}
          style={{
            padding: '12px 16px',
            background: '#21262d',
            borderBottom: refOpen ? '1px solid #30363d' : 'none',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            cursor: 'pointer',
            userSelect: 'none'
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            
            <span style={{ fontSize: '13px', fontWeight: 600, color: '#f0f6fc' }}>
              Command Quick Reference
            </span>
          </div>
          <span style={{ color: '#8b949e', fontSize: '12px' }}>
            {refOpen ? 'Collapse' : 'Expand'}
          </span>
        </div>

        {/* Content */}
        {refOpen && (
          <div style={{ padding: '16px', display: 'flex', flexDirection: 'column', gap: '12px' }}>
            <div>
              <div style={{ fontSize: '11px', color: '#8b949e', marginBottom: '4px', fontWeight: 600 }}>Check protections</div>
              <code style={{ display: 'block', padding: '6px', background: '#0d1117', borderRadius: '4px', color: '#ff7b72', fontSize: '11px', fontFamily: 'monospace' }}>
                checksec ./binary
              </code>
            </div>
            <div>
              <div style={{ fontSize: '11px', color: '#8b949e', marginBottom: '4px', fontWeight: 600 }}>Find win functions</div>
              <code style={{ display: 'block', padding: '6px', background: '#0d1117', borderRadius: '4px', color: '#ff7b72', fontSize: '11px', fontFamily: 'monospace' }}>
                nm -a ./binary | grep win
              </code>
            </div>
            <div>
              <div style={{ fontSize: '11px', color: '#8b949e', marginBottom: '4px', fontWeight: 600 }}>Extract strings</div>
              <code style={{ display: 'block', padding: '6px', background: '#0d1117', borderRadius: '4px', color: '#ff7b72', fontSize: '11px', fontFamily: 'monospace' }}>
                strings ./binary
              </code>
            </div>
            <div>
              <div style={{ fontSize: '11px', color: '#8b949e', marginBottom: '4px', fontWeight: 600 }}>Find ROP gadgets</div>
              <code style={{ display: 'block', padding: '6px', background: '#0d1117', borderRadius: '4px', color: '#ff7b72', fontSize: '11px', fontFamily: 'monospace' }}>
                ROPgadget --binary ./binary
              </code>
            </div>
            <div>
              <div style={{ fontSize: '11px', color: '#8b949e', marginBottom: '4px', fontWeight: 600 }}>Test format string</div>
              <code style={{ display: 'block', padding: '6px', background: '#0d1117', borderRadius: '4px', color: '#ff7b72', fontSize: '11px', fontFamily: 'monospace' }}>
                python3 -c 'print("%p."*20)' | ./binary
              </code>
            </div>
          </div>
        )}
      </div>

      {/* Floating Term Glossary Button */}
      <button
        className="floating-glossary-btn"
        onClick={() => setGlossaryOpen(true)}
      >
        Term Glossary
      </button>

      {/* Glossary Backdrop */}
      <div
        onClick={() => setGlossaryOpen(false)}
        style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          background: 'rgba(0, 0, 0, 0.5)',
          zIndex: 1000,
          opacity: glossaryOpen ? 1 : 0,
          pointerEvents: glossaryOpen ? 'auto' : 'none',
          transition: 'opacity 0.3s ease-in-out',
        }}
      />

      {/* Glossary Slide-out Panel */}
      <div style={{
        position: 'fixed',
        top: 0,
        right: 0,
        bottom: 0,
        width: '400px',
        maxWidth: '100vw',
        background: '#161b22',
        borderLeft: '1px solid #30363d',
        boxShadow: '-8px 0 24px rgba(0, 0, 0, 0.5)',
        zIndex: 1001,
        transform: glossaryOpen ? 'translateX(0)' : 'translateX(100%)',
        transition: 'transform 0.3s ease-in-out',
        display: 'flex',
        flexDirection: 'column',
      }}>
        {/* Header */}
        <div style={{
          padding: '16px 20px',
          background: '#21262d',
          borderBottom: '1px solid #30363d',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
        }}>
          <h3 style={{ margin: 0, color: '#f0f6fc', fontSize: '16px', fontWeight: 600 }}>
            Term Glossary
          </h3>
          <button
            onClick={() => setGlossaryOpen(false)}
            style={{
              background: 'none',
              border: 'none',
              color: '#8b949e',
              fontSize: '18px',
              cursor: 'pointer',
              padding: '4px 8px',
            }}
          >
            ✕
          </button>
        </div>

        {/* Content */}
        <div style={{
          padding: '20px',
          overflowY: 'auto',
          flex: 1,
          display: 'flex',
          flexDirection: 'column',
          gap: '16px',
        }}>
          {[
            { title: 'STACK', desc: 'A pile of memory where your program keeps track of what function called what, and what to do next.' },
            { title: 'RETURN ADDRESS', desc: "A note on the stack telling the CPU 'go back here when this function finishes.'" },
            { title: 'BUFFER OVERFLOW', desc: 'Writing more data into a memory box than it was built to hold, so the extra data spills into the box next to it.' },
            { title: 'NX (No-Execute)', desc: 'A rule that says: this piece of memory can be run as code, OR written to as data — never both at once.' },
            { title: 'GADGET', desc: "A tiny 2-3 instruction fragment already inside the program's own code, ending in 'return.'" },
            { title: 'ROP (Return-Oriented Programming)', desc: 'Chaining multiple gadgets together, one after another, to make the CPU do something useful — without injecting any new code.' },
            { title: 'PIE (Position Independent Executable)', desc: 'A setting that makes the program load at a random memory address every single time it runs.' },
            { title: 'CANARY', desc: 'A random secret value placed right before the return address. If it changes, the program knows it was attacked and crashes on purpose.' },
            { title: 'GOT (Global Offset Table)', desc: 'A lookup table the program uses to find the real memory address of functions like printf() or system() at runtime.' },
            { title: 'RELRO (Relocation Read-Only)', desc: 'A setting that makes the GOT table read-only after the program starts, so it can never be changed again.' },
            { title: 'HEAP', desc: 'A separate area of memory for data your program asks for while it\'s running, using malloc(). You give it back with free().' },
            { title: 'LIBC', desc: 'A shared library of common functions — printf, malloc, system — that almost every program on Linux uses.' },
          ].map((item, i) => (
            <div key={i} style={{ borderBottom: '1px solid #21262d', paddingBottom: '12px' }}>
              <div style={{ color: '#79c0ff', fontWeight: 700, fontSize: '13px', marginBottom: '4px' }}>
                {i + 1}. {item.title}
              </div>
              <div style={{ color: '#c9d1d9', fontSize: '12px', lineHeight: '1.4' }}>
                {item.desc}
              </div>
            </div>
          ))}
        </div>
      </div>

      <style>{`
        .floating-glossary-btn {
          position: fixed;
          bottom: 24px;
          right: 360px;
          z-index: 999;
          padding: 10px 16px;
          background: #238636;
          border: 1px solid #2ea043;
          border-radius: 20px;
          color: #fff;
          font-size: 13px;
          font-weight: 600;
          cursor: pointer;
          box-shadow: 0 4px 12px rgba(0,0,0,0.3);
          transition: all 0.15s;
        }
        .floating-glossary-btn:hover {
          background: #2ea043;
        }
        @media (max-width: 768px) {
          .floating-glossary-btn {
            bottom: 80px;
            right: 24px;
          }
        }
      `}</style>
    </div>
  );
}
