import React, { useState } from 'react';
import { Helmet } from 'react-helmet-async';
import GlossaryText from '../components/GlossaryText';
import ElfDiagram from '../components/learn/ElfDiagram';
import ProtectionsMap from '../components/learn/ProtectionsMap';
import ExploitFlowchart from '../components/learn/ExploitFlowchart';
import TechniqueDives from '../components/learn/TechniqueDives';
import RelationshipMap from '../components/learn/RelationshipMap';
import RealWorldMap from '../components/learn/RealWorldMap';
import TryItYourself from '../components/learn/TryItYourself';

export default function Learn() {
  const [activeSection, setActiveSection] = useState('binary');
  const [refOpen, setRefOpen] = useState(false);

  const sections = [
    { id: 'binary',      label: '1. What is a Binary' },
    { id: 'protections', label: '2. Security Protections' },
    { id: 'flowchart',   label: '3. Exploitation Flowchart' },
    { id: 'techniques',  label: '4. Technique Deep Dives' },
    { id: 'relations',   label: '5. What Changes What' },
    { id: 'realworld',   label: '6. Real World Impact' },
    { id: 'tryit',       label: '7. Try It Yourself' },
  ];

  return (
    <div style={{
      maxWidth: '1100px', margin: '0 auto',
      padding: '40px 24px 80px', minHeight: '100vh'
    }}>
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
          <GlossaryText text="How do binaries work? What makes them exploitable? What changes when you add a security protection? Click anything to learn more. Hover over highlighted terms for definitions." />
        </p>
        <div style={{
          fontSize: '12px', color: '#484f58',
          marginTop: '12px'
        }}>
          💡 Hover over{' '}
          <span style={{ borderBottom: '1px dashed #388bfd', color: '#79c0ff' }}>
            highlighted terms
          </span>
          {' '}for plain English explanations with real-world examples
        </div>
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

      {/* Progress Breadcrumb */}
      <div style={{ display: 'flex', justifyContent: 'center', marginBottom: '40px' }}>
        <div style={{
          fontSize: '13px',
          color: 'var(--text-secondary)',
          padding: '10px 18px',
          background: '#161b22',
          borderRadius: '8px',
          border: '1px solid #21262d',
          lineHeight: '1.5',
          textAlign: 'center',
          maxWidth: '700px'
        }}>
          You are in:{' '}
          <strong style={{ color: '#58a6ff' }}>
            {sections.find(s => s.id === activeSection)?.label}
          </strong>
          {' — '}
          <span>
            {activeSection === 'binary' && 'Visual interactive guide to standard ELF binary layouts, headers, and sections.'}
            {activeSection === 'protections' && 'Explore active memory protection switches like NX, PIE, Canaries, and RELRO.'}
            {activeSection === 'flowchart' && 'Step through decision-tree classification paths to identify vulnerabilities.'}
            {activeSection === 'techniques' && 'In-depth analysis of core exploitation categories, payloads, and steps.'}
            {activeSection === 'relations' && 'Interactive map connecting dangerous functions, security flaws, techniques, and counters.'}
            {activeSection === 'realworld' && 'Real-world exploits, CVEs, impacts, and developer lessons mapped to each pwn technique.'}
            {activeSection === 'tryit' && 'Target practice suggestions, pwn checklists, and templates to start exploiting binaries.'}
          </span>
        </div>
      </div>

      {/* Section content */}
      <div>
        {activeSection === 'binary' && (
          <div id="section-binary">
            <ElfDiagram />
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
            <TechniqueDives />
          </div>
        )}
        {activeSection === 'relations' && (
          <div id="section-relations">
            <RelationshipMap />
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
                  onClick={() => {
                    setActiveSection(prevSection.id);
                    window.scrollTo({ top: 0, behavior: 'smooth' });
                  }}
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
                  onClick={() => {
                    setActiveSection(nextSection.id);
                    window.scrollTo({ top: 0, behavior: 'smooth' });
                  }}
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
            <span style={{ fontSize: '16px' }}>💡</span>
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
    </div>
  );
}
