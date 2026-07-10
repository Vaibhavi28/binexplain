import React, { useState } from 'react';
import GlossaryText from '../components/GlossaryText';
import ElfDiagram from '../components/learn/ElfDiagram';
import ProtectionsMap from '../components/learn/ProtectionsMap';
import ExploitFlowchart from '../components/learn/ExploitFlowchart';
import TechniqueDives from '../components/learn/TechniqueDives';
import RelationshipMap from '../components/learn/RelationshipMap';

export default function Learn() {
  const [activeSection, setActiveSection] = useState('binary');

  const sections = [
    { id: 'binary',     label: 'What is a Binary' },
    { id: 'protections', label: 'Security Protections' },
    { id: 'flowchart',  label: 'Exploitation Flowchart' },
    { id: 'techniques', label: 'Technique Deep Dives' },
    { id: 'relations',  label: 'What Changes What' },
  ];

  return (
    <div style={{
      maxWidth: '1100px', margin: '0 auto',
      padding: '40px 24px 80px', minHeight: '100vh'
    }}>
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
          How do binaries work? What makes them exploitable?
          What changes when you add a security protection?
          Click anything to learn more. Hover over highlighted terms for definitions.
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
        justifyContent: 'center', marginBottom: '48px'
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
    </div>
  );
}
