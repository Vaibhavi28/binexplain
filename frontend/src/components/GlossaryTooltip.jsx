import React, { useState, useRef } from 'react';
import { GLOSSARY } from '../data/glossary';

const GlossaryTooltip = ({ children, term }) => {
  const [visible, setVisible] = useState(false);
  const [position, setPosition] = useState({ top: 0, left: 0 });
  const triggerRef = useRef(null);
  const tooltipRef = useRef(null);
  const data = GLOSSARY[term.toLowerCase()];
  if (!data) return <>{children}</>;

  const handleMouseEnter = () => {
    if (!triggerRef.current) return;
    const rect = triggerRef.current.getBoundingClientRect();
    const scrollY = window.scrollY || document.documentElement.scrollTop;
    const scrollX = window.scrollX || document.documentElement.scrollLeft;

    setPosition({
      top: rect.bottom + scrollY + 8,
      left: Math.max(8, rect.left + scrollX - 100),
    });
    setVisible(true);
  };

  const handleMouseLeave = (e) => {
    if (tooltipRef.current && tooltipRef.current.contains(e.relatedTarget)) return;
    setVisible(false);
  };

  return (
    <>
      <span
        ref={triggerRef}
        onMouseEnter={handleMouseEnter}
        onMouseLeave={handleMouseLeave}
        style={{
          borderBottom: '1px dashed #388bfd',
          color: '#79c0ff',
          cursor: 'help',
          display: 'inline',
        }}
      >
        {children}
      </span>

      {visible && (
        <div
          ref={tooltipRef}
          onMouseLeave={() => setVisible(false)}
          style={{
            position: 'absolute',
            top: position.top,
            left: position.left,
            zIndex: 9999,
            width: '360px',
            background: '#161b22',
            border: '1px solid #388bfd',
            borderRadius: '10px',
            boxShadow: '0 8px 32px rgba(0,0,0,0.6)',
            padding: '16px',
            pointerEvents: 'auto',
          }}
        >
          {/* Term header */}
          <div style={{
            fontSize: '13px', fontWeight: 700, color: '#79c0ff',
            marginBottom: '10px', textTransform: 'capitalize',
            borderBottom: '1px solid #21262d', paddingBottom: '8px'
          }}>
            📖 {term}
          </div>

          {/* Simple explanation */}
          <div style={{ marginBottom: '12px' }}>
            <div style={{
              fontSize: '10px', color: '#8b949e', fontWeight: 600,
              textTransform: 'uppercase', letterSpacing: '0.08em',
              marginBottom: '5px'
            }}>
              What it means
            </div>
            <p style={{
              color: '#c9d1d9', fontSize: '13px', lineHeight: '1.6',
              margin: 0
            }}>
              {data.simple}
            </p>
          </div>

          {/* Real world example */}
          <div style={{
            background: '#0d1117', borderRadius: '6px',
            padding: '10px 12px', borderLeft: '3px solid #e3b341'
          }}>
            <div style={{
              fontSize: '10px', color: '#e3b341', fontWeight: 600,
              textTransform: 'uppercase', letterSpacing: '0.08em',
              marginBottom: '5px'
            }}>
              🌍 Real world example
            </div>
            <p style={{
              color: '#c9d1d9', fontSize: '12px', lineHeight: '1.5',
              margin: 0
            }}>
              {data.example}
            </p>
          </div>
        </div>
      )}
    </>
  );
};

export default GlossaryTooltip;
