import React from 'react';
import GlossaryTooltip from './GlossaryTooltip';
import { GLOSSARY } from '../data/glossary';

const GlossaryText = ({ text, style }) => {
  if (!text || typeof text !== 'string') return <span style={style}>{text}</span>;

  // Split by inline code blocks first (e.g. `code`)
  const codeParts = text.split(/(`[^`]+`)/g);

  const terms = Object.keys(GLOSSARY).sort((a, b) => b.length - a.length);
  const regex = new RegExp(
    '(' + terms.map(t => t.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|') + ')',
    'gi'
  );

  return (
    <span style={style}>
      {codeParts.map((codePart, idx) => {
        // If it's a code block (starts and ends with backtick)
        if (codePart.startsWith('`') && codePart.endsWith('`')) {
          return (
            <code key={`code-${idx}`} className="inline-code" style={{ fontFamily: 'Courier New, monospace', background: '#1f242c', padding: '2px 6px', borderRadius: '4px', fontSize: '0.9em', color: '#ff7b72' }}>
              {codePart.slice(1, -1)}
            </code>
          );
        }

        // Otherwise, split by glossary terms
        const parts = codePart.split(regex);
        return (
          <React.Fragment key={`text-${idx}`}>
            {parts.map((part, i) => {
              const lowerPart = part.toLowerCase();
              const matchedTerm = terms.find(t => t.toLowerCase() === lowerPart);
              if (matchedTerm) {
                return (
                  <GlossaryTooltip key={i} term={matchedTerm}>
                    {part}
                  </GlossaryTooltip>
                );
              }
              return <React.Fragment key={i}>{part}</React.Fragment>;
            })}
          </React.Fragment>
        );
      })}
    </span>
  );
};

export default GlossaryText;
