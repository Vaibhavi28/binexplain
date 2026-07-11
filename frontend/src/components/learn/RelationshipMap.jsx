import React, { useState, useRef, useEffect } from 'react';

const NODES = {
  gets: {
    id: 'gets',
    label: 'gets()',
    col: 1,
    left: 10,
    top: 50,
    desc: 'Reads user input until a newline. It does not check boundaries, making it highly vulnerable to buffer overflows.'
  },
  printf_buf: {
    id: 'printf_buf',
    label: 'printf(buf)',
    col: 1,
    left: 10,
    top: 140,
    desc: 'Prints a user-controlled buffer without format specifiers. This lets attackers leak or write stack memory.'
  },
  strcpy: {
    id: 'strcpy',
    label: 'strcpy()',
    col: 1,
    left: 10,
    top: 230,
    desc: 'Copies a string to a destination until a null byte. Overflows if the source string is larger than the destination buffer.'
  },
  malloc_free: {
    id: 'malloc_free',
    label: 'malloc() + free()',
    col: 1,
    left: 10,
    top: 320,
    desc: 'Dynamic heap memory allocation routines. Buggy code leads to double-free, use-after-free, or heap chunk overflows.'
  },
  system_fn: {
    id: 'system_fn',
    label: 'system()',
    col: 1,
    left: 10,
    top: 410,
    desc: 'Invokes command shells. If the argument contains unsanitized user inputs, attackers can execute arbitrary shell commands.'
  },

  buffer_overflow: {
    id: 'buffer_overflow',
    label: 'Buffer Overflow',
    col: 2,
    left: 250,
    top: 50,
    desc: 'Writing data beyond stack/heap boundaries, corrupting adjacent program structures like saved return pointers.'
  },
  format_string_vuln: {
    id: 'format_string_vuln',
    label: 'Format String Bug',
    col: 2,
    left: 250,
    top: 140,
    desc: 'Occurs when user-supplied inputs are evaluated directly as format variables inside printf calls.'
  },
  heap_corruption: {
    id: 'heap_corruption',
    label: 'Heap Corruption',
    col: 2,
    left: 250,
    top: 230,
    desc: 'Corrupting heap manager headers or bin pointers to hijack subsequent malloc allocations.'
  },
  use_after_free: {
    id: 'use_after_free',
    label: 'Use-After-Free',
    col: 2,
    left: 250,
    top: 320,
    desc: 'Accessing pointers pointing to heap addresses that have already been released back to the allocator.'
  },
  got_overwrite: {
    id: 'got_overwrite',
    label: 'GOT Overwrite',
    col: 2,
    left: 250,
    top: 410,
    desc: 'Writing malicious function pointer addresses into the Global Offset Table to hijack library function lookups.'
  },

  ret2win: {
    id: 'ret2win',
    label: 'ret2win',
    col: 3,
    left: 490,
    top: 30,
    desc: 'A beginner attack path where the return address is overwritten to point directly to a secret win() function.'
  },
  ret2libc: {
    id: 'ret2libc',
    label: 'ret2libc',
    col: 3,
    left: 490,
    top: 110,
    desc: 'Redirects execution to system() within libc, passing "/bin/sh" as an argument to spawn a shell.'
  },
  format_string: {
    id: 'format_string',
    label: 'format_string',
    col: 3,
    left: 490,
    top: 190,
    desc: 'An attack that exploits format string parameters to leak pointers or perform arbitrary memory writes.'
  },
  heap_exploitation: {
    id: 'heap_exploitation',
    label: 'Heap Exploitation',
    col: 3,
    left: 490,
    top: 270,
    desc: 'Taverning heap bin lists (tcache/fastbin) to redirect allocation pointers to target code or variable data.'
  },
  rop_chain: {
    id: 'rop_chain',
    label: 'ROP Chain',
    col: 3,
    left: 490,
    top: 350,
    desc: 'Return-Oriented Programming. Chaining gadgets to load variables and bypass executable page protections.'
  },
  shellcode: {
    id: 'shellcode',
    label: 'shellcode',
    col: 3,
    left: 490,
    top: 430,
    desc: 'Injecting raw assembly payloads into writable buffers and jumping to them to spawn shells under disabled NX.'
  },

  nx: {
    id: 'nx',
    label: 'NX / DEP',
    col: 4,
    left: 730,
    top: 50,
    desc: 'No-Execute / Data Execution Prevention. Flags stack/heap pages as non-executable, stopping raw shellcode execution.'
  },
  pie: {
    id: 'pie',
    label: 'PIE / ASLR',
    col: 4,
    left: 730,
    top: 140,
    desc: 'Position Independent Executable / Address Space Layout Randomization. Randomizes target instruction locations.'
  },
  canary: {
    id: 'canary',
    label: 'Stack Canary',
    col: 4,
    left: 730,
    top: 230,
    desc: 'A secret integer stored before the stack return pointer. Corrupting it triggers bounds checks, crashing the process safely.'
  },
  relro: {
    id: 'relro',
    label: 'RELRO',
    col: 4,
    left: 730,
    top: 320,
    desc: 'ReLocation Read-Only. Locks GOT sectors against dynamic writes, neutralizing GOT overwrite hijacks.'
  },
  safe_functions: {
    id: 'safe_functions',
    label: 'Safe Functions',
    col: 4,
    left: 730,
    top: 410,
    desc: 'Bounded alternatives like fgets() and snprintf() that check sizes and eliminate standard overflows.'
  }
};

const CONNECTIONS = [
  // Col 1 to Col 2
  { from: 'gets', to: 'buffer_overflow', label: 'enables', type: 'enable' },
  { from: 'gets', to: 'ret2win', label: 'direct path', type: 'enable' },
  { from: 'gets', to: 'rop_chain', label: 'if NX on', type: 'enable' },
  { from: 'printf_buf', to: 'format_string_vuln', label: 'enables', type: 'enable' },
  { from: 'printf_buf', to: 'got_overwrite', label: 'enables', type: 'enable' },
  { from: 'strcpy', to: 'buffer_overflow', label: 'enables', type: 'enable' },
  { from: 'malloc_free', to: 'heap_corruption', label: 'enables', type: 'enable' },
  { from: 'malloc_free', to: 'use_after_free', label: 'enables', type: 'enable' },
  { from: 'system_fn', to: 'ret2libc', label: 'calls system()', type: 'enable' },

  // Col 2 to Col 3
  { from: 'buffer_overflow', to: 'ret2win', label: 'exploited via', type: 'enable' },
  { from: 'buffer_overflow', to: 'ret2libc', label: 'exploited via', type: 'enable' },
  { from: 'buffer_overflow', to: 'rop_chain', label: 'exploited via', type: 'enable' },
  { from: 'buffer_overflow', to: 'shellcode', label: 'exploited via', type: 'enable' },
  { from: 'format_string_vuln', to: 'format_string', label: 'exploited via', type: 'enable' },
  { from: 'format_string_vuln', to: 'got_overwrite', label: 'enables', type: 'enable' },
  { from: 'heap_corruption', to: 'heap_exploitation', label: 'exploited via', type: 'enable' },
  { from: 'use_after_free', to: 'heap_exploitation', label: 'exploited via', type: 'enable' },
  { from: 'got_overwrite', to: 'ret2libc', label: 'hijacks GOT to', type: 'enable' },

  // Col 4 to targets
  { from: 'nx', to: 'shellcode', label: 'blocks stack run', type: 'block' },
  { from: 'nx', to: 'rop_chain', label: 'forces gadget chain', type: 'force' },
  { from: 'pie', to: 'ret2win', label: 'complicates (need leak)', type: 'complicate' },
  { from: 'pie', to: 'ret2libc', label: 'complicates (need leak)', type: 'complicate' },
  { from: 'canary', to: 'buffer_overflow', label: 'detects overflow', type: 'block' },
  { from: 'relro', to: 'got_overwrite', label: 'blocks GOT write', type: 'block' },
  { from: 'safe_functions', to: 'buffer_overflow', label: 'prevents', type: 'block' },
  { from: 'safe_functions', to: 'format_string_vuln', label: 'prevents', type: 'block' }
];

export default function RelationshipMap() {
  const [hoveredNode, setHoveredNode] = useState(null);
  const [selectedNode, setSelectedNode] = useState(null);
  const containerRef = useRef(null);
  const [dims, setDims] = useState({ width: 800, height: 600 });

  useEffect(() => {
    if (!containerRef.current) return;
    const { offsetWidth, offsetHeight } = containerRef.current;
    if (offsetWidth > 0 && offsetHeight > 0) {
      setDims({ width: offsetWidth, height: offsetHeight });
    }
  }, []);

  const activeNode = hoveredNode || selectedNode;

  const handleNodeClick = (nodeId) => {
    try {
      if (selectedNode === nodeId) {
        setSelectedNode(null);
      } else {
        setSelectedNode(nodeId);
      }
    } catch (e) {
      console.error('[RelationshipMap] Click handler error:', e);
    }
  };

  const handleMouseEnter = (nodeId) => {
    try {
      setHoveredNode(nodeId);
    } catch (e) {
      console.error('[RelationshipMap] MouseEnter handler error:', e);
    }
  };

  const handleMouseLeave = () => {
    try {
      setHoveredNode(null);
    } catch (e) {
      console.error('[RelationshipMap] MouseLeave handler error:', e);
    }
  };

  const isNodeConnected = (nodeId) => {
    try {
      if (!activeNode) return true;
      if (nodeId === activeNode) return true;
      return (CONNECTIONS || []).some(c => 
        (c.from === activeNode && c.to === nodeId) || 
        (c.from === nodeId && c.to === activeNode)
      );
    } catch (e) {
      console.error('[RelationshipMap] isNodeConnected error:', e);
      return true;
    }
  };

  const isLineConnected = (c) => {
    try {
      if (!activeNode) return false;
      return c.from === activeNode || c.to === activeNode;
    } catch (e) {
      console.error('[RelationshipMap] isLineConnected error:', e);
      return false;
    }
  };

  const getLineColor = (type) => {
    switch (type) {
      case 'block':
        return '#f85149'; // red
      case 'force':
      case 'complicate':
        return '#e3b341'; // amber
      default:
        return '#388bfd'; // blue
    }
  };

  const activeConnections = activeNode 
    ? (CONNECTIONS || []).filter(c => c.from === activeNode || c.to === activeNode)
    : [];

  return (
    <div style={{ maxWidth: '960px', margin: '0 auto' }}>
      <h2 style={{ color: 'var(--text-primary)', fontSize: '20px',
        fontWeight: 600, marginBottom: '8px', textAlign: 'center' }}>
        What Changes What: Relationship Map
      </h2>
      <p style={{ color: 'var(--text-secondary)', fontSize: '13px',
        textAlign: 'center', marginBottom: '24px' }}>
        Hover or click a node to highlight its relations, showing how compiler choices, vulnerabilities, and protections interconnect.
      </p>

      {/* Main Diagram Area with scroll on narrow screens */}
      <div style={{ overflowX: 'auto', background: '#0d1117', border: '1px solid #30363d', borderRadius: '12px', padding: '16px', marginBottom: '24px' }}>
        <div ref={containerRef} style={{ width: '900px', height: '500px', position: 'relative', margin: '0 auto' }}>
          
          {/* SVG Overlay for Connection Lines */}
          <svg
            viewBox={`0 0 ${dims.width || 900} ${dims.height || 500}`}
            width={dims.width || 900}
            height={dims.height || 500}
            style={{ position: 'absolute', top: 0, left: 0, width: '100%', height: '100%', pointerEvents: 'none', zIndex: 1 }}
          >
            {(CONNECTIONS || []).map((c, idx) => {
              const fromNode = NODES?.[c.from];
              const toNode = NODES?.[c.to];
              if (!fromNode || !toNode) return null;
              if (fromNode.left === undefined || fromNode.top === undefined || toNode.left === undefined || toNode.top === undefined) return null;

              // Compute ports based on left-to-right flow or right-to-left flow (mitigations)
              const fromCol = fromNode.col;
              const toCol = toNode.col;
              
              let startX, startY, endX, endY;
              
              if (fromCol < toCol) {
                // Left to right
                startX = fromNode.left + 160;
                startY = fromNode.top + 25;
                endX = toNode.left;
                endY = toNode.top + 25;
              } else {
                // Right to left (Mitigations to Vulns/Techniques)
                startX = fromNode.left;
                startY = fromNode.top + 25;
                endX = toNode.left + 160;
                endY = toNode.top + 25;
              }

              const controlX1 = startX + (endX - startX) * 0.4;
              const controlY1 = startY;
              const controlX2 = startX + (endX - startX) * 0.6;
              const controlY2 = endY;

              const isHighlighted = isLineConnected(c);
              const opacity = activeNode ? (isHighlighted ? 0.95 : 0.04) : 0.25;
              const color = getLineColor(c.type);

              return (
                <g key={idx}>
                  <path
                    d={`M ${startX} ${startY} C ${controlX1} ${controlY1}, ${controlX2} ${controlY2}, ${endX} ${endY}`}
                    fill="none"
                    stroke={color}
                    strokeWidth={isHighlighted ? 3 : 1.5}
                    opacity={opacity}
                    style={{ transition: 'stroke-width 0.15s, opacity 0.15s' }}
                  />
                  {isHighlighted && (
                    <text
                      x={(startX + endX) / 2}
                      y={(startY + endY) / 2 - 4}
                      fill={color}
                      fontSize="9px"
                      fontFamily="monospace"
                      textAnchor="middle"
                      opacity={0.9}
                      style={{ background: '#0d1117', padding: '2px' }}
                    >
                      {c.label}
                    </text>
                  )}
                </g>
              );
            })}
          </svg>

          {/* Column Headers */}
          <div style={{ position: 'absolute', top: '10px', left: '10px', width: '160px', textAlign: 'center', fontSize: '11px', fontWeight: 700, color: '#58a6ff', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
            Dangerous Functions
          </div>
          <div style={{ position: 'absolute', top: '10px', left: '250px', width: '160px', textAlign: 'center', fontSize: '11px', fontWeight: 700, color: '#ff7b72', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
            Vulnerabilities
          </div>
          <div style={{ position: 'absolute', top: '10px', left: '490px', width: '160px', textAlign: 'center', fontSize: '11px', fontWeight: 700, color: '#f0e042', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
            Exploit Techniques
          </div>
          <div style={{ position: 'absolute', top: '10px', left: '730px', width: '160px', textAlign: 'center', fontSize: '11px', fontWeight: 700, color: '#56d364', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
            Mitigations
          </div>

          {/* Node Cards */}
          {(Object.values(NODES || {}) || []).map((node) => {
            if (!node) return null;
            const isConnected = isNodeConnected(node.id);
            const isMainActive = activeNode === node.id;
            const opacity = activeNode ? (isConnected ? 1.0 : 0.25) : 1.0;
            
            let colorTheme = '#30363d'; // default
            if (isMainActive) {
              colorTheme = '#58a6ff';
            } else if (node.col === 1) {
              colorTheme = '#1f242c';
            } else if (node.col === 2) {
              colorTheme = '#281515';
            } else if (node.col === 3) {
              colorTheme = '#2b2214';
            } else if (node.col === 4) {
              colorTheme = '#162c1e';
            }

            let borderTheme = '#30363d';
            if (isMainActive) {
              borderTheme = '#58a6ff';
            } else if (activeNode && isConnected) {
              borderTheme = '#8b949e';
            }

            return (
              <div
                key={node.id}
                onMouseEnter={() => handleMouseEnter(node.id)}
                onMouseLeave={() => handleMouseLeave()}
                onClick={() => handleNodeClick(node.id)}
                style={{
                  position: 'absolute',
                  left: `${node.left}px`,
                  top: `${node.top}px`,
                  width: '160px',
                  height: '50px',
                  background: colorTheme,
                  border: `1px solid ${borderTheme}`,
                  borderRadius: '6px',
                  display: 'flex',
                  justifyContent: 'center',
                  alignItems: 'center',
                  cursor: 'pointer',
                  zIndex: isMainActive ? 10 : 5,
                  opacity: opacity,
                  userSelect: 'none',
                  boxShadow: isMainActive ? '0 0 10px rgba(88, 166, 255, 0.4)' : 'none',
                  transition: 'opacity 0.15s, border-color 0.15s, background-color 0.15s'
                }}
              >
                <div style={{
                  fontSize: '13px',
                  fontWeight: 600,
                  color: isMainActive ? '#fff' : '#c9d1d9',
                  textAlign: 'center',
                  fontFamily: node.col === 1 || node.col === 3 ? 'monospace' : 'inherit'
                }}>
                  {node.label}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Explanatory Details Panel */}
      <div style={{
        background: '#161b22',
        border: '1px solid #30363d',
        borderRadius: '12px',
        padding: '24px',
        minHeight: '130px'
      }}>
        {activeNode && NODES?.[activeNode] ? (
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
              <h3 style={{ margin: 0, fontSize: '18px', fontWeight: 600, color: 'var(--text-primary)' }}>
                {NODES[activeNode]?.label}
              </h3>
              <span style={{ fontSize: '11px', color: '#8b949e', textTransform: 'uppercase', fontWeight: 700 }}>
                Column {NODES[activeNode]?.col} Node
              </span>
            </div>
            <p style={{ color: '#c9d1d9', fontSize: '14px', lineHeight: '1.6', margin: '0 0 16px' }}>
              {NODES[activeNode]?.desc}
            </p>

            {/* List connections */}
            {(activeConnections || []).length > 0 && (
              <div>
                <h4 style={{ fontSize: '11px', color: '#8b949e', textTransform: 'uppercase', letterSpacing: '0.05em', margin: '0 0 8px' }}>
                  Related Connections
                </h4>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                  {(activeConnections || []).map((c, i) => {
                    const fromNode = NODES?.[c.from];
                    const toNode = NODES?.[c.to];
                    if (!fromNode || !toNode) return null;
                    const isFrom = c.from === activeNode;
                    const relationColor = getLineColor(c.type);

                    return (
                      <div key={i} style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '13px', color: '#c9d1d9' }}>
                        <span style={{ fontWeight: 600, color: isFrom ? '#58a6ff' : '#8b949e' }}>
                          {fromNode?.label}
                        </span>
                        <span style={{
                          fontSize: '10px',
                          padding: '1px 6px',
                          borderRadius: '4px',
                          background: relationColor + '20',
                          border: `1px solid ${relationColor}`,
                          color: relationColor,
                          fontWeight: 700
                        }}>
                          {c.label}
                        </span>
                        <span style={{ fontWeight: 600, color: !isFrom ? '#58a6ff' : '#8b949e' }}>
                          {toNode.label}
                        </span>
                      </div>
                    );
                  })}
                </div>
              </div>
            )}
          </div>
        ) : (
          <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '80px', color: '#8b949e', fontSize: '14px' }}>
            💡 Click or hover any block in the map to discover its compiler, vulnerability, and exploit paths.
          </div>
        )}
      </div>
    </div>
  );
}
