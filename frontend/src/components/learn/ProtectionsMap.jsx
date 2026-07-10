import React, { useState } from 'react';
import GlossaryText from '../GlossaryText';

export default function ProtectionsMap() {
  const [protections, setProtections] = useState({
    nx: true,
    pie: true,
    canary: true,
    relro: 'full',
    fortify: false,
  });

  const [selectedAttack, setSelectedAttack] = useState('shellcode');

  const toggleProtection = (name) => {
    setProtections((prev) => ({ ...prev, [name]: !prev[name] }));
  };

  const setRelro = (level) => {
    setProtections((prev) => ({ ...prev, relro: level }));
  };

  const getStatus = (id) => {
    switch (id) {
      case 'shellcode':
        return !protections.nx ? 'available' : 'blocked';
      case 'ret2win':
        if (protections.canary) return 'blocked';
        return protections.pie ? 'harder' : 'available';
      case 'ret2libc':
        if (protections.canary) return 'blocked';
        return (protections.pie || protections.relro === 'full') ? 'harder' : 'available';
      case 'format_string':
        return protections.relro === 'full' ? 'harder' : 'available';
      case 'heap_exploitation':
        return protections.relro === 'full' ? 'harder' : 'available';
      case 'rop_chain':
        if (protections.canary) return 'blocked';
        return protections.pie ? 'harder' : 'available';
      default:
        return 'available';
    }
  };

  const getExplanation = (id) => {
    const status = getStatus(id);
    switch (id) {
      case 'shellcode':
        if (status === 'blocked') {
          return 'No-Execute (NX) is enabled, meaning stack and heap pages are not executable. Direct shellcode execution is prevented.';
        }
        return 'No-Execute (NX) is disabled! You can write executable shellcode to a stack/heap buffer and jump to its address to execute arbitrary instructions.';
      case 'ret2win':
        if (status === 'blocked') {
          return 'The Stack Canary detects the stack buffer overflow when trying to rewrite the return address, terminating the program before reaching win().';
        }
        if (status === 'harder') {
          return 'No Stack Canary prevents the overflow, but Position Independent Executable (PIE) is enabled. Addresses are randomized, so you must leak a code address first to find win().';
        }
        return 'No Stack Canary and PIE is disabled! The address of win() is static and predictable. You can overwrite the return address directly to it.';
      case 'ret2libc':
        if (status === 'blocked') {
          return 'The active Stack Canary prevents overwriting the saved return address on the stack, blocking basic ret2libc.';
        }
        if (status === 'harder') {
          if (protections.pie && protections.relro === 'full') {
            return 'Stack Canary is disabled allowing return address control, but PIE randomizes libc in memory (requiring a leak) and Full RELRO protects function tables (GOT).';
          }
          if (protections.pie) {
            return 'Canary is disabled, but PIE is active. You must leak a library address first to calculate the randomized location of libc functions (like system).';
          }
          return 'Canary is disabled, but Full RELRO prevents modifying GOT entries, making target redirection harder.';
        }
        return 'Canary is disabled, PIE is disabled, and RELRO is not Full. You can overwrite the stack return address directly with fixed libc system() and /bin/sh addresses.';
      case 'format_string':
        if (status === 'harder') {
          return 'Format string is active (e.g. printf(buffer)), but Full RELRO makes the GOT read-only. You can read variables and leak pointers, but you cannot overwrite dynamic function pointers.';
        }
        return 'Format string is active, and the GOT is writable (RELRO is not Full). You can leak sensitive addresses (canary, libc base) and rewrite GOT entries to hijack execution.';
      case 'heap_exploitation':
        if (status === 'harder') {
          return 'Heap vulnerabilities are exploitable, but with Full RELRO active, you cannot overwrite GOT pointers. You must target heap metadata or other function pointers.';
        }
        return 'Heap vulnerabilities allow heap allocation hijacking. Since RELRO is not Full, you can easily overwrite GOT entries to redirect execution to system().';
      case 'rop_chain':
        if (status === 'blocked') {
          return 'The active Stack Canary prevents stack hijacking, blocking you from creating a custom ROP chain on the stack.';
        }
        if (status === 'harder') {
          return 'Canary is disabled, but PIE is enabled. You can construct a ROP chain on the stack, but you must first leak the binary base address to find gadget offsets.';
        }
        return 'NX is active, making ROP chain necessary. Since Canary is OFF and PIE is OFF, you can overwrite the return address and chains using fixed gadget addresses.';
      default:
        return '';
    }
  };

  const attacks = [
    { id: 'shellcode', label: 'Shellcode Injection' },
    { id: 'ret2win', label: 'ret2win' },
    { id: 'ret2libc', label: 'ret2libc' },
    { id: 'format_string', label: 'Format String' },
    { id: 'heap_exploitation', label: 'Heap Exploitation' },
    { id: 'rop_chain', label: 'ROP Chain' },
  ];

  const getStatusColor = (status) => {
    switch (status) {
      case 'available':
        return { bg: '#162c1e', border: '#2ea043', text: '#56d364', label: 'Available' };
      case 'harder':
        return { bg: '#382a17', border: '#d29922', text: '#f0e042', label: 'Harder' };
      case 'blocked':
        return { bg: '#3c1e1e', border: '#f85149', text: '#ff7b72', label: 'Blocked' };
      default:
        return { bg: '#21262d', border: '#30363d', text: '#c9d1d9', label: 'Unknown' };
    }
  };

  return (
    <div style={{ maxWidth: '960px', margin: '0 auto' }}>
      <h2 style={{ color: 'var(--text-primary)', fontSize: '20px',
        fontWeight: 600, marginBottom: '8px', textAlign: 'center' }}>
        Security Protections vs. Exploitation
      </h2>
      <p style={{ color: 'var(--text-secondary)', fontSize: '13px',
        textAlign: 'center', marginBottom: '32px' }}>
        Toggle compiler flags and security controls to see how they defend against CTF exploitation techniques
      </p>

      <div style={{
        display: 'flex',
        gap: '24px',
        flexWrap: 'wrap',
      }}>
        {/* Left Panel: Protections */}
        <div style={{
          flex: '1 1 350px',
          background: '#161b22',
          padding: '24px',
          borderRadius: '12px',
          border: '1px solid #30363d',
          display: 'flex',
          flexDirection: 'column',
          gap: '20px',
        }}>
          <h3 style={{ margin: '0 0 10px', fontSize: '16px', fontWeight: 600, color: 'var(--text-primary)' }}>
            Binary Protections
          </h3>

          {/* NX */}
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div>
              <div style={{ fontSize: '14px', fontWeight: 600, color: '#c9d1d9' }}>NX (No-Execute)</div>
              <div style={{ fontSize: '11px', color: '#8b949e', marginTop: '2px' }}>
                Prevents execution of code on stack/heap
              </div>
            </div>
            <button
              onClick={() => toggleProtection('nx')}
              style={{
                width: '46px', height: '24px', borderRadius: '12px',
                background: protections.nx ? '#238636' : '#30363d',
                border: 'none', cursor: 'pointer', position: 'relative',
                padding: 0, transition: 'background 0.2s'
              }}
            >
              <div style={{
                width: '18px', height: '18px', borderRadius: '50%',
                background: '#fff', position: 'absolute', top: '3px',
                left: protections.nx ? '25px' : '3px',
                transition: 'left 0.2s'
              }} />
            </button>
          </div>

          {/* PIE */}
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div>
              <div style={{ fontSize: '14px', fontWeight: 600, color: '#c9d1d9' }}>PIE (Position Independent Executable)</div>
              <div style={{ fontSize: '11px', color: '#8b949e', marginTop: '2px' }}>
                Randomizes memory address space layout
              </div>
            </div>
            <button
              onClick={() => toggleProtection('pie')}
              style={{
                width: '46px', height: '24px', borderRadius: '12px',
                background: protections.pie ? '#238636' : '#30363d',
                border: 'none', cursor: 'pointer', position: 'relative',
                padding: 0, transition: 'background 0.2s'
              }}
            >
              <div style={{
                width: '18px', height: '18px', borderRadius: '50%',
                background: '#fff', position: 'absolute', top: '3px',
                left: protections.pie ? '25px' : '3px',
                transition: 'left 0.2s'
              }} />
            </button>
          </div>

          {/* Stack Canary */}
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div>
              <div style={{ fontSize: '14px', fontWeight: 600, color: '#c9d1d9' }}>Stack Canary</div>
              <div style={{ fontSize: '11px', color: '#8b949e', marginTop: '2px' }}>
                Detects stack buffer overflow triggers
              </div>
            </div>
            <button
              onClick={() => toggleProtection('canary')}
              style={{
                width: '46px', height: '24px', borderRadius: '12px',
                background: protections.canary ? '#238636' : '#30363d',
                border: 'none', cursor: 'pointer', position: 'relative',
                padding: 0, transition: 'background 0.2s'
              }}
            >
              <div style={{
                width: '18px', height: '18px', borderRadius: '50%',
                background: '#fff', position: 'absolute', top: '3px',
                left: protections.canary ? '25px' : '3px',
                transition: 'left 0.2s'
              }} />
            </button>
          </div>

          {/* RELRO */}
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
              <div>
                <div style={{ fontSize: '14px', fontWeight: 600, color: '#c9d1d9' }}>RELRO (ReLocation Read-Only)</div>
                <div style={{ fontSize: '11px', color: '#8b949e', marginTop: '2px' }}>
                  Protects GOT pointers from arbitrary overwrites
                </div>
              </div>
            </div>
            <div style={{ display: 'flex', gap: '4px', background: '#21262d', padding: '3px', borderRadius: '6px' }}>
              {['none', 'partial', 'full'].map((lvl) => (
                <button
                  key={lvl}
                  onClick={() => setRelro(lvl)}
                  style={{
                    flex: 1,
                    padding: '6px 10px',
                    borderRadius: '4px',
                    border: 'none',
                    fontSize: '11px',
                    fontWeight: 600,
                    textTransform: 'uppercase',
                    cursor: 'pointer',
                    background: protections.relro === lvl ? '#388bfd' : 'transparent',
                    color: protections.relro === lvl ? '#fff' : '#8b949e',
                    transition: 'all 0.15s',
                  }}
                >
                  {lvl}
                </button>
              ))}
            </div>
          </div>

          {/* Fortify */}
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div>
              <div style={{ fontSize: '14px', fontWeight: 600, color: '#c9d1d9' }}>Fortify Source</div>
              <div style={{ fontSize: '11px', color: '#8b949e', marginTop: '2px' }}>
                Replaces risky string functions with safe checks
              </div>
            </div>
            <button
              onClick={() => toggleProtection('fortify')}
              style={{
                width: '46px', height: '24px', borderRadius: '12px',
                background: protections.fortify ? '#238636' : '#30363d',
                border: 'none', cursor: 'pointer', position: 'relative',
                padding: 0, transition: 'background 0.2s'
              }}
            >
              <div style={{
                width: '18px', height: '18px', borderRadius: '50%',
                background: '#fff', position: 'absolute', top: '3px',
                left: protections.fortify ? '25px' : '3px',
                transition: 'left 0.2s'
              }} />
            </button>
          </div>
        </div>

        {/* Right Panel: Attacks */}
        <div style={{
          flex: '1 2 450px',
          background: '#161b22',
          padding: '24px',
          borderRadius: '12px',
          border: '1px solid #30363d',
          display: 'flex',
          flexDirection: 'column',
          justifyContent: 'space-between',
        }}>
          <div>
            <h3 style={{ margin: '0 0 16px', fontSize: '16px', fontWeight: 600, color: 'var(--text-primary)' }}>
              Exploitation Feasibility
            </h3>

            {/* Attack Grid */}
            <div style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fill, minmax(130px, 1fr))',
              gap: '10px',
              marginBottom: '20px',
            }}>
              {attacks.map((atk) => {
                const status = getStatus(atk.id);
                const colorMap = getStatusColor(status);
                const isSelected = selectedAttack === atk.id;
                return (
                  <div
                    key={atk.id}
                    onClick={() => setSelectedAttack(atk.id)}
                    style={{
                      background: colorMap.bg,
                      border: `1px solid ${isSelected ? '#388bfd' : colorMap.border}`,
                      boxShadow: isSelected ? '0 0 8px rgba(56, 139, 253, 0.4)' : 'none',
                      borderRadius: '8px',
                      padding: '12px',
                      cursor: 'pointer',
                      display: 'flex',
                      flexDirection: 'column',
                      justifyContent: 'space-between',
                      minHeight: '80px',
                      transition: 'transform 0.15s, border-color 0.15s',
                      transform: isSelected ? 'scale(1.02)' : 'none',
                    }}
                  >
                    <div style={{ fontSize: '12px', fontWeight: 700, color: '#f0f6fc', lineHeight: '1.3' }}>
                      {atk.label}
                    </div>
                    <div style={{
                      fontSize: '9px',
                      fontWeight: 700,
                      textTransform: 'uppercase',
                      color: colorMap.text,
                      marginTop: '8px',
                      letterSpacing: '0.05em',
                    }}>
                      {colorMap.label}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Explanation panel for the selected attack */}
          <div style={{
            background: '#0d1117',
            border: '1px solid #30363d',
            borderRadius: '8px',
            padding: '16px',
            minHeight: '110px',
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
              <div style={{ fontSize: '14px', fontWeight: 700, color: '#f0f6fc' }}>
                {attacks.find((a) => a.id === selectedAttack)?.label}
              </div>
              <span style={{
                fontSize: '11px',
                fontWeight: 700,
                padding: '2px 8px',
                borderRadius: '10px',
                textTransform: 'uppercase',
                background: getStatusColor(getStatus(selectedAttack)).bg,
                color: getStatusColor(getStatus(selectedAttack)).text,
                border: `1px solid ${getStatusColor(getStatus(selectedAttack)).border}`,
              }}>
                {getStatusColor(getStatus(selectedAttack)).label}
              </span>
            </div>
            <p style={{ color: '#c9d1d9', fontSize: '13px', lineHeight: '1.5', margin: 0 }}>
              <GlossaryText text={getExplanation(selectedAttack)} />
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
