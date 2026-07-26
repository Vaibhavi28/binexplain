import React from 'react';

/**
 * Shared provenance extraction utility.
 * Inspects text against binaryContext findings to identify the exact evidence type and value.
 */
export const extractFrontendProvenance = (text, binaryContext) => {
  if (!text || typeof text !== 'string') return { evidence_type: 'general', evidence_value: null };
  const ctx = binaryContext || {};

  const escapeRegExp = (str) => String(str).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

  // 1. Resolve offset safely
  let offsetStr = null;
  const rawOffset = ctx.predicted_offset ?? ctx.overflow_offset ?? ctx.likely_offset ?? ctx.offset ?? ctx.overflow_hint?.likely_offset;
  if (rawOffset !== null && rawOffset !== undefined && String(rawOffset).trim() !== '') {
    const num = parseInt(rawOffset, 10);
    if (!isNaN(num)) {
      offsetStr = String(num);
    } else {
      offsetStr = String(rawOffset).trim();
    }
  }

  // 2. Resolve functions safely
  const functions = ctx.functions || ctx.function_list || ctx.detected_functions || [];
  const functionNames = [];
  for (const f of functions.slice(0, 15)) {
    if (typeof f === 'object' && f?.name) {
      functionNames.push(String(f.name).trim());
    } else if (f) {
      functionNames.push(String(f).trim());
    }
  }

  // 3. Resolve protections safely
  const protections = ctx.protections || ctx.checksec || {};

  // 4. Resolve disassembly safely
  const disassembly = ctx.disassembly || ctx.disasm || ctx.disassembly_excerpt || [];

  // 5. Resolve ROP gadgets safely
  const ropGadgets = ctx.rop_gadgets || ctx.gadgets || [];

  const candidates = {};

  // Category A: disassembly_line
  for (const item of disassembly) {
    const lineStr = (typeof item === 'object' && item?.line) ? item.line : String(item);
    const stripped = lineStr.trim();
    if (stripped.length > 5 && text.toLowerCase().includes(stripped.toLowerCase())) {
      candidates.disassembly_line = { evidence_type: 'disassembly_line', evidence_value: stripped };
      break;
    }
  }

  // Category B: rop_gadget
  for (const g of ropGadgets) {
    const gStr = (typeof g === 'object' && g?.gadget) ? g.gadget : String(g);
    const stripped = gStr.trim();
    if (stripped.length > 3 && text.toLowerCase().includes(stripped.toLowerCase())) {
      candidates.rop_gadget = { evidence_type: 'rop_gadget', evidence_value: stripped };
      break;
    }
  }

  // Category C: overflow_offset
  if (offsetStr && offsetStr !== '0') {
    const regex = new RegExp('\\b' + escapeRegExp(offsetStr) + '\\b', 'i');
    if (regex.test(text)) {
      candidates.overflow_offset = { evidence_type: 'overflow_offset', evidence_value: offsetStr };
    }
  }

  // Category D: detected_function
  for (const fname of functionNames) {
    if (fname && fname.length > 1) {
      const regex = new RegExp('\\b' + escapeRegExp(fname) + '\\b', 'i');
      if (regex.test(text)) {
        candidates.detected_function = { evidence_type: 'detected_function', evidence_value: fname };
        break;
      }
    }
  }

  // Category E: protection_flag
  const protAliases = {
    nx: ['nx', 'no-execute', 'noexecute', 'dep', 'non-executable', 'w^x'],
    pie: ['pie', 'position independent', 'aslr'],
    canary: ['canary', 'stack canary', 'stack cookie', '__stack_chk'],
    relro: ['relro', 'read-only relocations'],
    fortify: ['fortify', 'fortified']
  };

  if (typeof protections === 'object' && protections !== null) {
    for (const [k, v] of Object.entries(protections)) {
      if (!k) continue;
      const kLower = String(k).toLowerCase();
      const aliases = protAliases[kLower] || [kLower];
      for (const alias of aliases) {
        const regex = new RegExp('\\b' + escapeRegExp(alias) + '\\b', 'i');
        if (regex.test(text)) {
          const valStr = (v !== null && v !== undefined) ? String(v) : 'Enabled';
          candidates.protection_flag = { evidence_type: 'protection_flag', evidence_value: `${String(k).toUpperCase()}: ${valStr}` };
          break;
        }
      }
      if (candidates.protection_flag) break;
    }
  } else if (Array.isArray(protections)) {
    for (const prot of protections) {
      const protStr = String(prot).trim();
      if (protStr) {
        const regex = new RegExp('\\b' + escapeRegExp(protStr) + '\\b', 'i');
        if (regex.test(text)) {
          candidates.protection_flag = { evidence_type: 'protection_flag', evidence_value: protStr };
          break;
        }
      }
    }
  }

  const priorityOrder = ['disassembly_line', 'rop_gadget', 'overflow_offset', 'detected_function', 'protection_flag'];
  for (const etype of priorityOrder) {
    if (candidates[etype]) {
      return candidates[etype];
    }
  }

  return { evidence_type: 'general', evidence_value: null };
};

/**
 * Shared provenance badge renderer.
 * Renders a small badge showing which finding supports a claim.
 */
export const renderProvenanceBadge = (item, binaryContext, options = {}) => {
  if (!item) return null;
  const isMessage = typeof item === 'object' && item !== null && 'content' in item;
  if (isMessage && item.role !== 'assistant') return null;

  const text = isMessage ? item.content : String(item);
  const prov = (isMessage && item.provenance) ? item.provenance : extractFrontendProvenance(text, binaryContext);

  if (options?.hideGeneral && prov?.evidence_type === 'general') {
    return null;
  }

  return (
    <div
      className="provenance-badge"
      style={{
        marginTop: '6px',
        fontSize: '11px',
        color: prov?.evidence_type === 'general' ? '#8b949e' : '#58a6ff',
        background: 'rgba(22, 27, 34, 0.6)',
        border: '1px solid rgba(48, 54, 61, 0.6)',
        borderRadius: '4px',
        padding: '3px 8px',
        display: 'inline-flex',
        alignItems: 'center',
        gap: '4px',
        ...options.style
      }}
    >
      {prov?.evidence_type === 'detected_function' && (
        <span>Based on: <strong>{prov.evidence_value}</strong> in the detected functions</span>
      )}
      {prov?.evidence_type === 'overflow_offset' && (
        <span>Based on: the detected overflow offset (<strong>{prov.evidence_value}</strong> bytes)</span>
      )}
      {prov?.evidence_type === 'protection_flag' && (
        <span>Based on: <strong>{prov.evidence_value}</strong> status shown above</span>
      )}
      {prov?.evidence_type === 'disassembly_line' && (
        <span>Based on: the disassembly excerpt shown above</span>
      )}
      {prov?.evidence_type === 'rop_gadget' && (
        <span>Based on: the ROP gadgets listed above</span>
      )}
      {(!prov || prov?.evidence_type === 'general') && !options?.hideGeneral && (
        <span style={{ fontStyle: 'italic', color: '#8b949e' }}>General guidance — not tied to a specific finding</span>
      )}
    </div>
  );
};
