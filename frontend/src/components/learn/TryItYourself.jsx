import React from 'react';

const CARDS = [
  {
    id: 'ret2win',
    title: 'ret2win',
    difficulty: 'Easy',
    difficultyColor: { bg: '#162c1e', border: '#2ea043', text: '#56d364' },
    desc: 'Find a picoCTF binary exploitation challenge rated Easy. Look for challenges named \'buffer overflow\', \'vuln\', or \'get it\'.',
    where: 'picoCTF.org → Binary Exploitation → Easy',
    checklist: [
      'CTF Category: ret2win (High confidence)',
      'Win function detected in symbol table',
      'Overflow offset predicted from disassembly',
      'Pwntools template pre-populated with win address'
    ]
  },
  {
    id: 'format_string',
    title: 'format_string',
    difficulty: 'Easy/Medium',
    difficultyColor: { bg: '#382a17', border: '#d29922', text: '#f0e042' },
    desc: 'Look for CTF binaries that print your input back to you. Test manually: python3 -c \'print("%p")\' | ./binary. If you see 0x... in the output, it is vulnerable.',
    where: 'CTFtime.org → filter by pwn → look for format string tag',
    checklist: [
      'CTF Category: format_string',
      'printf() without format argument detected',
      'Similar writeups from knowledge base',
      'fmtstr_payload usage in AI hints'
    ]
  },
  {
    id: 'heap_exploitation',
    title: 'heap_exploitation',
    difficulty: 'Hard',
    difficultyColor: { bg: '#3c1e1e', border: '#f85149', text: '#ff7b72' },
    desc: 'Look for binaries with a menu (1. Add, 2. Delete, 3. Edit). Menu-driven heap challenges are very common.',
    where: 'HackTheBox → Challenges → Pwn → Medium/Hard',
    checklist: [
      'CTF Category: heap_exploitation',
      'Heap functions detected (malloc/free)',
      'Menu structure detected in strings',
      'AI hints reference specific heap technique'
    ]
  },
  {
    id: 'ret2libc',
    title: 'ret2libc',
    difficulty: 'Medium',
    difficultyColor: { bg: '#382a17', border: '#d29922', text: '#f0e042' },
    desc: 'Look for binaries with NX enabled but no stack canary. Run checksec first — if NX=Enabled and Canary=No, this is likely.',
    where: 'picoCTF → Binary Exploitation → Medium',
    checklist: [
      'CTF Category: ret2libc',
      'Libc version identified',
      'PLT/GOT table extracted',
      'Pwntools template with libc leak scaffold'
    ]
  },
  {
    id: 'rop_chain',
    title: 'rop_chain',
    difficulty: 'Medium/Hard',
    difficultyColor: { bg: '#3c1e1e', border: '#f85149', text: '#ff7b72' },
    desc: 'Look for binaries with NX enabled AND a stack canary. Full protection binaries almost always require ROP.',
    where: 'CTFtime.org → pwn → filter for harder challenges',
    checklist: [
      'CTF Category: rop_chain',
      'ROP gadgets detected with addresses',
      'pop rdi gadget highlighted if present',
      'Pwntools template with gadget addresses'
    ]
  },
  {
    id: 'shellcode',
    title: 'shellcode',
    difficulty: 'Easy (with older binaries)',
    difficultyColor: { bg: '#162c1e', border: '#2ea043', text: '#56d364' },
    desc: 'Look for old CTF binaries (pre-2015) or challenges specifically marked as NX disabled. These are rare in modern CTFs.',
    where: 'picoCTF older archives, Pwnable.kr',
    checklist: [
      'CTF Category: shellcode',
      'NX: Disabled shown in checksec',
      'shellcraft.sh() mentioned in AI hints'
    ]
  }
];

export default function TryItYourself({ onSectionChange }) {
  return (
    <div style={{ maxWidth: '960px', margin: '0 auto' }}>
      <h2 style={{ color: 'var(--text-primary)', fontSize: '20px',
        fontWeight: 600, marginBottom: '8px', textAlign: 'center' }}>
        Practice Challenges & Targets
      </h2>
      <p style={{ color: 'var(--text-secondary)', fontSize: '13px',
        textAlign: 'center', marginBottom: '32px' }}>
        Ready to take what you have learned and apply it to a real binary? Choose a target, download a challenge, and run it through the BinExplain analyser.
      </p>

      {/* Grid of 6 Challenge Cards */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))',
        gap: '20px',
        marginBottom: '48px'
      }}>
        {CARDS.map((c) => (
          <div
            key={c.id}
            style={{
              background: '#161b22',
              border: '1px solid #30363d',
              borderRadius: '10px',
              padding: '24px',
              display: 'flex',
              flexDirection: 'column',
              justifyContent: 'space-between',
              minHeight: '340px',
              transition: 'transform 0.15s, border-color 0.15s, box-shadow 0.15s'
            }}
            onMouseEnter={(e) => {
              e.currentTarget.style.transform = 'translateY(-2px)';
              e.currentTarget.style.borderColor = '#388bfd';
              e.currentTarget.style.boxShadow = '0 4px 12px rgba(56, 139, 253, 0.1)';
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.transform = 'translateY(0)';
              e.currentTarget.style.borderColor = '#30363d';
              e.currentTarget.style.boxShadow = 'none';
            }}
          >
            <div>
              {/* Header */}
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
                <h3 style={{ margin: 0, fontSize: '16px', fontWeight: 700, color: '#f0f6fc', fontFamily: 'monospace' }}>
                  {c.title}
                </h3>
                <span style={{
                  fontSize: '9px',
                  fontWeight: 700,
                  padding: '2px 6px',
                  borderRadius: '4px',
                  background: c.difficultyColor.bg,
                  border: `1px solid ${c.difficultyColor.border}`,
                  color: c.difficultyColor.text,
                  textTransform: 'uppercase'
                }}>
                  {c.difficulty}
                </span>
              </div>

              {/* Description */}
              <p style={{ color: '#c9d1d9', fontSize: '13px', lineHeight: '1.5', margin: '0 0 16px' }}>
                {c.desc}
              </p>

              {/* Source/Find */}
              <div style={{ marginBottom: '20px' }}>
                <div style={{ fontSize: '10px', color: '#8b949e', textTransform: 'uppercase', fontWeight: 700, marginBottom: '4px' }}>
                  Where to find
                </div>
                <div style={{ color: '#58a6ff', fontSize: '12px', fontWeight: 500 }}>
                  {c.where}
                </div>
              </div>

              {/* Checklist */}
              <div style={{ marginBottom: '24px' }}>
                <div style={{ fontSize: '10px', color: '#8b949e', textTransform: 'uppercase', fontWeight: 700, marginBottom: '6px' }}>
                  What BinExplain finds
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                  {c.checklist.map((item, idx) => (
                    <div key={idx} style={{ display: 'flex', alignItems: 'flex-start', gap: '8px', fontSize: '11px', color: '#c9d1d9' }}>
                      <span style={{ color: '#56d364', fontWeight: 'bold' }}>✓</span>
                      <span>{item}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* Action */}
            <a
              href="/"
              style={{
                display: 'block',
                padding: '10px 14px',
                background: '#21262d',
                border: '1px solid #30363d',
                borderRadius: '6px',
                color: '#f0f6fc',
                textDecoration: 'none',
                fontSize: '13px',
                fontWeight: 600,
                textAlign: 'center',
                transition: 'all 0.15s'
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.background = '#388bfd';
                e.currentTarget.style.borderColor = '#388bfd';
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.background = '#21262d';
                e.currentTarget.style.borderColor = '#30363d';
              }}
            >
              Analyze a binary →
            </a>
          </div>
        ))}
      </div>

      {/* Bottom CTA Block */}
      <div style={{
        background: '#161b22',
        border: '1px solid #30363d',
        borderRadius: '12px',
        padding: '40px 24px',
        textAlign: 'center',
        boxShadow: '0 4px 20px rgba(0,0,0,0.2)'
      }}>
        <h3 style={{ color: '#f0f6fc', fontSize: '22px', fontWeight: 700, margin: '0 0 12px' }}>
          Ready to analyze your own binary?
        </h3>
        <p style={{ color: '#8b949e', fontSize: '14px', maxWidth: '500px', margin: '0 auto 24px', lineHeight: '1.5' }}>
          Drop your CTF executable or ZIP files containing binaries directly into our analysis suite to extract dynamic insights instantly.
        </p>

        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '16px' }}>
          <a
            href="/"
            style={{
              display: 'inline-block',
              padding: '12px 28px',
              background: '#238636',
              border: '1px solid #2ea043',
              color: '#fff',
              borderRadius: '8px',
              textDecoration: 'none',
              fontSize: '15px',
              fontWeight: 600,
              boxShadow: '0 2px 6px rgba(35, 134, 54, 0.3)',
              transition: 'background 0.15s'
            }}
            onMouseEnter={(e) => { e.currentTarget.style.background = '#2ea043'; }}
            onMouseLeave={(e) => { e.currentTarget.style.background = '#238636'; }}
          >
            Upload a binary →
          </a>
          
          <span style={{ color: '#8b949e', fontSize: '12px', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
            or
          </span>

          <button
            onClick={() => {
              if (onSectionChange) {
                onSectionChange('flowchart');
              }
              // Smooth scroll to top/nav
              window.scrollTo({ top: 0, behavior: 'smooth' });
            }}
            style={{
              background: 'none',
              border: 'none',
              color: '#58a6ff',
              fontSize: '14px',
              fontWeight: 600,
              cursor: 'pointer',
              textDecoration: 'underline',
              padding: '4px 8px'
            }}
          >
            Not sure where to start? Try the exploitation flowchart first →
          </button>
        </div>
      </div>
    </div>
  );
}
