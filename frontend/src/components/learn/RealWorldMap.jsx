import React, { useState } from 'react';
import GlossaryText from '../GlossaryText';

const REAL_WORLD_DATA = [
  {
    technique: 'buffer_overflow',
    technique_label: 'Buffer Overflow',
    color: '#1c2d4a',
    border: '#388bfd',
    cwe: 'CWE-121',
    cwe_label: 'Stack-based Buffer Overflow',
    cwe_desc: 'A stack-based buffer overflow occurs when a program writes more data to a buffer on the stack than is allocated, overwriting adjacent memory including stack frames and instruction pointers.',
    cases: [
      {
        cve: 'CVE-2021-3156',
        name: 'Baron Samedit — sudo heap overflow',
        severity: 'Critical',
        cvss: 'CVSS 7.8',
        affected: 'Virtually every Linux server in the world',
        discovered: '2021 — bug existed since 2011 (10 years undetected)',
        what_happened: `A single buffer overflow in the sudo command gave any local user complete root access on any Linux system.
The bug was in how sudo parsed escape characters in arguments.
An attacker just needed a local account — no password, no special permissions.
The command: sudoedit -s '\\' $(python3 -c 'print("A"*65536)')`,
        impact: 'Root access on millions of servers including Ubuntu, Debian, Fedora, CentOS',
        patch: 'sudo version 1.9.5p2 fixed it within days of disclosure',
        lesson: 'Buffer overflows in privileged programs (running as root) are catastrophic. One overflow = game over for the entire system.'
      },
      {
        cve: 'CVE-2000-0884',
        name: 'IIS Unicode Directory Traversal',
        severity: 'Critical',
        cvss: 'Critical',
        affected: 'All Windows IIS 4.0 and 5.0 web servers',
        discovered: '2000',
        what_happened: `A buffer overflow in Microsoft IIS allowed attackers to execute arbitrary commands on web servers by sending a specially crafted URL.
This was exploited by the Code Red worm in 2001 which infected 359,000 machines in 14 hours — at peak spreading to 2,000 new hosts per minute.`,
        impact: '$2.6 billion in damages. Brought down significant portions of internet infrastructure.',
        lesson: 'Buffer overflows in network-facing services are critical — no local access needed, exploitable from anywhere on the internet.'
      }
    ]
  },
  {
    technique: 'format_string',
    technique_label: 'Format String',
    color: '#2d1a4a',
    border: '#bc8cff',
    cwe: 'CWE-134',
    cwe_label: 'Use of Externally-Controlled Format String',
    cwe_desc: 'An externally-controlled format string vulnerability occurs when user input is passed directly to the format argument of printing functions, letting attackers read or overwrite memory locations.',
    cases: [
      {
        cve: 'CVE-2000-0867',
        name: 'wu-ftpd format string vulnerability',
        severity: 'Critical',
        cvss: 'Critical',
        affected: 'Millions of FTP servers worldwide',
        discovered: '2000 — one of the first documented format string attacks',
        what_happened: `The wu-ftpd FTP server passed user-controlled input directly to syslog() as a format string argument.
Attackers sent %n format specifiers as their FTP username, writing arbitrary values to memory and achieving remote root access without any authentication.
The vulnerable code was simply: syslog(LOG_NOTICE, username);
The fix was: syslog(LOG_NOTICE, "%s", username);`,
        impact: 'Remote root access on any server running wu-ftpd. Affected universities, ISPs, and corporate servers globally.',
        lesson: 'One missing "%s" can compromise an entire server. Format string bugs are trivial to introduce and devastating to exploit.'
      },
      {
        cve: 'CVE-2012-0809',
        name: 'sudo format string vulnerability',
        severity: 'High',
        cvss: 'High',
        affected: 'Linux systems using sudo with specific configurations',
        discovered: '2012',
        what_happened: `Another sudo vulnerability, this time a format string bug.
The -e flag in sudo passed user input as a format string to a print function.
Allowed local privilege escalation to root.`,
        impact: 'Local privilege escalation on affected Linux systems.',
        lesson: 'Format string bugs keep appearing in privileged software because developers forget that user input must never be a format argument.'
      }
    ]
  },
  {
    technique: 'heap_exploitation',
    technique_label: 'Heap Exploitation',
    color: '#1a3a1a',
    border: '#3fb950',
    cwe: 'CWE-122',
    cwe_label: 'Heap-based Buffer Overflow',
    cwe_desc: 'A heap-based overflow or memory corruption occurs when a buffer allocated in dynamic memory is written beyond its size limits, corrupting allocator bookkeeping metadata.',
    cases: [
      {
        cve: 'CVE-2014-1776',
        name: 'Internet Explorer Use-After-Free (Operation Clandestine Fox)',
        severity: 'Critical',
        cvss: 'CVSS 9.3',
        affected: 'Internet Explorer 6 through 11 on Windows XP/7/8',
        discovered: '2014',
        what_happened: `A use-after-free vulnerability in Internet Explorer allowed attackers to execute arbitrary code by visiting a malicious webpage.
The VML component freed a CMarkup object but continued to reference it.
This was exploited in Operation Clandestine Fox targeting US defense contractors.
The exploit corrupted heap metadata to redirect execution to attacker shellcode.`,
        impact: 'Zero-day actively exploited by nation-state actors against defense industry. Microsoft released an emergency patch.',
        lesson: 'Use-after-free bugs are common in complex C++ codebases with manual memory management. Browsers are particularly vulnerable due to their complexity.'
      },
      {
        cve: 'CVE-2019-11932',
        name: 'WhatsApp double-free remote code execution',
        severity: 'Critical',
        cvss: 'CVSS 8.8',
        affected: '1.5 billion WhatsApp users on Android',
        discovered: '2019',
        what_happened: `A double-free vulnerability in the GIF image parsing library used by WhatsApp allowed attackers to achieve remote code execution by sending a malicious GIF file.
The parsing code freed the same pointer twice, corrupting heap metadata in a way that let attackers control what memory free() and malloc() operate on next.`,
        impact: 'Full device compromise possible by simply sending a GIF to a WhatsApp user. Spyware including NSO Group Pegasus used similar techniques.',
        lesson: 'Double-free bugs in media parsers are especially dangerous because media files come from untrusted sources constantly.'
      }
    ]
  },
  {
    technique: 'ret2libc',
    technique_label: 'Return-to-libc',
    color: '#3a2a1a',
    border: '#e3b341',
    cwe: 'CWE-676',
    cwe_label: 'Use of Potentially Dangerous Function',
    cwe_desc: 'ret2libc is a consequence of dangerous functions like system() being available in linked libraries combined with a memory corruption bug. CWE-676 captures the root cause: using functions that create exploitable conditions when memory safety is violated.',
    cwe_explanation: 'ret2libc is a consequence of dangerous functions like system() being available in linked libraries combined with a memory corruption bug. CWE-676 captures the root cause: using functions that create exploitable conditions when memory safety is violated.',
    cases: [
      {
        cve: 'CVE-2010-4221',
        name: 'ProFTPD ret2libc exploitation',
        severity: 'Critical',
        cvss: 'Critical',
        affected: 'ProFTPD FTP server — used on hundreds of thousands of servers',
        discovered: '2010',
        what_happened: `A stack overflow in ProFTPD was exploited using ret2libc technique to bypass NX protections.
Instead of injecting shellcode, attackers chained calls to existing libc functions (system() and execve()) to achieve command execution.
This was one of the early real-world demonstrations that NX alone is insufficient against ret2libc attacks.`,
        impact: 'Remote code execution on ProFTPD servers. Added to Metasploit framework demonstrating the technique to the broader security community.',
        lesson: 'NX/DEP was supposed to stop code injection attacks. ret2libc showed that reusing existing code bypasses it entirely — leading to the development of ASLR.'
      },
      {
        cve: 'CVE-2015-7547',
        name: 'glibc getaddrinfo() remote ret2libc',
        severity: 'Critical (CVSS 8.1)',
        cvss: 'Critical (CVSS 8.1)',
        affected: 'All Linux systems using glibc — virtually every Linux device',
        discovered: '2016',
        what_happened: `A stack overflow in the glibc DNS resolver was exploited
using ret2libc technique. When a Linux system made any DNS lookup,
an attacker who controlled DNS responses could overflow a stack buffer
and redirect execution to system() in libc.
This affected sudo, ssh, curl, wget, and any program that resolved hostnames —
which is almost every networked application. Google and Red Hat
coordinated disclosure after finding the bug internally.`,
        impact: 'Every major Linux distribution was affected. Any program making a DNS request was potentially exploitable from the network.',
        patch: 'glibc 2.23 fixed it. All major distributions released emergency patches.',
        lesson: 'ret2libc exploits do not require local access when the overflow is in a network-facing library. DNS lookups happen constantly — this made the attack surface enormous.'
      }
    ]
  },
  {
    technique: 'rop_chain',
    technique_label: 'ROP Chain',
    color: '#1a1a3a',
    border: '#79c0ff',
    cwe: 'CWE-693',
    cwe_label: 'Protection Mechanism Failure',
    cwe_desc: 'Return-Oriented Programming (ROP) chains construct arbitrary operations by chaining together existing tiny instruction sequences ending in returns ("gadgets") inside compiled code.',
    cases: [
      {
        cve: 'CVE-2015-1538',
        name: 'Stagefright — Android ROP exploitation',
        severity: 'Critical',
        cvss: 'CVSS 10.0',
        affected: '950 million Android devices',
        discovered: '2015',
        what_happened: `Stagefright was a heap corruption vulnerability in Android's
media processing library. The exploit chain worked in two stages:
Stage 1 — Heap corruption: A malformed MP4 file triggered an integer
overflow during parsing, leading to a heap buffer overflow.
Stage 2 — ROP to bypass NX: Because NX was enabled, the exploit used
Return-Oriented Programming to chain existing code gadgets from loaded
libraries, achieving code execution without injecting shellcode.
The combination of heap corruption + ROP chain is now a standard
technique for bypassing modern protections. The victim needed only to
receive a malicious MMS — some apps processed it automatically before
the user saw it.`,
        impact: 'Every Android phone in the world was potentially vulnerable. Called "the worst Android vulnerabilities discovered to date" at the time.',
        lesson: `Modern exploitation often requires chaining multiple techniques.
Heap corruption gets you control of execution flow. ROP bypasses NX.
Neither alone is sufficient on a modern device — but combined they
defeat both protections. This is why defense requires layered mitigations.`
      },
      {
        cve: 'CVE-2017-5638',
        name: 'Apache Struts — Equifax breach',
        severity: 'Critical',
        cvss: 'CVSS 10.0',
        affected: '143 million Americans (Equifax breach)',
        discovered: '2017',
        what_happened: `A remote code execution vulnerability in Apache Struts allowed attackers to execute arbitrary commands through crafted Content-Type headers.
The exploitation chain used ROP-like technique of chaining OGNL expression evaluations to bypass security sandboxes and achieve OS command execution.
Equifax failed to patch this known vulnerability for months — the breach lasted 78 days.`,
        impact: 'Social Security numbers, birth dates, addresses, and credit card numbers of 143 million Americans stolen. $700 million settlement.',
        lesson: 'Known vulnerabilities with published exploits are the most dangerous — not because they are complex but because organizations fail to patch them.'
      }
    ]
  },
  {
    technique: 'shellcode',
    technique_label: 'Shellcode Injection',
    color: '#3a1a1a',
    border: '#f85149',
    cwe: 'CWE-94',
    cwe_label: 'Improper Control of Generation of Code',
    cwe_desc: 'Shellcode injection occurs when an attacker writes raw assembly execution instructions directly into memory segments and forces the instruction pointer to jump to the payload.',
    cases: [
      {
        cve: 'CVE-2003-0026',
        name: 'MS Blaster Worm — Windows RPC shellcode',
        severity: 'Critical',
        cvss: 'Critical',
        affected: 'Millions of Windows XP and 2000 machines',
        discovered: '2003',
        what_happened: `A buffer overflow in Windows DCOM RPC allowed remote shellcode injection.
The Blaster worm exploited this to inject shellcode that downloaded and executed itself on the victim machine, then scanned for new victims.
NX protection did not exist in 2003 — shellcode could execute directly on the stack.
The worm spread to millions of machines within days, causing widespread disruption including taking down hospital systems and government networks.`,
        impact: 'Estimated $320 million in damages. Triggered Microsoft to completely overhaul their security development process (creating SDL).',
        lesson: 'Shellcode injection without NX protection was devastatingly effective — one reason why NX became a mandatory protection in modern systems.'
      },
      {
        cve: 'CVE-2017-0144',
        name: 'EternalBlue — WannaCry ransomware',
        severity: 'Critical',
        cvss: 'CVSS 9.3',
        affected: '200,000 computers in 150 countries',
        discovered: '2017 (developed by NSA, leaked by Shadow Brokers)',
        what_happened: `A buffer overflow in Windows SMB protocol allowed shellcode injection and remote code execution without any user interaction.
The NSA developed EternalBlue as an offensive weapon. When leaked, the WannaCry ransomware used it to spread automatically across networks, encrypting files and demanding ransom.
It shut down the UK National Health Service, Telefonica, FedEx, and others within hours of release.`,
        impact: '$4-8 billion in damages globally. NHS cancelled 19,000 appointments. Lives were at risk as hospital systems went offline.',
        lesson: 'Government-developed offensive exploits do not stay secret forever. When they leak, the damage is catastrophic. This is why patching is urgent.'
      }
    ]
  }
];

export default function RealWorldMap() {
  const [selectedTech, setSelectedTech] = useState(null);
  const [expandedCve, setExpandedCve] = useState(null);

  const getSeverityStyle = (severity) => {
    const s = severity ? severity.toLowerCase() : '';
    if (s.includes('critical')) {
      return { bg: '#3c1e1e', border: '#f85149', text: '#ff7b72' };
    }
    if (s.includes('high')) {
      return { bg: '#382a17', border: '#d29922', text: '#f0e042' };
    }
    return { bg: '#2b2214', border: '#c9d1d9', text: '#c9d1d9' };
  };

  const handleCveToggle = (cve) => {
    setExpandedCve(expandedCve === cve ? null : cve);
  };

  const renderWhatHappened = (text) => {
    const lines = text.split('\n');
    return lines.map((line, idx) => {
      const trimmed = line.trim();
      const isCode = trimmed.startsWith('$') || 
                     trimmed.startsWith('sudoedit') || 
                     trimmed.startsWith('syslog') || 
                     trimmed.includes('syslog(') || 
                     trimmed.startsWith('python3');
      if (isCode) {
        return (
          <pre key={idx} style={{
            background: '#0d1117', border: '1px solid #21262d',
            borderRadius: '6px', padding: '10px 14px',
            fontFamily: 'Courier New, monospace', fontSize: '12px',
            color: '#ff7b72', overflowX: 'auto', margin: '10px 0'
          }}>
            {line}
          </pre>
        );
      }
      return (
        <p key={idx} style={{ margin: '6px 0', lineHeight: '1.5', color: '#c9d1d9', fontSize: '14px' }}>
          <GlossaryText text={line} />
        </p>
      );
    });
  };

  if (selectedTech) {
    const data = REAL_WORLD_DATA.find(d => d.technique === selectedTech);
    return (
      <div style={{ maxWidth: '800px', margin: '0 auto' }}>
        {/* Back Button */}
        <button
          onClick={() => { setSelectedTech(null); setExpandedCve(null); }}
          style={{
            padding: '8px 16px', borderRadius: '6px', background: '#21262d',
            border: '1px solid #30363d', color: '#c9d1d9', fontSize: '13px',
            cursor: 'pointer', transition: 'all 0.15s', marginBottom: '24px'
          }}
        >
          ← Back to techniques
        </button>

        {/* Header */}
        <div style={{
          background: '#161b22', border: `1px solid ${data.border}`,
          borderRadius: '12px', padding: '24px', marginBottom: '24px'
        }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '8px', marginBottom: '12px' }}>
            <h3 style={{ margin: 0, fontSize: '22px', fontWeight: 700, color: '#f0f6fc' }}>
              {data.technique_label}
            </h3>
            <span 
              title="Common Weakness Enumeration — a standardized catalog of software weakness types maintained by MITRE. Each CWE describes a category of vulnerability, not a specific bug."
              style={{
                fontSize: '11px', fontWeight: 700, padding: '3px 8px', borderRadius: '4px',
                background: '#21262d', color: '#58a6ff', border: '1px solid #388bfd',
                cursor: 'help'
              }}
            >
              {data.cwe}
            </span>
          </div>
          <h4 style={{ margin: '0 0 4px', fontSize: '14px', fontWeight: 600, color: '#8b949e' }}>
            {data.cwe_label}
          </h4>
          <div 
            title="Common Weakness Enumeration — a standardized catalog of software weakness types maintained by MITRE. Each CWE describes a category of vulnerability, not a specific bug."
            style={{ fontSize: '11px', color: '#8b949e', cursor: 'help', marginBottom: '12px' }}
          >
            CWE: {data.cwe} — {data.cwe_label}
          </div>
          <p style={{ color: '#c9d1d9', fontSize: '14px', lineHeight: '1.6', margin: 0 }}>
            <GlossaryText text={data.cwe_desc} />
          </p>
        </div>

        {/* Case List */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          {data.cases.map((c) => {
            const isExpanded = expandedCve === c.cve;
            const sevStyle = getSeverityStyle(c.severity);
            return (
              <div
                key={c.cve}
                style={{
                  background: '#161b22', border: '1px solid #30363d',
                  borderRadius: '8px', overflow: 'hidden'
                }}
              >
                {/* Collapsed Accordion Header */}
                <div
                  onClick={() => handleCveToggle(c.cve)}
                  style={{
                    padding: '16px 20px', display: 'flex', justifyContent: 'space-between',
                    alignItems: 'center', cursor: 'pointer', userSelect: 'none', flexWrap: 'wrap', gap: '12px'
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: '12px', flexWrap: 'wrap' }}>
                    <span style={{ fontFamily: 'monospace', fontWeight: 700, color: '#58a6ff', fontSize: '14px' }}>
                      {c.cve}
                    </span>
                    <span style={{ fontWeight: 600, color: '#f0f6fc', fontSize: '14px' }}>
                      {c.name}
                    </span>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                    <span style={{
                      fontSize: '10px', fontWeight: 700, padding: '2px 6px', borderRadius: '4px',
                      background: sevStyle.bg, color: sevStyle.text, border: `1px solid ${sevStyle.border}`,
                      textTransform: 'uppercase'
                    }}>
                      {c.cvss}
                    </span>
                    <span style={{ color: '#8b949e', fontSize: '14px' }}>
                      {isExpanded ? '▲' : '▼'}
                    </span>
                  </div>
                </div>

                {/* Expanded Accordion Body */}
                {isExpanded && (
                  <div style={{
                    padding: '20px', background: '#0d1117', borderTop: '1px solid #30363d',
                    display: 'flex', flexDirection: 'column', gap: '16px'
                  }}>
                    {/* Meta Info Grid */}
                    <div style={{
                      display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
                      gap: '12px', paddingBottom: '16px', borderBottom: '1px solid #21262d'
                    }}>
                      <div>
                        <div style={{ fontSize: '10px', color: '#8b949e', textTransform: 'uppercase', fontWeight: 700, marginBottom: '2px' }}>Discovered</div>
                        <div style={{ color: '#c9d1d9', fontSize: '13px' }}>{c.discovered}</div>
                      </div>
                      <div>
                        <div style={{ fontSize: '10px', color: '#8b949e', textTransform: 'uppercase', fontWeight: 700, marginBottom: '2px' }}>Target / Affected</div>
                        <div style={{ color: '#c9d1d9', fontSize: '13px' }}>{c.affected}</div>
                      </div>
                    </div>

                    {/* What Happened */}
                    <div>
                      <div style={{ fontSize: '11px', color: '#58a6ff', textTransform: 'uppercase', fontWeight: 700, marginBottom: '8px' }}>What Happened</div>
                      {renderWhatHappened(c.what_happened)}
                    </div>

                    {/* Impact */}
                    <div>
                      <div style={{ fontSize: '11px', color: '#da3637', textTransform: 'uppercase', fontWeight: 700, marginBottom: '6px' }}>Impact</div>
                      <p style={{ color: '#c9d1d9', fontSize: '14px', lineHeight: '1.5', margin: 0 }}>{c.impact}</p>
                    </div>

                    {/* Patch (if exists) */}
                    {c.patch && (
                      <div>
                        <div style={{ fontSize: '11px', color: '#3fb950', textTransform: 'uppercase', fontWeight: 700, marginBottom: '6px' }}>Resolution / Patch</div>
                        <p style={{ color: '#c9d1d9', fontSize: '14px', lineHeight: '1.5', margin: 0 }}>{c.patch}</p>
                      </div>
                    )}

                    {/* Lesson */}
                    <div style={{
                      background: '#1c2d4a30', borderLeft: '4px solid #388bfd',
                      padding: '12px 16px', borderRadius: '0 6px 6px 0', marginTop: '4px'
                    }}>
                      <div style={{ fontSize: '11px', color: '#79c0ff', textTransform: 'uppercase', fontWeight: 700, marginBottom: '4px' }}>Key Security Lesson</div>
                      <p style={{ color: '#c9d1d9', fontSize: '13px', lineHeight: '1.5', margin: 0 }}>
                        <GlossaryText text={c.lesson} />
                      </p>
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>
    );
  }

  // VIEW 1: Grid of 6 techniques
  return (
    <div style={{ maxWidth: '960px', margin: '0 auto' }}>
      <h2 style={{ color: 'var(--text-primary)', fontSize: '20px',
        fontWeight: 600, marginBottom: '8px', textAlign: 'center' }}>
        Real-World Exploits & CVEs
      </h2>
      <p style={{ color: 'var(--text-secondary)', fontSize: '13px',
        textAlign: 'center', marginBottom: '32px' }}>
        Learn how binary exploitation plays out in reality. Select a technique to explore real CVE cases, their impact, code-level details, and mitigation lessons.
      </p>

      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))',
        gap: '20px'
      }}>
        {REAL_WORLD_DATA.map((d) => (
          <div
            key={d.technique}
            style={{
              background: '#161b22',
              border: `1px solid ${d.border}`,
              borderRadius: '10px',
              padding: '20px',
              display: 'flex',
              flexDirection: 'column',
              justifyContent: 'space-between',
              minHeight: '180px',
              transition: 'transform 0.15s, border-color 0.15s',
            }}
            onMouseEnter={(e) => {
              e.currentTarget.style.transform = 'translateY(-2px)';
              e.currentTarget.style.boxShadow = `0 4px 12px ${d.border}20`;
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.transform = 'translateY(0)';
              e.currentTarget.style.boxShadow = 'none';
            }}
          >
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                <h3 style={{ margin: 0, fontSize: '16px', fontWeight: 700, color: '#f0f6fc' }}>
                  {d.technique_label}
                </h3>
                <span 
                  title="Common Weakness Enumeration — a standardized catalog of software weakness types maintained by MITRE. Each CWE describes a category of vulnerability, not a specific bug."
                  style={{
                    fontSize: '9px', fontWeight: 700, padding: '1px 5px', borderRadius: '4px',
                    background: '#21262d', color: '#8b949e', border: '1px solid #30363d',
                    cursor: 'help'
                  }}
                >
                  {d.cwe}
                </span>
              </div>
              <h4 style={{ margin: '0 0 4px', fontSize: '11px', color: '#8b949e', fontWeight: 600 }}>
                {d.cwe_label}
              </h4>
              <div 
                title="Common Weakness Enumeration — a standardized catalog of software weakness types maintained by MITRE. Each CWE describes a category of vulnerability, not a specific bug."
                style={{ fontSize: '10px', color: '#8b949e', cursor: 'help', marginBottom: '12px' }}
              >
                CWE: {d.cwe} — {d.cwe_label}
              </div>
              <div style={{ fontSize: '12px', color: '#c9d1d9', marginBottom: '12px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                <span>📁</span>
                <span>{d.cases.length} real-world case{d.cases.length > 1 ? 's' : ''}</span>
              </div>
              <div style={{ fontSize: '11px', color: '#8b949e', fontStyle: 'italic', marginBottom: '16px', textOverflow: 'ellipsis', overflow: 'hidden', whiteSpace: 'nowrap' }}>
                Preview: {d.cases[0].name}
              </div>
            </div>

            <button
              onClick={() => setSelectedTech(d.technique)}
              style={{
                width: '100%', padding: '10px 14px', borderRadius: '6px',
                background: d.color, border: `1px solid ${d.border}`,
                color: '#fff', fontSize: '13px', fontWeight: 600,
                cursor: 'pointer', transition: 'all 0.15s', textAlign: 'center'
              }}
            >
              Explore →
            </button>
          </div>
        ))}
      </div>
    </div>
  );
}
