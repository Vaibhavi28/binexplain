import React from 'react';
import { Helmet } from 'react-helmet-async';
import { Link } from 'react-router-dom';

const STATS = [
  { value: '2,200+', label: 'CTF writeups indexed' },
  { value: '13',     label: 'writeup sources' },
  { value: '6',      label: 'exploit categories' },
  { value: '235',    label: 'backend tests passing' },
];

const FEATURES = [
  {
    icon: '[01]',
    title: 'CTF Category Detection',
    desc: 'Classifies your binary into one of six exploitation archetypes — ret2win, format string, heap, ret2libc, ROP chain, shellcode — with a confidence level, explanation, and difficulty rating.',
    accent: '#238636',
    dim: 'rgba(35,134,54,0.10)',
    border: 'rgba(35,134,54,0.3)',
  },
  {
    icon: '[02]',
    title: 'Parallel AI Inference',
    desc: 'Calls Groq and Nemotron 3 Ultra simultaneously. A quality gate filters generic responses. Both answers merge into one expert-level hint that references your actual binary data.',
    accent: '#388bfd',
    dim: 'rgba(56,139,253,0.10)',
    border: 'rgba(56,139,253,0.3)',
  },
  {
    icon: '[03]',
    title: 'RAG-Powered Hints',
    desc: '2,200+ real CTF writeups from 13 sources indexed with 24 technique tags. Hybrid vector + tag overlap retrieval surfaces genuinely similar past challenges — not just keyword matches.',
    accent: '#8957e5',
    dim: 'rgba(137,87,229,0.10)',
    border: 'rgba(137,87,229,0.3)',
  },
  {
    icon: '[04]',
    title: 'Follow-up Chat',
    desc: 'An AI mentor that remembers your binary context, tracks commands you have already tried, and answers follow-up questions with binary-specific advice — not generic answers.',
    accent: '#d2a8ff',
    dim: 'rgba(210,168,255,0.10)',
    border: 'rgba(210,168,255,0.3)',
  },
  {
    icon: '[05]',
    title: 'Source Code Analysis',
    desc: 'Full feature parity for C/C++/Python/Rust/Go source files. Buffer overflow offsets read directly from declarations — more precise than binary disassembly alone.',
    accent: '#ff8b4d',
    dim: 'rgba(255,139,77,0.10)',
    border: 'rgba(255,139,77,0.3)',
  },
  {
    icon: '[06]',
    title: 'Security First',
    desc: 'Static analysis only. Files deleted immediately after analysis. Zero binary execution. Rate limited per IP. All inputs validated. Nothing is stored or logged.',
    accent: '#f0e042',
    dim: 'rgba(240,224,66,0.10)',
    border: 'rgba(240,224,66,0.3)',
  },
];

const TIMELINE = [
  { phase: 'The Problem',    text: 'Struggled through first binary exploitation CTF challenges. No free tool explained what analysis results actually meant or what to do next.' },
  { phase: 'First Build',   text: 'Shipped the core static analyser — checksec, strings, ROP gadget extraction — in evenings and weekends. Validated it on picoCTF challenges.' },
  { phase: 'AI Layer',      text: 'Added parallel AI inference (Groq + Nemotron) with a quality gate. Built the RAG pipeline over 2,200+ real CTF writeups from 13 sources.' },
  { phase: 'Learn Page',    text: 'Built the interactive Learn hub: zero-knowledge ELF guide, exploitation flowchart classifier, technique deep dives, and demo binary analysis.' },
  { phase: 'Today',         text: 'Live at binexplain.com — free, no account required. 235 backend tests. Source code analysis. Follow-up chat with binary context memory.' },
];

export default function About({ onNavigate }) {
  const handleBackClick = (e) => {
    e.preventDefault();
    if (onNavigate) onNavigate('/');
    else window.location.hash = '#/';
  };

  return (
    <div style={{
      maxWidth: '900px', margin: '0 auto',
      padding: '40px 24px 80px',
      fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif'
    }}>
      <Helmet>
        <title>About — BinExplain</title>
        <meta name="description" content="BinExplain was built by a master's student who got tired of staring at binaries with no idea where to start. Learn the story behind the tool." />
        <link rel="canonical" href="https://binexplain.com/about" />
      </Helmet>

      <style>{`
        @keyframes fadeUp { from{opacity:0;transform:translateY(20px)} to{opacity:1;transform:none} }
        @keyframes glow { 0%,100%{opacity:0.6} 50%{opacity:1} }
        .about-feat-card:hover { transform: translateY(-3px) !important; }
      `}</style>

      {/* Back */}
      <a href="#/" onClick={handleBackClick} style={{
        display: 'inline-flex', alignItems: 'center', gap: '6px',
        color: '#8b949e', fontSize: '13px', textDecoration: 'none',
        marginBottom: '40px', transition: 'color 0.15s'
      }}
        onMouseEnter={e => e.currentTarget.style.color = '#c9d1d9'}
        onMouseLeave={e => e.currentTarget.style.color = '#8b949e'}
      >
        ← Back to Analyzer
      </a>

      {/* ── Hero ──────────────────────────────────────────────────────── */}
      <div style={{ textAlign: 'center', marginBottom: '64px', animation: 'fadeUp 0.5s ease-out' }}>
        {/* Glow orb */}
        <div style={{
          width: '160px', height: '160px',
          background: 'radial-gradient(circle, rgba(56,139,253,0.25) 0%, transparent 70%)',
          borderRadius: '50%', margin: '0 auto 24px',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          animation: 'glow 3s ease-in-out infinite'
        }}>
          <div style={{
            width: '80px', height: '80px', borderRadius: '20px',
            background: 'linear-gradient(135deg, #161b22 0%, #1c2d4a 100%)',
            border: '1px solid rgba(56,139,253,0.4)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            fontSize: '20px', fontWeight: 800, color: '#58a6ff'
          }}>
            [BE]
          </div>
        </div>

        <h1 style={{
          fontSize: '40px', fontWeight: 800, color: '#f0f6fc',
          margin: '0 0 16px', letterSpacing: '-0.5px'
        }}>
          About BinExplain
        </h1>
        <p style={{
          fontSize: '18px', color: '#8b949e', maxWidth: '580px',
          margin: '0 auto', lineHeight: '1.65'
        }}>
          Built by a master's student who got tired of staring at binaries with no idea where to start.
        </p>
      </div>

      {/* ── Stats ─────────────────────────────────────────────────────── */}
      <div style={{
        display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)',
        gap: '1px', background: '#21262d',
        borderRadius: '12px', overflow: 'hidden',
        marginBottom: '64px', border: '1px solid #21262d'
      }}>
        {STATS.map((s, i) => (
          <div key={i} style={{
            background: '#0d1117', padding: '28px 16px', textAlign: 'center'
          }}>
            <div style={{
              fontSize: '32px', fontWeight: 800, color: '#388bfd',
              fontFamily: 'monospace', marginBottom: '6px'
            }}>{s.value}</div>
            <div style={{ fontSize: '12px', color: '#6e7681', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
              {s.label}
            </div>
          </div>
        ))}
      </div>

      {/* ── The Problem ───────────────────────────────────────────────── */}
      <div style={{ marginBottom: '64px' }}>
        <div style={{
          display: 'flex', gap: '20px', alignItems: 'flex-start',
          background: '#161b22', border: '1px solid #30363d',
          borderRadius: '12px', padding: '28px'
        }}>
          <div style={{
            fontSize: '32px', flexShrink: 0,
            width: '56px', height: '56px',
            background: 'rgba(218,54,55,0.1)', border: '1px solid rgba(218,54,55,0.3)',
            borderRadius: '12px', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#f85149', fontWeight: 800
          }}>!</div>
          <div>
            <h2 style={{ color: '#f0f6fc', fontSize: '20px', fontWeight: 700, margin: '0 0 12px' }}>
              The Problem
            </h2>
            <p style={{ color: '#c9d1d9', fontSize: '15px', lineHeight: '1.75', margin: 0 }}>
              Binary exploitation has the highest barrier to entry of any CTF category. Professional tools cost hundreds of dollars or assume you already know assembly. No free tool explains what the analysis <em>means</em> or what to do next. Beginners download their first binary and stare at it — with no idea where to start.
            </p>
            <p style={{ color: '#8b949e', fontSize: '14px', lineHeight: '1.6', margin: '12px 0 0' }}>
              BinExplain was built to fix exactly that — free, no account, works in the browser, and explains everything in plain English.
            </p>
          </div>
        </div>
      </div>

      {/* ── Features grid ─────────────────────────────────────────────── */}
      <div style={{ marginBottom: '64px' }}>
        <h2 style={{ color: '#f0f6fc', fontSize: '22px', fontWeight: 700, margin: '0 0 24px', textAlign: 'center' }}>
          What BinExplain Does
        </h2>
        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fill, minmax(260px, 1fr))',
          gap: '16px'
        }}>
          {FEATURES.map((f, i) => (
            <div
              key={i}
              className="about-feat-card"
              style={{
                background: f.dim, border: `1px solid ${f.border}`,
                borderRadius: '10px', padding: '20px',
                transition: 'transform 0.2s, box-shadow 0.2s'
              }}
            >
              <div style={{
                fontSize: '24px', marginBottom: '12px',
                width: '44px', height: '44px',
                background: 'rgba(0,0,0,0.3)',
                borderRadius: '10px',
                display: 'flex', alignItems: 'center', justifyContent: 'center'
              }}>{f.icon}</div>
              <h3 style={{ color: f.accent, fontSize: '14px', fontWeight: 700, margin: '0 0 8px' }}>
                {f.title}
              </h3>
              <p style={{ color: '#8b949e', fontSize: '13px', lineHeight: '1.65', margin: 0 }}>
                {f.desc}
              </p>
            </div>
          ))}
        </div>
      </div>

      {/* ── Builder ───────────────────────────────────────────────────── */}
      <div style={{ marginBottom: '64px' }}>
        <h2 style={{ color: '#f0f6fc', fontSize: '22px', fontWeight: 700, margin: '0 0 24px', textAlign: 'center' }}>
          Who Built This
        </h2>
        <div style={{
          background: 'linear-gradient(135deg, #161b22 0%, #1a1f2e 100%)',
          border: '1px solid #30363d', borderRadius: '12px',
          padding: '32px', display: 'flex', gap: '24px', alignItems: 'flex-start',
          flexWrap: 'wrap'
        }}>
          <div style={{
            width: '72px', height: '72px', borderRadius: '50%', flexShrink: 0,
            background: 'linear-gradient(135deg, #388bfd, #8957e5)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            fontSize: '16px', fontWeight: 800, color: '#fff'
          }}>VK</div>
          <div style={{ flex: 1, minWidth: '200px' }}>
            <div style={{ fontSize: '18px', fontWeight: 700, color: '#f0f6fc', marginBottom: '4px' }}>
              Vaibhavi Sanjay Kathepuri
            </div>
            <div style={{ fontSize: '13px', color: '#58a6ff', marginBottom: '14px' }}>
              M.S. Cybersecurity Analytics and Operations — Pennsylvania State University
            </div>
            <p style={{ color: '#c9d1d9', fontSize: '14px', lineHeight: '1.7', margin: '0 0 10px' }}>
              After spending months struggling through her first binary exploitation challenges, Vaibhavi decided to build the tool she wished had existed. BinExplain started as a personal frustration with existing tools and grew into a full-featured platform over months of active development.
            </p>
            <p style={{ color: '#8b949e', fontSize: '14px', lineHeight: '1.65', margin: 0 }}>
              The project explores AI-assisted scaffolding for binary exploitation education — combining static analysis, retrieval-augmented generation over real CTF writeups, and parallel AI inference to give beginners a genuine head start.
            </p>
          </div>
        </div>
      </div>

      {/* ── Timeline ──────────────────────────────────────────────────── */}
      <div style={{ marginBottom: '64px' }}>
        <h2 style={{ color: '#f0f6fc', fontSize: '22px', fontWeight: 700, margin: '0 0 28px', textAlign: 'center' }}>
          How It Was Built
        </h2>
        <div style={{ position: 'relative', paddingLeft: '32px' }}>
          {/* Vertical line */}
          <div style={{
            position: 'absolute', left: '7px', top: '10px',
            bottom: '10px', width: '2px',
            background: 'linear-gradient(to bottom, #388bfd, #8957e5, #238636)',
            borderRadius: '1px'
          }} />
          {TIMELINE.map((t, i) => (
            <div key={i} style={{ display: 'flex', gap: '20px', marginBottom: '28px', position: 'relative' }}>
              {/* Dot */}
              <div style={{
                width: '14px', height: '14px', borderRadius: '50%',
                background: '#388bfd', border: '2px solid #0d1117',
                flexShrink: 0, position: 'absolute', left: '-29px', top: '4px'
              }} />
              <div>
                <div style={{ fontSize: '11px', fontWeight: 800, color: '#58a6ff', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: '4px' }}>
                  {t.phase}
                </div>
                <p style={{ color: '#c9d1d9', fontSize: '14px', lineHeight: '1.65', margin: 0 }}>
                  {t.text}
                </p>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* ── CTA ───────────────────────────────────────────────────────── */}
      <div style={{
        background: 'linear-gradient(135deg, rgba(56,139,253,0.10) 0%, rgba(137,87,229,0.08) 100%)',
        border: '1px solid rgba(56,139,253,0.3)',
        borderRadius: '16px', padding: '40px 32px',
        textAlign: 'center'
      }}>
        <h2 style={{ color: '#f0f6fc', fontSize: '22px', fontWeight: 700, margin: '0 0 10px' }}>
          Ready to try it?
        </h2>
        <p style={{ color: '#8b949e', fontSize: '14px', margin: '0 0 28px', lineHeight: '1.6' }}>
          Free. No account. Works in the browser. Upload any binary and get AI-powered analysis in seconds.
        </p>
        <div style={{ display: 'flex', gap: '12px', justifyContent: 'center', flexWrap: 'wrap' }}>
          <Link to="/" style={{
            padding: '12px 28px', borderRadius: '8px',
            background: '#388bfd', color: '#fff',
            fontSize: '14px', fontWeight: 700, textDecoration: 'none',
            transition: 'background 0.15s'
          }}
            onMouseEnter={e => e.currentTarget.style.background = '#2575e6'}
            onMouseLeave={e => e.currentTarget.style.background = '#388bfd'}
          >
            Try BinExplain →
          </Link>
          <a href="https://github.com/Vaibhavi28/binexplain" target="_blank" rel="noopener noreferrer"
            style={{
              padding: '12px 24px', borderRadius: '8px',
              background: 'transparent', color: '#c9d1d9',
              border: '1px solid #30363d', fontSize: '14px', fontWeight: 600,
              textDecoration: 'none', transition: 'border-color 0.15s'
            }}
            onMouseEnter={e => e.currentTarget.style.borderColor = '#8b949e'}
            onMouseLeave={e => e.currentTarget.style.borderColor = '#30363d'}
          >
            View on GitHub ↗
          </a>
          <a href="#/contact" onClick={(e) => { e.preventDefault(); onNavigate('#/contact'); }}
            style={{
              padding: '12px 24px', borderRadius: '8px',
              background: 'transparent', color: '#8b949e',
              border: '1px solid #30363d', fontSize: '14px', fontWeight: 600,
              textDecoration: 'none', transition: 'border-color 0.15s'
            }}
            onMouseEnter={e => e.currentTarget.style.borderColor = '#8b949e'}
            onMouseLeave={e => e.currentTarget.style.borderColor = '#30363d'}
          >
            Get in Touch
          </a>
        </div>
        <div style={{ marginTop: '24px', fontSize: '13px', color: '#8b949e', lineHeight: '1.6' }}>
          BinExplain is open source,{' '}
          <a
            href="https://www.apache.org/licenses/LICENSE-2.0"
            target="_blank"
            rel="noopener noreferrer"
            style={{ color: '#58a6ff', textDecoration: 'none', fontWeight: 600 }}
          >
            Licensed under Apache License 2.0
          </a>
          . The "BinExplain" name and branding are protected rights reserved for the official project (see NOTICE).
        </div>
      </div>
    </div>
  );
}
