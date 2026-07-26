import React, { useState } from 'react';
import { Helmet } from 'react-helmet-async';
import { Link } from 'react-router-dom';

const ARTICLES = [
  {
    emoji: '🔐',
    title: "I Built a Free AI Tool for CTF Binary Analysis — Here's What I Learned",
    category: 'Tool Reveal',
    tag: 'Featured',
    tagColor: '#f0e042',
    tagBg: 'rgba(240,224,66,0.12)',
    tagBorder: 'rgba(240,224,66,0.35)',
    accent: '#f0e042',
    dim: 'rgba(240,224,66,0.06)',
    border: 'rgba(240,224,66,0.2)',
    excerpt: 'After months of evenings building, I shipped the tool I wished existed when I started CTF. Here is the full story — the technical decisions, the failures, and what I would do differently.',
    readTime: '8 min read',
  },
  {
    emoji: '📖',
    title: "What Is a Binary File? A Beginner's Guide for CTF Players",
    category: 'Beginner Guide',
    tag: 'Beginner',
    tagColor: '#56d364',
    tagBg: 'rgba(86,211,100,0.12)',
    tagBorder: 'rgba(86,211,100,0.35)',
    accent: '#56d364',
    dim: 'rgba(86,211,100,0.06)',
    border: 'rgba(86,211,100,0.2)',
    excerpt: 'Every CTF binary challenge starts with a file. This guide explains what that file actually is, how to read it, and what the first five commands you should run on any binary are.',
    readTime: '6 min read',
  },
  {
    emoji: '💥',
    title: 'Buffer Overflows Explained With a Real CTF Challenge',
    category: 'Tutorial',
    tag: 'Tutorial',
    tagColor: '#79c0ff',
    tagBg: 'rgba(121,192,255,0.12)',
    tagBorder: 'rgba(121,192,255,0.35)',
    accent: '#58a6ff',
    dim: 'rgba(56,139,253,0.06)',
    border: 'rgba(56,139,253,0.2)',
    excerpt: 'A buffer overflow is one of the most common CTF vulnerability classes. We walk through a real challenge using BinExplain to identify the vulnerability and generate a working exploit.',
    readTime: '10 min read',
  },
  {
    emoji: '🔢',
    title: 'Format String Vulnerabilities: From Zero to Exploit',
    category: 'Tutorial',
    tag: 'Tutorial',
    tagColor: '#d2a8ff',
    tagBg: 'rgba(210,168,255,0.12)',
    tagBorder: 'rgba(210,168,255,0.35)',
    accent: '#d2a8ff',
    dim: 'rgba(137,87,229,0.06)',
    border: 'rgba(137,87,229,0.2)',
    excerpt: 'printf(buf) is a one-line mistake that gives an attacker arbitrary read and write. Here is exactly how to identify it, verify it with %p, and chain it into a full exploit.',
    readTime: '12 min read',
  },
  {
    emoji: '🗑️',
    title: 'Heap Exploitation Basics: Use-After-Free Explained',
    category: 'Tutorial',
    tag: 'Advanced',
    tagColor: '#ff8b4d',
    tagBg: 'rgba(255,139,77,0.12)',
    tagBorder: 'rgba(255,139,77,0.35)',
    accent: '#ff8b4d',
    dim: 'rgba(255,139,77,0.06)',
    border: 'rgba(255,139,77,0.2)',
    excerpt: 'Heap challenges are the hardest CTF binary category. This guide breaks down use-after-free from first principles — what tcache is, how fd pointers work, and how BinExplain identifies the pattern.',
    readTime: '15 min read',
  },
  {
    emoji: '🔨',
    title: 'How I Built a RAG System Over Real CTF Writeups',
    category: 'Technical Deep Dive',
    tag: 'Technical',
    tagColor: '#ffa198',
    tagBg: 'rgba(255,123,114,0.12)',
    tagBorder: 'rgba(255,123,114,0.35)',
    accent: '#ff7b72',
    dim: 'rgba(218,54,55,0.06)',
    border: 'rgba(218,54,55,0.2)',
    excerpt: 'BinExplain uses a Retrieval Augmented Generation pipeline with 2,200+ real CTF writeups, 24 technique tags for hybrid retrieval, automatic conversation summarisation, and a quality gate that filters generic AI answers.',
    readTime: '20 min read',
  },
];

const CATEGORIES = ['All', 'Beginner Guide', 'Tutorial', 'Technical Deep Dive', 'Tool Reveal'];

export default function Blog({ onNavigate }) {
  const [email, setEmail] = useState('');
  const [subscribed, setSubscribed] = useState(false);
  const [filter, setFilter] = useState('All');
  const [hoveredCard, setHoveredCard] = useState(null);

  const handleBackClick = (e) => {
    e.preventDefault();
    if (onNavigate) onNavigate('/');
    else window.location.hash = '#/';
  };

  const filtered = filter === 'All' ? ARTICLES : ARTICLES.filter(a => a.category === filter);

  return (
    <div style={{
      maxWidth: '900px', margin: '0 auto',
      padding: '40px 24px 80px',
      fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif'
    }}>
      <Helmet>
        <title>Blog — BinExplain</title>
        <meta name="description" content="Articles about binary exploitation, CTF challenges, and cybersecurity education. Written by the creator of BinExplain." />
        <link rel="canonical" href="https://binexplain.com/blog" />
      </Helmet>

      <style>{`
        @keyframes fadeUp { from{opacity:0;transform:translateY(16px)} to{opacity:1;transform:none} }
        @keyframes shimmer {
          0%   { background-position: -400px 0; }
          100% { background-position: 400px 0; }
        }
        .blog-pill:hover { opacity: 1 !important; }
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
      <div style={{ textAlign: 'center', marginBottom: '48px', animation: 'fadeUp 0.4s ease-out' }}>
        <div style={{
          display: 'inline-block', padding: '4px 14px', borderRadius: '20px',
          background: 'rgba(56,139,253,0.10)', border: '1px solid rgba(56,139,253,0.3)',
          color: '#58a6ff', fontSize: '11px', fontWeight: 700,
          textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: '20px'
        }}>
          Articles &amp; Deep Dives
        </div>
        <h1 style={{
          fontSize: '38px', fontWeight: 800, color: '#f0f6fc',
          margin: '0 0 14px', letterSpacing: '-0.5px'
        }}>
          BinExplain Blog
        </h1>
        <p style={{
          color: '#8b949e', fontSize: '16px', maxWidth: '520px',
          margin: '0 auto 32px', lineHeight: '1.65'
        }}>
          Binary exploitation tutorials, tool deep dives, and beginner guides — written from the perspective of someone who learned the hard way.
        </p>

        {/* Newsletter */}
        <div style={{
          background: '#161b22', border: '1px solid #30363d',
          borderRadius: '12px', padding: '24px',
          maxWidth: '480px', margin: '0 auto'
        }}>
          {subscribed ? (
            <div style={{
              color: '#56d364', fontSize: '14px', fontWeight: 600,
              display: 'flex', alignItems: 'center', gap: '8px', justifyContent: 'center'
            }}>
              <span style={{ fontSize: '18px' }}>✓</span>
              You're on the list — we'll email you when articles go live.
            </div>
          ) : (
            <>
              <div style={{ fontSize: '13px', color: '#8b949e', marginBottom: '12px' }}>
                Get notified when new articles are published — no spam.
              </div>
              <form onSubmit={(e) => { e.preventDefault(); if (email.trim()) { setSubscribed(true); setEmail(''); } }}
                style={{ display: 'flex', gap: '8px' }}
              >
                <input
                  type="email"
                  value={email}
                  onChange={e => setEmail(e.target.value)}
                  placeholder="your@email.com"
                  required
                  style={{
                    flex: 1, padding: '10px 14px', borderRadius: '6px',
                    background: '#0d1117', border: '1px solid #30363d',
                    color: '#f0f6fc', fontSize: '13px', outline: 'none'
                  }}
                />
                <button type="submit" style={{
                  padding: '10px 20px', borderRadius: '6px',
                  background: '#388bfd', border: 'none',
                  color: '#fff', fontSize: '13px', fontWeight: 700, cursor: 'pointer',
                  flexShrink: 0, transition: 'background 0.15s'
                }}
                  onMouseEnter={e => e.currentTarget.style.background = '#2575e6'}
                  onMouseLeave={e => e.currentTarget.style.background = '#388bfd'}
                >
                  Subscribe
                </button>
              </form>
            </>
          )}
        </div>
      </div>

      {/* ── Category filter ───────────────────────────────────────────── */}
      <div style={{
        display: 'flex', gap: '8px', flexWrap: 'wrap',
        marginBottom: '32px', justifyContent: 'center'
      }}>
        {CATEGORIES.map(cat => (
          <button
            key={cat}
            className="blog-pill"
            onClick={() => setFilter(cat)}
            style={{
              padding: '6px 16px', borderRadius: '20px', fontSize: '12px',
              fontWeight: filter === cat ? 700 : 500,
              background: filter === cat ? '#388bfd' : '#21262d',
              border: filter === cat ? '1px solid #388bfd' : '1px solid #30363d',
              color: filter === cat ? '#fff' : '#8b949e',
              cursor: 'pointer', transition: 'all 0.15s',
              opacity: filter === cat ? 1 : 0.8
            }}
          >
            {cat}
          </button>
        ))}
      </div>

      {/* ── Coming Soon banner ────────────────────────────────────────── */}
      <div style={{
        display: 'flex', alignItems: 'center', gap: '12px',
        background: 'rgba(240,224,66,0.06)', border: '1px solid rgba(240,224,66,0.25)',
        borderRadius: '8px', padding: '12px 16px', marginBottom: '28px',
        fontSize: '13px', color: '#f0e042'
      }}>
        <span style={{ fontSize: '16px' }}>️</span>
        <span>Articles are being written. Subscribe above to be the first to know when they go live.</span>
      </div>

      {/* ── Article cards ─────────────────────────────────────────────── */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', marginBottom: '56px' }}>
        {filtered.map((art, i) => (
          <div
            key={i}
            onMouseEnter={() => setHoveredCard(i)}
            onMouseLeave={() => setHoveredCard(null)}
            style={{
              background: hoveredCard === i ? art.dim : '#161b22',
              border: `1px solid ${hoveredCard === i ? art.border : '#30363d'}`,
              borderRadius: '12px', padding: '24px',
              transition: 'all 0.2s', cursor: 'default',
              display: 'flex', gap: '20px', alignItems: 'flex-start'
            }}
          >
            {/* Emoji icon */}
            <div style={{
              width: '52px', height: '52px', borderRadius: '12px', flexShrink: 0,
              background: art.dim, border: `1px solid ${art.border}`,
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              fontSize: '24px'
            }}>
              {art.emoji}
            </div>

            <div style={{ flex: 1, minWidth: 0 }}>
              {/* Meta row */}
              <div style={{ display: 'flex', gap: '8px', alignItems: 'center', marginBottom: '8px', flexWrap: 'wrap' }}>
                <span style={{
                  fontSize: '10px', fontWeight: 700, textTransform: 'uppercase',
                  letterSpacing: '0.08em', color: '#6e7681'
                }}>{art.category}</span>
                <span style={{ color: '#21262d' }}>·</span>
                <span style={{
                  padding: '2px 8px', borderRadius: '4px', fontSize: '10px', fontWeight: 700,
                  background: art.tagBg, border: `1px solid ${art.tagBorder}`, color: art.tagColor,
                  textTransform: 'uppercase'
                }}>{art.tag}</span>
                <span style={{ color: '#21262d' }}>·</span>
                <span style={{ fontSize: '11px', color: '#6e7681' }}>{art.readTime}</span>
              </div>

              <h2 style={{
                color: '#f0f6fc', fontSize: '16px', fontWeight: 700,
                margin: '0 0 8px', lineHeight: '1.4'
              }}>
                {art.title}
              </h2>
              <p style={{
                color: '#8b949e', fontSize: '13px', lineHeight: '1.65', margin: '0 0 14px'
              }}>
                {art.excerpt}
              </p>

              <span style={{
                display: 'inline-flex', alignItems: 'center', gap: '4px',
                fontSize: '12px', fontWeight: 600, color: '#6e7681'
              }}>
                Coming Soon
              </span>
            </div>
          </div>
        ))}
      </div>

      {/* ── Bottom CTA ────────────────────────────────────────────────── */}
      <div style={{
        background: 'linear-gradient(135deg, rgba(35,134,54,0.10) 0%, rgba(56,139,253,0.08) 100%)',
        border: '1px solid rgba(35,134,54,0.25)',
        borderRadius: '16px', padding: '36px 28px',
        textAlign: 'center'
      }}>
        <div style={{ fontSize: '28px', marginBottom: '12px' }}></div>
        <h3 style={{ color: '#f0f6fc', fontSize: '20px', fontWeight: 700, margin: '0 0 10px' }}>
          Ready to Exploit CTF Challenges?
        </h3>
        <p style={{ color: '#8b949e', fontSize: '14px', maxWidth: '440px', margin: '0 auto 24px', lineHeight: '1.6' }}>
          BinExplain is a free, browser-based CTF binary analyser — no account, no install, instant results.
        </p>
        <div style={{ display: 'flex', gap: '12px', justifyContent: 'center', flexWrap: 'wrap' }}>
          <Link to="/" style={{
            padding: '11px 26px', borderRadius: '8px',
            background: '#238636', border: '1px solid #2ea043',
            color: '#fff', fontSize: '14px', fontWeight: 700, textDecoration: 'none',
            transition: 'background 0.15s'
          }}
            onMouseEnter={e => e.currentTarget.style.background = '#2ea043'}
            onMouseLeave={e => e.currentTarget.style.background = '#238636'}
          >
            Try the Tool →
          </Link>
          <Link to="/docs" style={{
            padding: '11px 22px', borderRadius: '8px',
            background: 'transparent', border: '1px solid #30363d',
            color: '#58a6ff', fontSize: '14px', fontWeight: 600, textDecoration: 'none',
            transition: 'border-color 0.15s'
          }}
            onMouseEnter={e => e.currentTarget.style.borderColor = '#58a6ff'}
            onMouseLeave={e => e.currentTarget.style.borderColor = '#30363d'}
          >
            Read the Docs →
          </Link>
        </div>
      </div>
    </div>
  );
}
