import React from 'react';
import { Helmet } from 'react-helmet-async';
import { Link } from 'react-router-dom';

export default function About({ onNavigate }) {
    const handleBackClick = (e) => {
        e.preventDefault();
        if (onNavigate) {
            onNavigate('/');
        } else {
            window.location.hash = '#/';
        }
    };

    return (
        <div className="about-container">
            <Helmet>
                <title>About — BinExplain</title>
                <meta name="description" content="BinExplain was built by a master's student who got tired of staring at binaries with no idea where to start. Learn the story behind the tool." />
                <link rel="canonical" href="https://binexplain.com/about" />
                <script type="application/ld+json">{`
{
  "@context": "https://schema.org",
  "@type": "BreadcrumbList",
  "itemListElement": [
    {"@type": "ListItem", "position": 1, "name": "Home", "item": "https://binexplain.com"},
    {"@type": "ListItem", "position": 2, "name": "About", "item": "https://binexplain.com/about"}
  ]
}
                `}</script>
            </Helmet>
            {/* Back to main tool */}
            <a href="#/" onClick={handleBackClick} className="about-back-link">
                &larr; Back to Analyzer
            </a>

            {/* SECTION 1 — Hero */}
            <header className="about-hero">
                <h1 className="hero-headline">About BinExplain</h1>
                <p className="hero-subheading">
                    <span>Built by a master's student who got tired of staring at binaries with no idea where to start</span>
                </p>
            </header>

            {/* SECTION 2 — The Problem */}
            <section className="about-section">
                <h2>The Problem</h2>
                <p>
                    <span>Binary exploitation has the highest barrier to entry of any CTF category. Professional tools cost hundreds of dollars or assume you already know assembly. No free tool explains what the analysis MEANS or what to do next. Beginners download their first binary and stare at it with no idea where to start.</span>
                </p>
            </section>

            {/* SECTION 3 — The Tool */}
            <section className="about-section">
                <h2>What BinExplain Does</h2>
                <div className="about-grid">
                    <div className="about-card">
                        <div className="about-card-header">
                            <span className="about-card-icon">🎯</span>
                            <h3 className="about-card-title">CTF Category Detection</h3>
                        </div>
                        <p className="about-card-desc">
                            <span>Classifies your binary into one of six exploitation archetypes with a confidence level, explanation, and difficulty prediction</span>
                        </p>
                    </div>

                    <div className="about-card">
                        <div className="about-card-header">
                            <span className="about-card-icon">🤖</span>
                            <h3 className="about-card-title">Parallel AI Inference</h3>
                        </div>
                        <p className="about-card-desc">
                            <span>Calls Groq and Nemotron 3 Ultra simultaneously. A quality gate filters generic responses. Both answers merge into one expert-level hint</span>
                        </p>
                    </div>

                    <div className="about-card">
                        <div className="about-card-header">
                            <span className="about-card-icon">🌐</span>
                            <h3 className="about-card-title">RAG-Powered Hints</h3>
                        </div>
                        <p className="about-card-desc">
                            <span>2200+ real CTF writeups from 13 sources indexed with 24 technique tags. Hybrid vector + tag overlap retrieval finds genuinely similar past challenges</span>
                        </p>
                    </div>

                    <div className="about-card">
                        <div className="about-card-header">
                            <span className="about-card-icon">⚡</span>
                            <h3 className="about-card-title">Interactive Glossary</h3>
                        </div>
                        <p className="about-card-desc">
                            <span>Hover over any technical term — NX, PIE, ROP, tcache — for a plain English explanation with a real-world attack example</span>
                        </p>
                    </div>

                    <div className="about-card">
                        <div className="about-card-header">
                            <span className="about-card-icon">📝</span>
                            <h3 className="about-card-title">Source Code Analysis</h3>
                        </div>
                        <p className="about-card-desc">
                            <span>Full feature parity between binary file and source code analysis. Overflow offset read directly from buffer declarations — more precise than binary disassembly</span>
                        </p>
                    </div>

                    <div className="about-card">
                        <div className="about-card-header">
                            <span className="about-card-icon">🔒</span>
                            <h3 className="about-card-title">Security First</h3>
                        </div>
                        <p className="about-card-desc">
                            <span>Static analysis only. Files deleted immediately. Zero binary execution. Rate limited. Input validated. Never stored.</span>
                        </p>
                    </div>
                </div>
                <p style={{ marginTop: '24px', textAlign: 'center' }}>
                    <span>BinExplain analyzes your binary and gives you category classification, ROP gadgets, and AI hints.</span> <Link to="/docs">See the full feature documentation</Link>.
                </p>
            </section>

            {/* SECTION 4 — The Builder */}
            <section className="about-section">
                <h2>Who Built This</h2>
                <p>
                    <span>BinExplain was built by Vaibhavi Sanjay Kathepuri, a master's student at Pennsylvania State University studying cybersecurity and AI. After spending months of evenings and weekends struggling to understand her first binary exploitation challenges, she decided to build the tool she wished had existed.</span>
                </p>
                <p>
                    <span>BinExplain began as a personal frustration with existing tools and grew into a full-featured platform over months of active development. The project explores AI-assisted scaffolding for binary exploitation education.</span>
                </p>
            </section>

            {/* SECTION 6 — Contact CTA */}
            <section className="about-cta-section">
                <div className="about-cta-container" style={{ display: 'flex', flexDirection: 'column', gap: '16px', alignItems: 'center' }}>
                    <div style={{ display: 'flex', gap: '12px' }}>
                        <Link to="/" className="about-btn about-btn--primary" style={{ textDecoration: 'none' }}>
                            Try BinExplain now
                        </Link>
                        <a href="/contact" className="about-btn about-btn--secondary" onClick={(e) => { e.preventDefault(); onNavigate('#/contact'); }}>
                            Get in Touch
                        </a>
                    </div>
                    <a href="https://github.com/Vaibhavi28/binexplain" target="_blank" rel="noopener noreferrer" className="about-btn about-btn--secondary" style={{ width: 'fit-content' }}>
                        View on GitHub
                    </a>
                </div>
            </section>


        </div>
    );
}
