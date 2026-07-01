import React from 'react';
import { Helmet } from 'react-helmet-async';

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
                    Built by a master's student who got tired of staring at
                    binaries with no idea where to start
                </p>
            </header>

            {/* SECTION 2 — The Problem */}
            <section className="about-section">
                <h2>The Problem</h2>
                <p>
                    Binary exploitation has the highest barrier to entry
                    of any CTF category. Professional tools cost hundreds of dollars or
                    assume you already know assembly. No free tool explains what the
                    analysis MEANS or what to do next. Beginners download their first
                    binary and stare at it with no idea where to start.
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
                            Classifies your binary into one of six exploitation archetypes with a confidence level and explanation.
                        </p>
                    </div>

                    <div className="about-card">
                        <div className="about-card-header">
                            <span className="about-card-icon">🤖</span>
                            <h3 className="about-card-title">Parallel AI Inference</h3>
                        </div>
                        <p className="about-card-desc">
                            Calls Groq and Nemotron simultaneously, merges the best of both responses.
                        </p>
                    </div>

                    <div className="about-card">
                        <div className="about-card-header">
                            <span className="about-card-icon">🌐</span>
                            <h3 className="about-card-title">RAG-Powered Hints</h3>
                        </div>
                        <p className="about-card-desc">
                            Finds similar past CTF challenges from a knowledge base of real writeups.
                        </p>
                    </div>

                    <div className="about-card">
                        <div className="about-card-header">
                            <span className="about-card-icon">⚡</span>
                            <h3 className="about-card-title">Instant Results</h3>
                        </div>
                        <p className="about-card-desc">
                            No installation, no account, results in seconds.
                        </p>
                    </div>

                    <div className="about-card">
                        <div className="about-card-header">
                            <span className="about-card-icon">📝</span>
                            <h3 className="about-card-title">Source Code Analysis</h3>
                        </div>
                        <p className="about-card-desc">
                            Full feature parity between binary and source code analysis flows.
                        </p>
                    </div>

                    <div className="about-card">
                        <div className="about-card-header">
                            <span className="about-card-icon">🔒</span>
                            <h3 className="about-card-title">Security First</h3>
                        </div>
                        <p className="about-card-desc">
                            Static analysis only, files deleted immediately, nothing stored.
                        </p>
                    </div>
                </div>
            </section>

            {/* SECTION 4 — The Builder */}
            <section className="about-section">
                <h2>Who Built This</h2>
                <p>
                    BinExplain was built by Vaibhavi Sanjay Kathepuri, a master's
                    student at Pennsylvania State University studying cybersecurity and AI.
                    After spending 40+ hours struggling to understand her first binary
                    exploitation challenges, she decided to build the tool she wished had
                    existed.
                </p>
            </section>

            {/* SECTION 6 — Contact CTA */}
            <section className="about-cta-section">
                <div className="about-cta-container">
                    <a href="/contact" className="about-btn about-btn--primary">
                        Get in Touch
                    </a>
                    <a href="https://github.com/Vaibhavi28/binexplain" target="_blank" rel="noopener noreferrer" className="about-btn about-btn--secondary">
                        View on GitHub
                    </a>
                </div>
            </section>
        </div>
    );
}
