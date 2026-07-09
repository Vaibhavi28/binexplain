import React, { useState } from 'react';
import { Helmet } from 'react-helmet-async';
import { Link } from 'react-router-dom';
import GlossaryText from '../components/GlossaryText';

export default function Blog({ onNavigate }) {
    const articles = [
        {
            title: "I Built a Free AI Tool for CTF Binary Analysis — Here's What I Learned",
            date: "Coming Soon",
            category: "Tool Reveal",
            excerpt: "After months of evenings building, I shipped the tool I wished existed when I started CTF. Here is the full story.",
            tag: "Featured",
            tagClass: "blog-tag--featured"
        },
        {
            title: "What Is a Binary File? A Beginner's Guide for CTF Players",
            date: "Coming Soon",
            category: "Beginner Guide",
            excerpt: "Every CTF binary challenge starts with a file. This guide explains what that file actually is, how to read it, and what the first five commands you should run are.",
            tag: "Beginner",
            tagClass: "blog-tag--beginner"
        },
        {
            title: "Buffer Overflows Explained With a Real CTF Challenge",
            date: "Coming Soon",
            category: "Tutorial",
            excerpt: "A buffer overflow is one of the most common CTF vulnerability classes. We walk through a real challenge using BinExplain to identify the vulnerability and generate a working exploit.",
            tag: "Tutorial",
            tagClass: "blog-tag--tutorial"
        },
        {
            title: "Format String Vulnerabilities: From Zero to Exploit",
            date: "Coming Soon",
            category: "Tutorial",
            excerpt: "printf(buf) is a one-line mistake that can give an attacker arbitrary read and write. Here's exactly how to identify and exploit it.",
            tag: "Tutorial",
            tagClass: "blog-tag--tutorial"
        },
        {
            title: "Heap Exploitation Basics: Use-After-Free Explained",
            date: "Coming Soon",
            category: "Tutorial",
            excerpt: "Heap challenges are the hardest CTF binary category. This guide breaks down use-after-free from first principles and shows how BinExplain identifies the pattern.",
            tag: "Tutorial",
            tagClass: "blog-tag--tutorial"
        },
        {
            title: "How I Built a RAG System Over Real CTF Writeups",
            date: "Coming Soon",
            category: "Technical Deep Dive",
            excerpt: "BinExplain uses a Retrieval Augmented Generation pipeline with 2200+ real CTF writeups from 13 sources, 24 technique tags for hybrid retrieval, and automatic conversation summarization. Here is exactly how it works.",
            tag: "Technical",
            tagClass: "blog-tag--technical"
        }
    ];

    const [email, setEmail] = useState('');
    const [isSubscribed, setIsSubscribed] = useState(false);

    const handleSubscribe = (e) => {
        e.preventDefault();
        if (email.trim()) {
            setIsSubscribed(true);
            setEmail('');
        }
    };

    const handleBackClick = (e) => {
        e.preventDefault();
        if (onNavigate) {
            onNavigate('/');
        } else {
            window.location.hash = '#/';
        }
    };

    return (
        <div className="blog-container">
            <Helmet>
                <title>Blog — BinExplain</title>
                <meta name="description" content="Articles about binary exploitation, CTF challenges, and cybersecurity education. Written by the creator of BinExplain." />
                <link rel="canonical" href="https://binexplain.com/blog" />
                <script type="application/ld+json">{`
{
  "@context": "https://schema.org",
  "@type": "BreadcrumbList",
  "itemListElement": [
    {"@type": "ListItem", "position": 1, "name": "Home", "item": "https://binexplain.com"},
    {"@type": "ListItem", "position": 2, "name": "Blog", "item": "https://binexplain.com/blog"}
  ]
}
                `}</script>
            </Helmet>
            {/* Back link */}
            <a href="#/" onClick={handleBackClick} className="blog-back-link">
                &larr; Back to Analyzer
            </a>

            <h1 className="blog-title">BinExplain Blog</h1>

            {/* Newsletter Subscription */}
            <div className="blog-subscribe">
                <p className="blog-subscribe-note">
                    Articles are published here first. Subscribe to get notified:
                </p>
                {isSubscribed ? (
                    <div className="blog-subscribe-success">
                        Thank you — you will be notified when new articles are published.
                    </div>
                ) : (
                    <form onSubmit={handleSubscribe} className="blog-subscribe-form">
                        <input
                            type="email"
                            className="blog-subscribe-input"
                            placeholder="Enter your email address..."
                            value={email}
                            onChange={(e) => setEmail(e.target.value)}
                            required
                        />
                        <button type="submit" className="blog-subscribe-btn">
                            Subscribe
                        </button>
                    </form>
                )}
            </div>

            {/* Articles Grid */}
            <div className="blog-grid">
                {articles.map((art, index) => (
                    <article className="blog-card" key={index} style={{ display: 'flex', flexDirection: 'column' }}>
                        <div className="blog-card-header">
                            <span className="blog-card-category">{art.category}</span>
                            <span className={`blog-card-tag ${art.tagClass}`}>{art.tag}</span>
                        </div>
                        <h2 className="blog-card-title">
                            <Link to="/" style={{ color: 'inherit', textDecoration: 'none' }}>
                                {art.title}
                            </Link>
                        </h2>
                        <p className="blog-card-excerpt">
                            <GlossaryText text={art.excerpt} />
                        </p>
                        <div className="blog-card-footer" style={{ marginTop: 'auto' }}>
                            <span className="blog-card-date">{art.date}</span>
                            <Link to="/" className="blog-card-readmore" style={{ textDecoration: 'none' }}>
                                Read More &rarr;
                            </Link>
                        </div>
                    </article>
                ))}
            </div>

            {/* Discover Callout */}
            <div className="blog-discover-callout" style={{ marginTop: '48px', padding: '32px', backgroundColor: 'var(--bg-card)', borderRadius: '12px', border: '1px solid var(--border)', textAlign: 'center' }}>
                <h3 style={{ fontSize: '20px', marginBottom: '12px', color: 'var(--primary)' }}>Ready to Exploit CTF Challenges?</h3>
                <p style={{ color: 'var(--text-secondary)', marginBottom: '20px' }}>
                    <GlossaryText text="BinExplain is a free, web-based CTF binary static analyzer that finds ROP gadgets and generates python exploit templates." />
                </p>
                <div style={{ display: 'flex', gap: '16px', justifyContent: 'center' }}>
                    <Link to="/" className="blog-subscribe-btn" style={{ textDecoration: 'none', padding: '10px 20px', borderRadius: '6px' }}>
                        Try the Tool
                    </Link>
                    <Link to="/docs" style={{ color: 'var(--primary)', textDecoration: 'none', alignSelf: 'center', fontWeight: '600' }}>
                        Read the Docs &rarr;
                    </Link>
                </div>
            </div>

            <div style={{fontSize:'11px',color:'#484f58',padding:'8px 16px',
                textAlign:'center',marginTop:'24px'}}>
              💡 Hover over <span style={{borderBottom:'1px dashed #388bfd',
                color:'#79c0ff'}}>highlighted terms</span> for plain English explanations
            </div>
        </div>
    );
}
