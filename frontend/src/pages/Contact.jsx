import React, { useState } from 'react';

const BACKEND_URL = import.meta.env.VITE_BACKEND_URL || 'http://localhost:8000';

export default function Contact({ onNavigate }) {
    const [name, setName] = useState('');
    const [email, setEmail] = useState('');
    const [subject, setSubject] = useState('Bug Report');
    const [message, setMessage] = useState('');
    
    const [status, setStatus] = useState('idle'); // 'idle' | 'loading' | 'success' | 'error'

    const handleSubmit = async (e) => {
        e.preventDefault();
        setStatus('loading');
        try {
            const res = await fetch(`${BACKEND_URL}/api/contact`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ name, email, subject, message })
            });

            if (res.ok) {
                setStatus('success');
                setName('');
                setEmail('');
                setSubject('Bug Report');
                setMessage('');
            } else {
                setStatus('error');
            }
        } catch (err) {
            setStatus('error');
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
        <div className="contact-container">
            {/* Back link */}
            <a href="#/" onClick={handleBackClick} className="contact-back-link">
                &larr; Back to Analyzer
            </a>

            {/* SECTION 1 — Header */}
            <header className="contact-header">
                <h1 className="contact-title">Get in Touch</h1>
                <p className="contact-subheading">
                    Bug report, feature request, research collaboration,
                    or just want to say the tool helped you solve a challenge?
                </p>
            </header>

            {/* SECTION 2 — Contact Cards */}
            <div className="contact-cards">
                <div className="contact-card">
                    <span className="contact-card-icon">🐛</span>
                    <h3 className="contact-card-title">Found a Bug?</h3>
                    <p className="contact-card-text">
                        Open a GitHub issue with steps to reproduce and I will fix it.
                    </p>
                    <a
                        href="https://github.com/Vaibhavi28/binexplain/issues"
                        target="_blank"
                        rel="noopener noreferrer"
                        className="contact-card-btn"
                    >
                        Open GitHub Issue
                    </a>
                </div>

                <div className="contact-card">
                    <span className="contact-card-icon">💬</span>
                    <h3 className="contact-card-title">General Feedback</h3>
                    <p className="contact-card-text">
                        Did BinExplain help you solve a challenge? I genuinely want to know.
                    </p>
                    <a href="mailto:hello@binexplain.com" className="contact-card-btn">
                        Send Email
                    </a>
                </div>
            </div>

            {/* SECTION 3 — Simple contact form */}
            <div className="contact-form-wrapper">
                <h2 className="contact-form-title">Send a Message</h2>
                
                {status === 'success' && (
                    <div className="contact-status-msg contact-status-msg--success">
                        Message sent! I typically respond within 48 hours.
                    </div>
                )}

                {status === 'error' && (
                    <div className="contact-status-msg contact-status-msg--error">
                        Could not send message. Please email hello@binexplain.com directly.
                    </div>
                )}

                <form onSubmit={handleSubmit} className="contact-form">
                    <div className="contact-form-group">
                        <label htmlFor="contact-name">Name</label>
                        <input
                            type="text"
                            id="contact-name"
                            className="contact-input"
                            value={name}
                            onChange={(e) => setName(e.target.value)}
                            required
                        />
                    </div>

                    <div className="contact-form-group">
                        <label htmlFor="contact-email">Email</label>
                        <input
                            type="email"
                            id="contact-email"
                            className="contact-input"
                            value={email}
                            onChange={(e) => setEmail(e.target.value)}
                            required
                        />
                    </div>

                    <div className="contact-form-group">
                        <label htmlFor="contact-subject">Subject</label>
                        <select
                            id="contact-subject"
                            className="contact-input contact-select"
                            value={subject}
                            onChange={(e) => setSubject(e.target.value)}
                            required
                        >
                            <option value="Bug Report">Bug Report</option>
                            <option value="Feature Request">Feature Request</option>
                            <option value="Research">Research</option>
                            <option value="General">General</option>
                        </select>
                    </div>

                    <div className="contact-form-group">
                        <label htmlFor="contact-message">Message</label>
                        <textarea
                            id="contact-message"
                            className="contact-input contact-textarea"
                            rows="5"
                            value={message}
                            onChange={(e) => setMessage(e.target.value)}
                            required
                        />
                    </div>

                    <button
                        type="submit"
                        className="contact-submit-btn"
                        disabled={status === 'loading'}
                    >
                        {status === 'loading' ? 'Sending...' : 'Send Message'}
                    </button>
                </form>
            </div>
        </div>
    );
}
