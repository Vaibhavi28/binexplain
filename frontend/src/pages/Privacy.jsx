import React from 'react';

export default function Privacy({ onNavigate }) {
    const handleBackClick = (e) => {
        e.preventDefault();
        if (onNavigate) {
            onNavigate('/');
        } else {
            window.location.hash = '#/';
        }
    };

    return (
        <div className="privacy-container">
            {/* Back link */}
            <a href="#/" onClick={handleBackClick} className="privacy-back-link">
                &larr; Back to Analyzer
            </a>

            <header className="privacy-header">
                <h1 className="privacy-title">Privacy Policy</h1>
                <p className="privacy-date">Last updated: June 2026</p>
            </header>

            <div className="privacy-intro">
                <p>
                    BinExplain ("the tool", "we", "us") is operated by Vaibhavi Sanjay
                    Kathepuri. This policy explains what information we collect, why, and
                    how we protect it.
                </p>
            </div>

            <main className="privacy-content">
                <section className="privacy-section">
                    <h2>1. FILES YOU UPLOAD</h2>
                    <p>
                        Files uploaded to BinExplain for analysis are processed entirely in
                        server memory and deleted immediately after analysis is complete via
                        automated cleanup. We do not store, log, or retain uploaded binary files,
                        source code files, or ZIP archives. Uploaded files are never shared with
                        third parties except as described below.
                    </p>
                </section>

                <section className="privacy-section">
                    <h2>2. VIRUSTOTAL SUBMISSION (OPTIONAL)</h2>
                    <p>
                        If you choose to enable VirusTotal scanning by checking the opt-in
                        checkbox before uploading, your file will be submitted to VirusTotal's
                        service. Files submitted to VirusTotal are stored permanently in their
                        database per their terms of service. This option is disabled by default.
                        Only enable it for files you have permission to share publicly.
                    </p>
                </section>

                <section className="privacy-section">
                    <h2>3. CONVERSATION DATA</h2>
                    <p>
                        Chat conversations with the AI mentor are processed via third-party AI
                        providers (Groq, NVIDIA via OpenRouter, Google Gemini, OpenAI, Anthropic)
                        to generate responses. Conversation history exists only in your browser
                        session and is never stored on our servers. AI providers may retain
                        messages per their own privacy policies.
                    </p>
                </section>

                <section className="privacy-section">
                    <h2>4. ANALYTICS</h2>
                    <p>
                        We use Google Analytics to understand aggregate usage patterns including
                        page views, feature usage, and traffic sources. This data is anonymized
                        and used only to improve the tool. Google Analytics uses cookies to
                        identify unique visitors. You can opt out via your browser settings or
                        browser extensions.
                    </p>
                </section>

                <section className="privacy-section">
                    <h2>5. GOOGLE ADSENSE (FUTURE)</h2>
                    <p>
                        We may display Google AdSense advertisements. Google uses cookies to
                        serve ads based on your prior visits to this website and other websites.
                        You can opt out of personalized advertising at <a href="https://aboutads.info" target="_blank" rel="noopener noreferrer" className="privacy-link">aboutads.info</a>.
                    </p>
                </section>

                <section className="privacy-section">
                    <h2>6. CONTACT FORM</h2>
                    <p>
                        If you submit a message via the contact form, we log your name, email,
                        and message to a private log file for the purpose of responding to your
                        inquiry. This data is not shared with third parties.
                    </p>
                </section>

                <section className="privacy-section">
                    <h2>7. COOKIES</h2>
                    <p>
                        BinExplain itself does not use cookies beyond what Google Analytics and
                        Google AdSense require. You can disable cookies in your browser settings.
                    </p>
                </section>

                <section className="privacy-section">
                    <h2>8. YOUR RIGHTS</h2>
                    <p>
                        You may request deletion of any contact form submissions by emailing <a href="mailto:hello@binexplain.com" className="privacy-link">hello@binexplain.com</a>.
                        Analysis files are deleted automatically and cannot be recovered.
                    </p>
                </section>

                <section className="privacy-section">
                    <h2>9. CHANGES TO THIS POLICY</h2>
                    <p>
                        We may update this policy. Changes will be reflected on this page with
                        an updated date.
                    </p>
                </section>

                <section className="privacy-section">
                    <h2>10. CONTACT</h2>
                    <p>
                        For privacy questions: <a href="mailto:hello@binexplain.com" className="privacy-link">hello@binexplain.com</a>
                    </p>
                </section>
            </main>
        </div>
    );
}
