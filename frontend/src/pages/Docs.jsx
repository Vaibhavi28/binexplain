import React, { useState, useEffect } from 'react';
import { Helmet } from 'react-helmet-async';
import { Link } from 'react-router-dom';
import GlossaryText from '../components/GlossaryText';

export default function Docs({ onNavigate }) {
    const sections = [
        { id: 'getting-started', label: '1. Getting Started' },
        { id: 'uploading-files', label: '2. Uploading Files' },
        { id: 'understanding-results', label: '3. Understanding Results' },
        { id: 'learn-page', label: '4. Learn Page & Interactive Guides' },
        { id: 'ai-features', label: '5. AI Features & Mentor Commitment' },
        { id: 'provenance', label: '6. Evidence & Provenance Labeling' },
        { id: 'quick-commands', label: '7. Quick Commands' },
        { id: 'source-analysis', label: '8. Source Code Analysis' },
        { id: 'virustotal', label: '9. VirusTotal' },
        { id: 'api-keys', label: '10. API Keys' },
        { id: 'troubleshooting', label: '11. Troubleshooting' },
        { id: 'license-notice', label: '12. License & Open Source' }
    ];

    const [activeSection, setActiveSection] = useState('getting-started');

    useEffect(() => {
        const handleScroll = () => {
            let current = 'getting-started';
            for (const section of sections) {
                const el = document.getElementById(section.id);
                if (el) {
                    const rect = el.getBoundingClientRect();
                    if (rect.top <= 120) {
                        current = section.id;
                    }
                }
            }
            setActiveSection(current);
        };

        window.addEventListener('scroll', handleScroll);
        handleScroll();
        return () => window.removeEventListener('scroll', handleScroll);
    }, []);

    const handleBackClick = (e) => {
        e.preventDefault();
        if (onNavigate) {
            onNavigate('/');
        } else {
            window.location.hash = '#/';
        }
    };

    const scrollToSection = (e, id) => {
        e.preventDefault();
        const el = document.getElementById(id);
        if (el) {
            el.scrollIntoView({ behavior: 'smooth' });
            window.history.pushState(null, '', `#docs#${id}`);
            setActiveSection(id);
        }
    };

    return (
        <div className="docs-container">
            <Helmet>
                <title>Documentation — BinExplain</title>
                <meta name="description" content="Complete documentation for BinExplain binary analysis tool, interactive Learn guides, AI mentor commitment rules, evidence provenance, and Apache 2.0 licensing." />
                <link rel="canonical" href="https://binexplain.com/docs" />
                <script type="application/ld+json">{`
{
  "@context": "https://schema.org",
  "@type": "FAQPage",
  "mainEntity": [
    {
      "@type": "Question",
      "name": "What is BinExplain?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "BinExplain is a browser-based static analysis platform for CTF binary exploitation. It parses executables and source code, classifies exploitation vectors, extracts gadgets, and provides AI mentoring with evidence provenance."
      }
    },
    {
      "@type": "Question",
      "name": "How does the AI mentor work?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "The AI mentor commits to a single exploitation hypothesis based on your binary's data and diagnoses reported failures before pivoting."
      }
    },
    {
      "@type": "Question",
      "name": "What is evidence provenance?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "Every hint displays a 'Based on:' label showing the exact binary evidence (function name, protection flag, offset, gadget, disassembly) backing the claim."
      }
    },
    {
      "@type": "Question",
      "name": "What license does BinExplain use?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "BinExplain code is open source under Apache License 2.0. The BinExplain brand name remains reserved per the NOTICE file."
      }
    }
  ]
}
                `}</script>
            </Helmet>

            {/* Left Sidebar Navigation */}
            <aside className="docs-sidebar">
                <div className="docs-nav-title">Documentation</div>
                <nav>
                    <ul className="docs-nav-list">
                        {sections.map((sec) => (
                            <li key={sec.id}>
                                <a
                                    href={`#${sec.id}`}
                                    onClick={(e) => scrollToSection(e, sec.id)}
                                    className={`docs-nav-link ${activeSection === sec.id ? 'docs-nav-link--active' : ''}`}
                                >
                                    {sec.label}
                                </a>
                            </li>
                        ))}
                    </ul>
                </nav>
            </aside>

            {/* Right Scrollable Content area */}
            <main className="docs-content">
                <a href="#/" onClick={handleBackClick} className="docs-back-link">
                    &larr; Back to Analyzer
                </a>
                <h1 className="docs-title">BinExplain Documentation</h1>

                <div style={{fontSize:'12px',color:'#8b949e',padding:'12px 16px',
                    background:'#161b22',borderRadius:'6px',marginBottom:'20px',
                    border:'1px solid #21262d'}}>
                  <strong style={{color:'#79c0ff'}}>Tip:</strong> Hover over{' '}
                  <span style={{borderBottom:'1px dashed #388bfd',color:'#79c0ff'}}>
                    highlighted terms
                  </span>{' '}anywhere in this documentation for plain English explanations
                  with real-world examples.
                </div>

                {/* Section 1 — Getting Started */}
                <section id="getting-started" className="docs-section">
                    <h2>1. Getting Started</h2>
                    <h3>What is BinExplain</h3>
                    <p>
                        <GlossaryText text="BinExplain is a modern, web-based static analysis platform designed to help beginners and experienced security researchers analyze binary executables and source code. It combines traditional static analysis tools with advanced AI models to translate low-level output into understandable, context-rich explanations and actionable guidance. BinExplain was built to lower the barrier to entry for CTF beginners." /> <Link to="/about">Read the full story</Link> of why this tool exists.
                    </p>
                    <h3>No Installation Required</h3>
                    <p>
                        <GlossaryText text="There are no command-line tools to download, no compilers or dependencies to configure, and no account setup required. BinExplain runs entirely in your web browser, communicating with a backend analysis service to parse file characteristics in real time." />
                    </p>
                    <h3>Supported Browsers</h3>
                    <p>
                        <GlossaryText text="BinExplain is compatible with and optimized for all modern web browsers:" />
                    </p>
                    <ul>
                        <li><strong>Google Chrome</strong> (and chromium-based browsers)</li>
                        <li><strong>Mozilla Firefox</strong></li>
                        <li><strong>Microsoft Edge</strong></li>
                        <li><strong>Apple Safari</strong></li>
                    </ul>
                </section>

                {/* Section 2 — Uploading Files */}
                <section id="uploading-files" className="docs-section">
                    <h2>2. Uploading Files</h2>
                    <p>
                        <GlossaryText text="You can drag and drop your files directly into the analyzer dropzone, or browse files from your local system." />
                    </p>
                    <ul>
                        <li>
                            <strong>Accepted Binary Formats:</strong> <code className="docs-code">.elf</code>, <code className="docs-code">.exe</code>, <code className="docs-code">.bin</code>, <code className="docs-code">.so</code>, <code className="docs-code">.dll</code>, <code className="docs-code">.out</code>, <code className="docs-code">.o</code>, and extensionless compiled files.
                        </li>
                        <li>
                            <strong>Accepted Source Code:</strong> <code className="docs-code">.c</code>, <code className="docs-code">.cpp</code>, <code className="docs-code">.py</code>, <code className="docs-code">.js</code>, <code className="docs-code">.rs</code>, <code className="docs-code">.go</code>.
                        </li>
                        <li>
                            <strong>ZIP Archives:</strong> Compressed archives are supported and fully unpacked for scanning, including password-protected ZIP archives (supports max 20 files, 10MB total). When a password is required, you will be prompted to enter it securely.
                        </li>
                        <li>
                            <strong>Maximum File Size:</strong> 5MB per individual file.
                        </li>
                        <li>
                            <strong>Privacy &amp; Security:</strong> <GlossaryText text="Files are strictly parsed using static analysis only. They are deleted immediately after the analysis finishes — nothing is stored on our servers." />
                        </li>
                    </ul>
                </section>

                {/* Section 3 — Understanding Results */}
                <section id="understanding-results" className="docs-section">
                    <h2>3. Understanding Results</h2>
                    
                    <h3>CTF Categories Explained</h3>
                    <p>
                        BinExplain automatically classifies your binary or source code into one of six core exploitation archetypes:
                    </p>
                    <ul>
                        <li>
                            <strong>ret2win:</strong> <GlossaryText text="A classic buffer overflow scenario. The binary contains a developer-written `win()` function (e.g., `win()`, `flag()`, or `secret()`) that is not normally called. The goal is to overflow the stack buffer and overwrite the return address with the address of the win function." />
                        </li>
                        <li>
                            <strong>ret2libc:</strong> <GlossaryText text="NX (No-Execute) is enabled, meaning you cannot execute shellcode on the stack, and there is no win function. The goal is to overflow the buffer and redirect code execution to library functions in `libc`, commonly targeting `system()` with the argument string '/bin/sh'." />
                        </li>
                        <li>
                            <strong>format_string:</strong> <GlossaryText text="Occurs when user input is passed directly to output formatting functions (like `printf(buf)`) without a format specifier. Attackers can supply format modifiers like `%p` to leak stack values (canaries, pointers) or `%n` to write arbitrary values to arbitrary memory." />
                        </li>
                        <li>
                            <strong>heap_exploitation:</strong> <GlossaryText text="Involves memory safety violations within dynamically allocated heap chunks. Common vulnerability patterns include Use-After-Free (UAF), double-freeing pointers, heap overflows, or fastbin/tcache poisoning to bypass allocator metadata." />
                        </li>
                        <li>
                            <strong>rop_chain:</strong> <GlossaryText text="NX is enabled and PIE is often enabled, requiring code reuse. The goal is to chain small assembly instruction snippets (gadgets) ending in `ret` to bypass protections, typically call functions, or pivot the stack." />
                        </li>
                        <li>
                            <strong>shellcode:</strong> <GlossaryText text="NX is disabled. You can inject custom machine code (shellcode) into a buffer on the stack or heap and overwrite the return address to jump directly to the buffer's address to execute the payload." />
                        </li>
                    </ul>

                    <h4>Extended Techniques Detected</h4>
                    <p>
                        BinExplain also detects and indexes advanced binary exploitation and bypass techniques:
                    </p>
                    <ul style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))', gap: '8px', paddingLeft: '20px' }}>
                        <li><code className="docs-code">ret2plt</code></li>
                        <li><code className="docs-code">got_overwrite</code></li>
                        <li><code className="docs-code">ret2csu</code></li>
                        <li><code className="docs-code">srop</code></li>
                        <li><code className="docs-code">fastbin_dup</code></li>
                        <li><code className="docs-code">tcache_poisoning</code></li>
                        <li><code className="docs-code">use_after_free</code></li>
                        <li><code className="docs-code">one_gadget</code></li>
                        <li><code className="docs-code">canary_bypass</code></li>
                        <li><code className="docs-code">pie_bypass</code></li>
                        <li><code className="docs-code">off_by_one</code></li>
                        <li><code className="docs-code">stack_pivot</code></li>
                        <li><code className="docs-code">integer_overflow</code></li>
                        <li><code className="docs-code">seccomp_bypass</code></li>
                    </ul>

                    <h3>Difficulty Assessment &amp; CVSS Score</h3>
                    <p>
                        Difficulty is classified as <strong>Easy</strong>, <strong>Medium</strong>, or <strong>Hard</strong> based on active mitigations. A Common Vulnerability Scoring System (CVSS) severity score between 0.0 and 10.0 is computed from dangerous functions, protections, and exploit vectors.
                    </p>

                    <h3>Checksec Protections</h3>
                    <ul>
                        <li><strong>NX (No-Execute):</strong> <GlossaryText text="Prevents code execution on the stack/heap." /></li>
                        <li><strong>PIE (Position Independent Executable):</strong> <GlossaryText text="Randomizes the binary's code section base address in memory." /></li>
                        <li><strong>Stack Canary:</strong> <GlossaryText text="A guard value placed on the stack to detect buffer overflows before returning." /></li>
                        <li><strong>RELRO (RELocation Read-Only):</strong> <GlossaryText text="Hardens the Global Offset Table (GOT) against overwriting." /></li>
                        <li><strong>Fortify:</strong> <GlossaryText text="Replaces buffer-bound functions with bounds-checked variants (e.g. `__printf_chk`)." /></li>
                    </ul>
                </section>

                {/* Section 4 — Learn Page & Interactive Guides */}
                <section id="learn-page" className="docs-section">
                    <h2>4. Learn Page &amp; Interactive Guides</h2>
                    <p>
                        The <Link to="/learn">Learn Page</Link> provides an interactive, visual curriculum designed to build mental models of binary exploitation concepts step-by-step:
                    </p>
                    <ul>
                        <li>
                            <strong>0. Key Terms First (Core Vocabulary):</strong> Documents 12 foundational security terms (Stack, Return Address, Buffer Overflow, NX, Gadget, ROP, PIE, Canary, GOT, RELRO, Heap, libc). Each card includes a direct definition and a toggleable 3-part narrative mode:
                            <br />
                            <em>Part A (In Real Life)</em> — concrete literal definition without jargon.
                            <br />
                            <em>Part B (Picture It Like This)</em> — real-world apartment building metaphor with zero code or assembly syntax.
                            <br />
                            <em>Part C (Translated Back)</em> — direct one-to-one mapping connecting the metaphor back to technical primitives.
                        </li>
                        <li>
                            <strong>1. What is a Binary:</strong> Interactive ELF structure layout and step-by-step binary execution walkthrough.
                        </li>
                        <li>
                            <strong>2. Security Protections Map:</strong> Interactive mitigation toggles with a live feasibility matrix showing how NX, PIE, Canary, and RELRO block specific attack vectors.
                        </li>
                        <li>
                            <strong>3. Exploitation Flowchart:</strong> Guided decision tree that leads you through binary analysis questions to pinpoint the exact attack strategy.
                        </li>
                        <li>
                            <strong>4. Technique Deep Dives:</strong> Interactive animated visual walkthroughs for ret2win, ret2libc, format string, heap exploitation, ROP chains, and shellcode.
                        </li>
                        <li>
                            <strong>5. Wired Connection Map:</strong> Architectural relationship diagram connecting binary sections, CPU registers, and exploit targets.
                        </li>
                        <li>
                            <strong>6. Real World Impact:</strong> Real-world CVE case studies (such as Heartbleed, Shellshock, and sudo UAF) mapped directly to binary exploitation techniques.
                        </li>
                        <li>
                            <strong>7. Try It Yourself:</strong> Pre-loaded demo binary challenges compiled from source code, complete with source code views and pre-configured pwntools exploit scripts.
                        </li>
                    </ul>
                </section>

                {/* Section 5 — AI Features & Mentor Commitment */}
                <section id="ai-features" className="docs-section">
                    <h2>5. AI Features &amp; Mentor Commitment</h2>
                    <p>
                        BinExplain combines LLM inference with binary-derived analysis data to act as an active CTF mentor:
                    </p>
                    <ul>
                        <li>
                            <strong>Single Hypothesis Commitment (Rule 11):</strong> The AI mentor commits to a single exploitation hypothesis based on your binary's specific data and drives it forward, rather than listing multiple possible approaches.
                        </li>
                        <li>
                            <strong>Diagnose Before Pivoting (Rule 12 &amp; 13):</strong> When something does not work, describe exactly what happened (the error message, unexpected output, or crash) so the AI can diagnose the specific cause rather than guessing at alternatives.
                        </li>
                        <li>
                            <strong>Multi-Model Fallback &amp; Quality Gate:</strong> BinExplain queries Groq and Nemotron in parallel. If a primary response is generic or missing key detail, the system automatically falls back to secondary providers to ensure high-quality output.
                        </li>
                        <li>
                            <strong>Knowledge Base RAG:</strong> Backed by 2,200+ indexed CTF writeups across 24 exploitation technique tags to provide accurate, real-world exploit patterns.
                        </li>
                        <li>
                            <strong>Screenshot Analysis:</strong> Upload GDB or terminal error screenshots into the chatbot for contextual visual debugging assistance.
                        </li>
                        <li>
                            <strong>Command Explainer:</strong> Clicking the helper icon next to suggested terminal commands opens a parameter-by-parameter breakdown of what the command does.
                        </li>
                    </ul>
                </section>

                {/* Section 6 — Evidence & Provenance Labeling */}
                <section id="provenance" className="docs-section">
                    <h2>6. Evidence &amp; Provenance Labeling</h2>
                    <p>
                        To ensure AI advice is verifiable and grounded in empirical facts, BinExplain implements end-to-end evidence provenance tracking across both backend analysis and frontend cards:
                    </p>
                    <ul>
                        <li>
                            <strong>"Based on:" Labels:</strong> AI-generated hints and analysis-derived cards each display a small "Based on:" label showing exactly which finding in the binary supports that specific claim.
                        </li>
                        <li>
                            <strong>Evidence Types Tracked:</strong>
                            <ul>
                                <li><code>function</code> — specific symbols detected (e.g. <code>win</code>, <code>puts</code>, <code>system</code>)</li>
                                <li><code>offset</code> — predicted stack buffer overflow distance (e.g. 72 bytes)</li>
                                <li><code>protection</code> — active checksec mitigations (e.g. <code>NX Enabled</code>, <code>PIE Disabled</code>)</li>
                                <li><code>disassembly</code> — assembly line instructions or function calls</li>
                                <li><code>gadget</code> — discovered ROP gadgets (e.g. <code>pop rdi; ret</code>)</li>
                                <li><code>general</code> — fallback binary metadata verification</li>
                            </ul>
                        </li>
                        <li>
                            <strong>Independent Verification:</strong> Users can cross-check every AI suggestion directly against the extracted binary evidence rather than relying on unverified claims.
                        </li>
                    </ul>
                </section>

                {/* Section 7 — Quick Commands */}
                <section id="quick-commands" className="docs-section">
                    <h2>7. Quick Commands Panel</h2>
                    <p>
                        The Quick Commands panel automatically displays relevant terminal commands (e.g., <code className="docs-code">checksec</code>, <code className="docs-code">strings</code>, <code className="docs-code">objdump</code>, or custom Python pwntools commands) pre-filled with the name of the file you uploaded.
                    </p>
                    <ul>
                        <li>
                            <strong>Each command includes:</strong>
                            <ul>
                                <li><strong>Copy</strong> — copies the exact command with your binary name pre-filled</li>
                                <li><strong>Explain</strong> — shows a visual word-by-word breakdown of what each flag and argument does, with expected output and CTF relevance</li>
                            </ul>
                        </li>
                    </ul>
                </section>

                {/* Section 8 — Source Code Analysis */}
                <section id="source-analysis" className="docs-section">
                    <h2>8. Source Code Analysis</h2>
                    <p>
                        BinExplain provides full feature parity between binary and source code analysis.
                    </p>
                    <ul>
                        <li>
                            <strong>Pasted Code or Uploads:</strong> You can paste source code directly into the editor box or upload a source code file.
                        </li>
                        <li>
                            <strong>Precise Buffer Calculation:</strong> <GlossaryText text="In source code mode, the analyzer reads variable declarations directly (e.g., `char buf[64];`) to provide more precise overflow offset predictions." />
                        </li>
                        <li>
                            <strong>Compilation Helper:</strong> <GlossaryText text="The quick commands panel in source code mode automatically generates compilation commands (e.g. `gcc -fno-stack-protector -z execstack`) showing you how to compile the source code to enable or disable specific mitigations for practice." />
                        </li>
                    </ul>
                </section>

                {/* Section 9 — VirusTotal */}
                <section id="virustotal" className="docs-section">
                    <h2>9. VirusTotal Integration</h2>
                    <p>
                        BinExplain features an optional VirusTotal scanning flag.
                    </p>
                    <ul>
                        <li>
                            <strong>Disabled by Default:</strong> This feature is completely opt-in. Files are never submitted to VirusTotal unless you check the box prior to upload.
                        </li>
                        <li>
                            <strong>Warning:</strong> <GlossaryText text="Any files uploaded to VirusTotal are stored permanently in public threat-intelligence archives. Do not submit corporate binaries, private university assignments, or sensitive personal data." />
                        </li>
                    </ul>
                </section>

                {/* Section 10 — API Keys */}
                <section id="api-keys" className="docs-section">
                    <h2>10. API Keys (for self-hosting)</h2>
                    <p>
                        If you choose to run BinExplain locally, you can self-host the application and add your own API keys. Full features are accessible using only free-tier API endpoints.
                    </p>
                    <div className="docs-table-wrapper">
                        <table className="docs-table">
                            <thead>
                                <tr>
                                    <th>Provider</th>
                                    <th>Get Key Link</th>
                                    <th>Used For</th>
                                    <th>Cost Tier</th>
                                </tr>
                            </thead>
                            <tbody>
                                <tr>
                                    <td><strong>Groq</strong></td>
                                    <td><a href="https://console.groq.com" target="_blank" rel="noopener noreferrer" className="docs-link">console.groq.com</a></td>
                                    <td>Primary AI hints (parallel)</td>
                                    <td>Free</td>
                                </tr>
                                <tr>
                                    <td><strong>OpenRouter</strong></td>
                                    <td><a href="https://openrouter.ai" target="_blank" rel="noopener noreferrer" className="docs-link">openrouter.ai</a></td>
                                    <td>Nemotron 3 Ultra</td>
                                    <td>Free</td>
                                </tr>
                                <tr>
                                    <td><strong>Gemini</strong></td>
                                    <td><a href="https://aistudio.google.com" target="_blank" rel="noopener noreferrer" className="docs-link">aistudio.google.com</a></td>
                                    <td>Fallback inference + Vision</td>
                                    <td>Free</td>
                                </tr>
                                <tr>
                                    <td><strong>OpenAI</strong></td>
                                    <td><a href="https://platform.openai.com" target="_blank" rel="noopener noreferrer" className="docs-link">platform.openai.com</a></td>
                                    <td>Fallback</td>
                                    <td>Paid</td>
                                </tr>
                                <tr>
                                    <td><strong>VirusTotal</strong></td>
                                    <td><a href="https://virustotal.com" target="_blank" rel="noopener noreferrer" className="docs-link">virustotal.com</a></td>
                                    <td>Optional file scan hashes</td>
                                    <td>Free</td>
                                </tr>
                                <tr>
                                    <td><strong>Anthropic</strong></td>
                                    <td><a href="https://console.anthropic.com" target="_blank" rel="noopener noreferrer" className="docs-link">console.anthropic.com</a></td>
                                    <td>Last resort inference</td>
                                    <td>Paid</td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                </section>

                {/* Section 11 — Troubleshooting */}
                <section id="troubleshooting" className="docs-section">
                    <h2>11. Troubleshooting</h2>
                    <ul>
                        <li>
                            <strong>"Cannot connect to backend":</strong> <GlossaryText text="Check that the backend server is running (defaults to `http://localhost:8000`). Refresh the page and try again." />
                        </li>
                        <li>
                            <strong>"All AI providers failed":</strong> <GlossaryText text="Groq or Gemini API endpoints may be rate-limited. Wait 30 seconds and click analyze again." />
                        </li>
                        <li>
                            <strong>"File rejected":</strong> <GlossaryText text="Ensure the uploaded file size is under the 5MB limit and uses a supported extension or is a valid extensionless binary file." />
                        </li>
                        <li>
                            <strong>"AI hints are generic":</strong> <GlossaryText text="This happens occasionally if the binary contains zero strings or readable tables. Ask a specific question in the follow-up chat (e.g., 'what does the main function do?') to seed the conversational memory." />
                        </li>
                    </ul>
                </section>

                {/* Section 12 — License & Open Source */}
                <section id="license-notice" className="docs-section">
                    <h2>12. License &amp; Open Source</h2>
                    <p>
                        BinExplain source code is open source and{' '}
                        <a href="https://www.apache.org/licenses/LICENSE-2.0" target="_blank" rel="noopener noreferrer" className="docs-link">
                            Licensed under Apache License 2.0
                        </a>.
                    </p>
                    <ul>
                        <li>
                            <strong>Permissive Code License:</strong> You are free to inspect, modify, fork, and use the source code for commercial and non-commercial purposes under the terms of Apache License 2.0.
                        </li>
                        <li>
                            <strong>Protected Name &amp; Branding:</strong> Per the project NOTICE file, the name "BinExplain", logos, and branding are protected identifiers for the official project maintained at <a href="https://binexplain.com" target="_blank" rel="noopener noreferrer" className="docs-link">binexplain.com</a>. Derivative works, forks, or competing deployments must use a distinct name and branding.
                        </li>
                    </ul>
                </section>
            </main>
        </div>
    );
}
