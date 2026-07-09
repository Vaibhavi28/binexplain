import React, { useState, useEffect } from 'react';
import { Helmet } from 'react-helmet-async';
import { Link } from 'react-router-dom';
import GlossaryText from '../components/GlossaryText';

export default function Docs({ onNavigate }) {
    const sections = [
        { id: 'getting-started', label: '1. Getting Started' },
        { id: 'uploading-files', label: '2. Uploading Files' },
        { id: 'understanding-results', label: '3. Understanding Results' },
        { id: 'ai-features', label: '4. AI Features' },
        { id: 'quick-commands', label: '5. Quick Commands' },
        { id: 'source-analysis', label: '6. Source Code Analysis' },
        { id: 'virustotal', label: '7. VirusTotal' },
        { id: 'api-keys', label: '8. API Keys' },
        { id: 'troubleshooting', label: '9. Troubleshooting' }
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
                <meta name="description" content="Learn how to use BinExplain. Supported file formats, how to interpret CTF category results, AI features, and troubleshooting guide." />
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
        "text": "BinExplain is a free, browser-based tool that analyzes binary files for CTF (Capture The Flag) challenges. It detects the CTF exploitation category, finds ROP gadgets, predicts buffer overflow offsets, and generates a pre-filled pwntools exploit template."
      }
    },
    {
      "@type": "Question",
      "name": "Is BinExplain free to use?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "Yes, BinExplain is completely free for individual use. No account or installation required."
      }
    },
    {
      "@type": "Question",
      "name": "What file types does BinExplain support?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "BinExplain supports ELF binaries, PE executables, extensionless files, ZIP archives including password-protected ones, and source code in C, C++, Python, JavaScript, Rust, and Go."
      }
    },
    {
      "@type": "Question",
      "name": "Does BinExplain execute uploaded binaries?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "No. BinExplain performs static analysis only and never executes uploaded files. Files are deleted immediately after analysis."
      }
    },
    {
      "@type": "Question",
      "name": "What CTF categories does BinExplain detect?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "BinExplain classifies binaries into six CTF exploitation categories: ret2win, ret2libc, format string, heap exploitation, ROP chain, and shellcode."
      }
    }
  ]
}
                `}</script>
                <script type="application/ld+json">{`
{
  "@context": "https://schema.org",
  "@type": "BreadcrumbList",
  "itemListElement": [
    {"@type": "ListItem", "position": 1, "name": "Home", "item": "https://binexplain.com"},
    {"@type": "ListItem", "position": 2, "name": "Documentation", "item": "https://binexplain.com/docs"}
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
                  💡 <strong style={{color:'#79c0ff'}}>Tip:</strong> Hover over{' '}
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

                    <h4>Extended Techniques Detected (via RAG and technique tagging)</h4>
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
                        <li><code className="docs-code">house_of_force</code></li>
                        <li><code className="docs-code">house_of_spirit</code></li>
                        <li><code className="docs-code">house_of_orange</code></li>
                        <li><code className="docs-code">unsorted_bin_attack</code></li>
                    </ul>

                    <h3>Difficulty Assessment</h3>
                    <p>
                        The analyzer classifies difficulty as <strong>Easy</strong>, <strong>Medium</strong>, or <strong>Hard</strong>. This rating is dynamically calculated based on the active security mitigations (e.g. checksec flags) present in the executable.
                    </p>

                    <h3>CVSS Score</h3>
                    <p>
                        A computed industry-standard Common Vulnerability Scoring System (CVSS) severity score between 0.0 (low risk) and 10.0 (critical risk) is provided based on the combined presence of dangerous functions, file mitigations, and potential exploit vectors.
                    </p>

                    <h3>Checksec Protections</h3>
                    <p>
                        Security mitigations compiled into the binary are explained in plain English:
                    </p>
                    <ul>
                        <li><strong>NX (No-Execute):</strong> <GlossaryText text="Prevents code execution on the stack/heap." /></li>
                        <li><strong>PIE (Position Independent Executable):</strong> <GlossaryText text="Randomizes the binary's code section base address in memory." /></li>
                        <li><strong>Stack Canary:</strong> <GlossaryText text="A guard value placed on the stack to detect buffer overflows before returning." /></li>
                        <li><strong>RELRO (RELocation Read-Only):</strong> <GlossaryText text="Hardens the Global Offset Table (GOT) against overwriting." /></li>
                        <li><strong>Fortify:</strong> <GlossaryText text="Replaces buffer-bound functions with bounds-checked variants (e.g. `__printf_chk`)." /></li>
                    </ul>

                    <h3>ROP Gadgets</h3>
                    <p>
                        <GlossaryText text="Lists discovered assembly code sequences followed by a return instruction (`ret`) and their virtual memory addresses. These addresses are key ingredients for building custom ROP chains." />
                    </p>

                    <h3>Overflow Offset Prediction</h3>
                    <p>
                        <GlossaryText text="Predicts the exact number of bytes required to fill a local stack buffer and reach the saved frame pointer (EBP/RBP) or return address (EIP/RIP)." />
                    </p>
                </section>

                {/* Section 4 — AI Features */}
                <section id="ai-features" className="docs-section">
                    <h2>4. AI Features</h2>
                    <p>
                        BinExplain includes AI features that assist you with customized hints and interactive walk-throughs:
                    </p>
                    <ul>
                        <li>
                            <strong>AI Mentor Hints:</strong> <GlossaryText text="The system reads the results of checksec, file metadata, and strings to generate binary-specific hints. This goes beyond static documentation to explain the vulnerabilities present in the actual uploaded file." />
                        </li>
                        <li>
                            <strong>Parallel AI Inference:</strong> <GlossaryText text="To produce high-quality hints, BinExplain sends requests to Groq (which returns a fast, structured initial analysis) and Nemotron (which processes deep, conceptual advice) simultaneously, merging the best of both outputs." />
                        </li>
                        <li>
                            <strong>Quality Gate:</strong> <GlossaryText text="BinExplain uses a two-pass quality system. If an AI provider returns a generic or too-short response, it automatically tries the next provider instead of showing you a useless answer. You always get a substantive hint." />
                        </li>
                        <li>
                            <strong>Conversation Summarization:</strong> <GlossaryText text="Conversations never hit a hard limit. Every 10 messages, BinExplain automatically summarizes the session so far and continues with full context. You can have unlimited length sessions without losing context or starting over." />
                        </li>
                        <li>
                            <strong>AI Knowledge Base:</strong> <GlossaryText text="2200+ real CTF writeups from 13 curated sources, categorized across 24 exploitation technique tags including tcache poisoning, ret2csu, SROP, GOT overwrite, and more." />
                        </li>
                        <li>
                            <strong>Enhanced Badge:</strong> <GlossaryText text="An Enhanced badge appears in the UI when the Nemotron model is active and its deep analysis has been successfully merged into the final output." />
                        </li>
                        <li>
                            <strong>Follow-up Chat:</strong> <GlossaryText text="Use the interactive AI chatbot beneath your results to ask follow-up questions. Press Shift+Enter to insert a newline." />
                        </li>
                        <li>
                            <strong>Screenshot Analysis:</strong> <GlossaryText text="If you are stuck in GDB or are encountering a specific terminal error, take a screenshot and upload it to the chatbot. The vision model will analyze it and provide contextual debug advice." />
                        </li>
                        <li>
                            <strong>Command Explainer:</strong> <GlossaryText text="Every time the AI suggests a terminal command, a ? helper icon is displayed next to it. Clicking the icon returns a visual breakdown of exactly what the command parameters do." />
                        </li>
                        <li>
                            <strong>Interactive Glossary:</strong> <GlossaryText text="Hover over any highlighted technical term in the analysis results to see a plain English explanation with a real-world attack example. Terms covered include: buffer overflow, ROP, NX, PIE, canary, tcache, UAF, format string, and 30+ more." />
                        </li>
                    </ul>
                </section>

                {/* Section 5 — Quick Commands */}
                <section id="quick-commands" className="docs-section">
                    <h2>5. Quick Commands Panel</h2>
                    <p>
                        The Quick Commands panel automatically displays relevant terminal commands (e.g., <code className="docs-code">checksec</code>, <code className="docs-code">strings</code>, <code className="docs-code">objdump</code>, or custom Python pwntools commands) pre-filled with the name of the file you uploaded.
                    </p>
                    <ul>
                        <li>
                            <strong>Each command has two buttons:</strong>
                            <ul>
                                <li><strong>⎘ Copy</strong> — copies the exact command with your binary name pre-filled</li>
                                <li><strong>? Explain</strong> — shows a visual word-by-word breakdown of what each flag and argument does, with expected output and CTF relevance</li>
                            </ul>
                        </li>
                    </ul>
                </section>

                {/* Section 6 — Source Code Analysis */}
                <section id="source-analysis" className="docs-section">
                    <h2>6. Source Code Analysis</h2>
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
                            <strong>Compilation Helper:</strong> <GlossaryText text="The quick commands panel in source code mode automatically generates compilations commands (e.g. `gcc -fno-stack-protector -z execstack`) showing you how to compile the source code to enable or disable specific mitigations for practice." />
                        </li>
                    </ul>
                </section>

                {/* Section 7 — VirusTotal */}
                <section id="virustotal" className="docs-section">
                    <h2>7. VirusTotal Integration</h2>
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

                {/* Section 8 — API Keys */}
                <section id="api-keys" className="docs-section">
                    <h2>8. API Keys (for self-hosting)</h2>
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

                {/* Section 9 — Troubleshooting */}
                <section id="troubleshooting" className="docs-section">
                    <h2>9. Troubleshooting</h2>
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
            </main>
        </div>
    );
}
