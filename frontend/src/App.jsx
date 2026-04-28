import { useState, useRef, useCallback, useEffect, useMemo } from 'react';

/* ── Config ────────────────────────────────────────────────────────── */
const BACKEND_URL = import.meta.env.VITE_BACKEND_URL || 'http://localhost:8000';

const ALLOWED_EXTENSIONS = ['.bin', '.elf', '.exe', '.so', '.dll', '.out', '.o', '.zip'];
const MAX_FILE_SIZE = 5 * 1024 * 1024; // 5 MB
const MAX_ZIP_SIZE = 10 * 1024 * 1024; // 10 MB

const LOADING_MESSAGES = [
    'Reading file headers...',
    'Extracting strings...',
    'Analyzing patterns...',
];

/* ── Helpers ───────────────────────────────────────────────────────── */
function formatBytes(bytes) {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

function getExtension(name) {
    if (!name) return '';
    const dot = name.lastIndexOf('.');
    // No dot, or dot is the first char with nothing after (e.g. ".bashrc" or "file.")
    if (dot <= 0) return '';
    const ext = name.slice(dot).toLowerCase();
    // Trailing dot (e.g. "file.") → treat as extensionless
    return ext === '.' ? '' : ext;
}

/* ── Accordion Card ────────────────────────────────────────────────── */
function AccordionCard({ id, icon, title, summary, open, onToggle, variant, children, sectionKey, openSections, toggleSection }) {
    const isOpen = open !== undefined ? open : (openSections && sectionKey ? openSections[sectionKey] : false);
    const handleToggle = onToggle || (toggleSection && sectionKey ? () => toggleSection(sectionKey) : () => {});
    const bodyRef = useRef(null);
    const [height, setHeight] = useState(isOpen ? 'auto' : '0px');
    const [measured, setMeasured] = useState(false);

    useEffect(() => {
        if (!bodyRef.current) return;
        if (isOpen) {
            setHeight(`${bodyRef.current.scrollHeight}px`);
            // After transition, switch to auto so inner content can resize
            const t = setTimeout(() => setHeight('auto'), 210);
            return () => clearTimeout(t);
        } else {
            // Force a reflow so the browser sees the current height before transitioning to 0
            if (measured) {
                setHeight(`${bodyRef.current.scrollHeight}px`);
                requestAnimationFrame(() => {
                    requestAnimationFrame(() => setHeight('0px'));
                });
            } else {
                setHeight('0px');
            }
        }
        setMeasured(true);
    }, [isOpen]);

    return (
        <div className={`accordion-card${variant ? ` accordion-card--${variant}` : ''}`} id={id || sectionKey}>
            <button
                className={`accordion-header${isOpen ? ' accordion-header--open' : ''}`}
                onClick={handleToggle}
                type="button"
                aria-expanded={isOpen}
                id={id || sectionKey ? `${id || sectionKey}-toggle` : undefined}
            >
                <span className={`accordion-arrow${isOpen ? ' accordion-arrow--open' : ''}`}>▶</span>
                <span className="accordion-icon">{icon}</span>
                <span className="accordion-title">{title}</span>
                {summary && <span className="accordion-summary">{summary}</span>}
            </button>
            <div
                className="accordion-body-wrapper"
                ref={bodyRef}
                style={{ height, overflow: height === 'auto' ? 'visible' : 'hidden' }}
            >
                <div className="accordion-body">
                    {children}
                </div>
            </div>
        </div>
    );
}

/* ── App ───────────────────────────────────────────────────────────── */
const MAX_CHAT_CHARS = 2000;
const MAX_CHAT_MESSAGES = 10;
const MAX_SOURCE_CODE_CHARS = 10000;
const SOURCE_CODE_EXTENSIONS = ['.c', '.cpp', '.h', '.hpp', '.py', '.js', '.rs', '.go', '.java'];

export default function App() {
    const [file, setFile] = useState(null);
    const [dragOver, setDragOver] = useState(false);
    const [loading, setLoading] = useState(false);
    const [loadingMsg, setLoadingMsg] = useState('');
    const [result, setResult] = useState(null);
    const [error, setError] = useState('');
    const inputRef = useRef(null);

    /* ── Analysis mode toggle ── */
    const [analysisMode, setAnalysisMode] = useState('binary');  // 'binary' | 'source'

    /* ── Source code analysis state ── */
    const [sourceCode, setSourceCode] = useState('');
    const [sourceFile, setSourceFile] = useState(null);
    const [sourceResult, setSourceResult] = useState(null);
    const [sourceLoading, setSourceLoading] = useState(false);
    const [sourceError, setSourceError] = useState('');
    const sourceInputRef = useRef(null);

    /* ── Chat state (lives in React only — lost on refresh by design) ── */
    const [chatMessages, setChatMessages] = useState([]);
    const [chatInput, setChatInput] = useState('');
    const [chatLoading, setChatLoading] = useState(false);
    const [chatImage, setChatImage] = useState(null);
    const [chatImagePreview, setChatImagePreview] = useState('');
    const chatEndRef = useRef(null);
    const chatImageRef = useRef(null);
    const analysisContextRef = useRef('');

    /* ── Password modal state (for protected ZIPs) ── */
    const [passwordModal, setPasswordModal] = useState(false);
    const [passwordInput, setPasswordInput] = useState('');
    const [passwordError, setPasswordError] = useState('');
    const [passwordLoading, setPasswordLoading] = useState(false);
    const passwordFileRef = useRef(null);

    /* ── VirusTotal polling state ── */
    const [submitToVt, setSubmitToVt] = useState(false);
    const [vtScanId, setVtScanId] = useState(null);
    const [vtResult, setVtResult] = useState(null);

    /* ── Accordion section open/close state ── */
    const [openSections, setOpenSections] = useState({
        ctfCategory: true,  // open by default — prominent
        cvss: false,
        functions: false,
        imports: false,
        dataFlows: false,
        checksec: false,
        ropGadgets: false,
        formatString: false,
        libcInfo: false,
        vt: false,
        hex: false,
        disasm: false,
        strings: false,
        flags: false,
        findings: false,
        encodings: false,
        pwn: false,
        hints: true,   // open by default
        chat: true,    // open by default
        // Source code sections
        srcLang: false,
        srcVuln: true,    // open by default
        srcDanger: false,
        srcHints: true,   // open by default
        srcSteps: false,
        srcCode: false,
    });

    /* ── AI Hints feedback ── */
    const [feedbackGiven, setFeedbackGiven] = useState(null);

    /* ── Rate limit countdown ── */
    const [rateLimitSeconds, setRateLimitSeconds] = useState(0);

    /* Toggle an accordion section */
    const toggleSection = useCallback((key) => {
        setOpenSections(prev => ({ ...prev, [key]: !prev[key] }));
    }, []);

    /* Build checksec summary for header (e.g. "NX✓ PIE✗ Canary✓") */
    const checksecSummary = useMemo(() => {
        if (!result?.checksec || result.checksec.nx === null) return '';
        const badges = [
            { key: 'nx', label: 'NX' },
            { key: 'pie', label: 'PIE' },
            { key: 'canary', label: 'Canary' },
            { key: 'relro', label: 'RELRO' },
            { key: 'fortify', label: 'Fortify' },
        ];
        return badges.map(b => `${b.label}${result.checksec[b.key] ? '✓' : '✗'}`).join(' ');
    }, [result?.checksec]);

    /* Auto-scroll chat to bottom on new messages */
    useEffect(() => {
        chatEndRef.current?.scrollIntoView({ behavior: 'smooth' });
    }, [chatMessages]);

    /* Cycle through loading messages while uploading */
    useEffect(() => {
        if (!loading) return;
        let i = 0;
        setLoadingMsg(LOADING_MESSAGES[0]);
        const id = setInterval(() => {
            i = (i + 1) % LOADING_MESSAGES.length;
            setLoadingMsg(LOADING_MESSAGES[i]);
        }, 1400);
        return () => clearInterval(id);
    }, [loading]);

    /* Poll VirusTotal for results every 5 seconds */
    useEffect(() => {
        if (!vtScanId) return;
        let cancelled = false;

        const poll = async () => {
            try {
                const res = await fetch(`${BACKEND_URL}/virustotal/${vtScanId}`);
                if (!res.ok) return;
                const data = await res.json();
                if (cancelled) return;

                if (data.status !== 'scanning') {
                    setVtResult(data);
                    setVtScanId(null); // stop polling
                }
            } catch {
                // Network error — keep polling
            }
        };

        const id = setInterval(poll, 5000);
        // Run immediately once
        poll();

        return () => {
            cancelled = true;
            clearInterval(id);
        };
    }, [vtScanId]);

    /* Rate limit countdown timer */
    useEffect(() => {
        if (rateLimitSeconds <= 0) return;
        const id = setInterval(() => {
            setRateLimitSeconds(prev => {
                if (prev <= 1) {
                    setError('');
                    return 0;
                }
                return prev - 1;
            });
        }, 1000);
        return () => clearInterval(id);
    }, [rateLimitSeconds]);

    /* Validate & stage a file */
    const stageFile = useCallback((f) => {
        setError('');
        setResult(null);

        if (!f || !f.name) {
            setError('❌ Invalid file. Please select a valid binary.');
            return;
        }

        const ext = getExtension(f.name);
        const isZip = ext === '.zip' || (f.type && f.type === 'application/zip') || (f.type && f.type === 'application/x-zip-compressed');

        // Allow extensionless files (auto-detected by backend via magic bytes)
        // Allow .zip files explicitly (backend supports them)
        if (ext !== '' && !isZip && !ALLOWED_EXTENSIONS.includes(ext)) {
            setError(`❌ Unsupported file type "${ext}". Accepted: ELF, EXE, BIN, SO, DLL, ZIP or extensionless binaries.`);
            return;
        }
        const sizeLimit = (ext === '.zip' || isZip) ? MAX_ZIP_SIZE : MAX_FILE_SIZE;
        const sizeLimitLabel = (ext === '.zip' || isZip) ? '10 MB' : '5 MB';
        if (f.size > sizeLimit) {
            setError(`📦 File too large (${formatBytes(f.size)}). Maximum size is ${sizeLimitLabel}.`);
            return;
        }
        if (f.size === 0) {
            setError('❌ File is empty. Please select a valid binary.');
            return;
        }
        setFile(f);
    }, []);

    /* Drag-and-drop handlers */
    const onDragOver = (e) => { e.preventDefault(); setDragOver(true); };
    const onDragLeave = () => setDragOver(false);
    const onDrop = (e) => {
        e.preventDefault();
        setDragOver(false);
        const f = e.dataTransfer.files?.[0];
        if (f) stageFile(f);
    };

    /* File picker */
    const onFileChange = (e) => {
        const f = e.target.files?.[0];
        if (f) stageFile(f);
        e.target.value = '';           // allow re-selecting the same file
    };

    /* Clear staged file */
    const clearFile = () => {
        setFile(null);
        setError('');
    };

    /* Upload & analyse */
    const upload = async () => {
        if (!file) return;
        setLoading(true);
        setError('');
        setResult(null);

        try {
            const form = new FormData();
            form.append('file', file);
            form.append('skip_virustotal', submitToVt ? 'false' : 'true');

            const res = await fetch(`${BACKEND_URL}/analyze`, {
                method: 'POST',
                body: form,
            });

            const data = await res.json().catch(() => ({}));

            if (!res.ok) {
                // Password-protected ZIP detection
                if (res.status === 422 && data.error_code === 'password_required') {
                    passwordFileRef.current = file;
                    setPasswordModal(true);
                    setPasswordInput('');
                    setPasswordError('');
                    setFile(null);
                    return;
                }

                if (res.status === 429) {
                    // Rate limited — parse retry-after
                    const retryAfter = res.headers.get('retry-after');
                    let waitMin = 60;
                    if (retryAfter) {
                        const secs = parseInt(retryAfter, 10);
                        if (!isNaN(secs)) {
                            waitMin = secs;
                            setRateLimitSeconds(secs);
                        }
                    } else {
                        setRateLimitSeconds(waitMin);
                    }
                    const mins = Math.ceil(waitMin / 60);
                    setError(`⏳ Rate limit reached — you can analyze 10 files per hour. Please wait ~${mins} minute${mins !== 1 ? 's' : ''} before trying again.`);
                } else {
                    setError(data.detail || `❌ Server error (${res.status})`);
                }
                return;
            }

            setRateLimitSeconds(0);
            setFeedbackGiven(null);
            
            // Fix ZIP crash in UI
            if (data.archive && data.results && Array.isArray(data.results)) {
                 setResult(data.results[0] || data);
            } else {
                 setResult(data);
            }
            
            setFile(null);

            /* Start VT polling if scan was submitted */
            if (data.virustotal?.status === 'scanning' && data.virustotal?.scan_id) {
                setVtScanId(data.virustotal.scan_id);
                setVtResult(null);
            } else if (data.virustotal?.status === 'disabled') {
                setVtScanId(null);
                setVtResult(null);
            } else {
                // error or other immediate result
                setVtScanId(null);
                // For zip array we still pass the top-level data virustotal if it exists, else result
                setVtResult(data.virustotal || (data.results && data.results[0]?.virustotal) || null);
            }

            /* Initialize chat with AI hints as first assistant message */
            const hints = data.hints || (data.results && data.results[0]?.hints);
            if (hints) {
                setChatMessages([{ role: 'assistant', content: hints }]);
                analysisContextRef.current = hints;
            } else {
                setChatMessages([]);
                analysisContextRef.current = '';
            }
        } catch (err) {
            setError(
                err.message === 'Failed to fetch'
                    ? '🔌 Cannot connect to backend. Make sure it\'s running on ' + BACKEND_URL
                    : `❌ Upload failed: ${err.message}`
            );
        } finally {
            setLoading(false);
        }
    };

    /* Upload with password (re-send file for protected ZIPs) */
    const uploadWithPassword = async () => {
        const zipFile = passwordFileRef.current;
        if (!zipFile || !passwordInput) return;

        setPasswordLoading(true);
        setPasswordError('');

        try {
            const form = new FormData();
            form.append('file', zipFile);
            form.append('password', passwordInput);
            form.append('skip_virustotal', submitToVt ? 'false' : 'true');

            const res = await fetch(`${BACKEND_URL}/analyze`, {
                method: 'POST',
                body: form,
            });

            const data = await res.json().catch(() => ({}));

            if (!res.ok) {
                if (res.status === 422 && data.error_code === 'wrong_password') {
                    setPasswordError('Incorrect password. Please try again.');
                    setPasswordInput('');
                    return;
                }
                if (res.status === 422 && data.error_code === 'password_required') {
                    setPasswordError('Password is required for this archive.');
                    return;
                }
                if (res.status === 429) {
                    setPasswordModal(false);
                    setPasswordInput('');
                    passwordFileRef.current = null;
                    setError('⏳ Rate limit reached. Please wait before trying again.');
                    return;
                }
                setPasswordError(data.detail || `Error (${res.status})`);
                return;
            }

            // Success — close modal, clear password, show results
            setPasswordModal(false);
            setPasswordInput('');
            setPasswordError('');
            passwordFileRef.current = null;

            setRateLimitSeconds(0);
            setFeedbackGiven(null);
            
            if (data.archive && data.results && Array.isArray(data.results)) {
                 setResult(data.results[0] || data);
            } else {
                 setResult(data);
            }

            /* Start VT polling if scan was submitted */
            if (data.virustotal?.status === 'scanning' && data.virustotal?.scan_id) {
                setVtScanId(data.virustotal.scan_id);
                setVtResult(null);
            } else if (data.virustotal?.status === 'disabled') {
                setVtScanId(null);
                setVtResult(null);
            } else {
                setVtScanId(null);
                setVtResult(data.virustotal || (data.results && data.results[0]?.virustotal) || null);
            }

            /* Initialize chat with AI hints */
            const hints = data.hints || (data.results && data.results[0]?.hints);
            if (hints) {
                setChatMessages([{ role: 'assistant', content: hints }]);
                analysisContextRef.current = hints;
            } else {
                setChatMessages([]);
                analysisContextRef.current = '';
            }
        } catch (err) {
            setPasswordError(
                err.message === 'Failed to fetch'
                    ? 'Cannot connect to backend.'
                    : err.message
            );
        } finally {
            setPasswordLoading(false);
        }
    };

    /* Attach image to chat */
    const onChatImageSelect = (e) => {
        const f = e.target.files?.[0];
        if (!f) return;
        e.target.value = '';
        const validTypes = ['image/png', 'image/jpeg', 'image/jpg', 'image/gif', 'image/webp'];
        if (!validTypes.includes(f.type)) {
            setChatMessages(prev => [...prev, { role: 'assistant', content: '⚠ Invalid image type. Accepted: PNG, JPG, GIF, WEBP.' }]);
            return;
        }
        if (f.size > 5 * 1024 * 1024) {
            setChatMessages(prev => [...prev, { role: 'assistant', content: '⚠ Image too large. Maximum: 5 MB.' }]);
            return;
        }
        setChatImage(f);
        setChatImagePreview(URL.createObjectURL(f));
    };

    const clearChatImage = () => {
        if (chatImagePreview) URL.revokeObjectURL(chatImagePreview);
        setChatImage(null);
        setChatImagePreview('');
    };

    /* Send a follow-up chat message */
    const sendChat = async () => {
        const hasImage = !!chatImage;
        const text = chatInput.trim();
        if ((!text && !hasImage) || chatLoading) return;
        if (text.length > MAX_CHAT_CHARS) return;

        // If there's an image, use the image endpoint
        if (hasImage) {
            const userMsg = { role: 'user', content: text || '📷 [Screenshot attached]', image: chatImagePreview };
            setChatMessages(prev => [...prev, userMsg]);
            setChatInput('');
            const imageFile = chatImage;
            clearChatImage();
            setChatLoading(true);

            try {
                const form = new FormData();
                form.append('file', imageFile);
                form.append('context', analysisContextRef.current || '');

                const res = await fetch(`${BACKEND_URL}/analyze-image`, {
                    method: 'POST',
                    body: form,
                });

                const data = await res.json();

                if (!res.ok) {
                    setChatMessages(prev => [...prev, { role: 'assistant', content: `⚠ Error: ${data.detail || 'Image analysis failed.'}` }]);
                    return;
                }

                setChatMessages(prev => [...prev, { role: 'assistant', content: data.response }]);
            } catch (err) {
                setChatMessages(prev => [...prev, { role: 'assistant', content: `⚠ ${err.message === 'Failed to fetch' ? 'Cannot reach backend.' : err.message}` }]);
            } finally {
                setChatLoading(false);
            }
            return;
        }

        // Text-only chat
        const userMsg = { role: 'user', content: text };
        const updated = [...chatMessages, userMsg].slice(-MAX_CHAT_MESSAGES);
        setChatMessages(updated);
        setChatInput('');
        setChatLoading(true);

        try {
            const res = await fetch(`${BACKEND_URL}/chat`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    messages: updated,
                    context: analysisContextRef.current,
                }),
            });

            const data = await res.json();

            if (!res.ok) {
                setChatMessages(prev => [
                    ...prev,
                    { role: 'assistant', content: `⚠ Error: ${data.detail || 'Something went wrong.'}` },
                ]);
                return;
            }

            setChatMessages(prev => [
                ...prev,
                { role: 'assistant', content: data.response },
            ]);
        } catch (err) {
            setChatMessages(prev => [
                ...prev,
                { role: 'assistant', content: `⚠ ${err.message === 'Failed to fetch' ? 'Cannot reach backend.' : err.message}` },
            ]);
        } finally {
            setChatLoading(false);
        }
    };

    const onChatKeyDown = (e) => {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();
            sendChat();
        }
    };
    /* ── Source code handlers ─────────────────────────────────────────── */
    const stageSourceFile = (f) => {
        if (!f) return;
        const ext = '.' + f.name.split('.').pop()?.toLowerCase();
        if (!SOURCE_CODE_EXTENSIONS.includes(ext)) {
            setSourceError(`Unsupported extension "${ext}". Accepted: ${SOURCE_CODE_EXTENSIONS.join(', ')}`);
            return;
        }
        if (f.size > MAX_SOURCE_CODE_CHARS * 2) {
            setSourceError(`File too large. Maximum ~${MAX_SOURCE_CODE_CHARS} characters.`);
            return;
        }
        setSourceError('');
        setSourceFile(f);
        const reader = new FileReader();
        reader.onload = (e) => {
            const text = e.target.result;
            if (text.length > MAX_SOURCE_CODE_CHARS) {
                setSourceError(`File content exceeds ${MAX_SOURCE_CODE_CHARS} character limit.`);
                setSourceFile(null);
                return;
            }
            setSourceCode(text);
        };
        reader.readAsText(f);
    };

    const analyzeSourceCode = async () => {
        if (!sourceCode.trim()) {
            setSourceError('Please paste or upload source code first.');
            return;
        }
        setSourceLoading(true);
        setSourceError('');
        setSourceResult(null);
        try {
            const resp = await fetch(`${BACKEND_URL}/analyze-code`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    code: sourceCode.slice(0, MAX_SOURCE_CODE_CHARS),
                    filename: sourceFile?.name || '',
                }),
            });
            if (resp.status === 429) {
                const data = await resp.json().catch(() => ({}));
                setSourceError(data.detail || 'Rate limit exceeded. Try again later.');
                return;
            }
            if (!resp.ok) {
                const data = await resp.json().catch(() => ({}));
                setSourceError(data.detail || `Server error (${resp.status})`);
                return;
            }
            const data = await resp.json();
            setSourceResult(data);
        } catch (err) {
            setSourceError(err.message === 'Failed to fetch' ? 'Cannot reach backend.' : err.message);
        } finally {
            setSourceLoading(false);
        }
    };

    const switchMode = (mode) => {
        setAnalysisMode(mode);
        if (mode === 'binary') {
            setSourceResult(null);
            setSourceError('');
        } else {
            setResult(null);
            setError('');
        }
    };

    /* ── Render ──────────────────────────────────────────────────────── */
    return (
        <div className="app-wrapper">
            <div className="content-wrapper">

                {/* ── Title ── */}
                <header className="hero-header">
                    <h1 className="hero-title">BinExplain</h1>
                    <p className="hero-subtitle">
                        Secure, sandboxed static analysis for binary executables.
                        Upload a binary to extract strings, detect CTF flags, and get AI-powered hints.
                    </p>
                </header>

                {/* ── Mode Toggle ── */}
                <div className="mode-toggle">
                    <button
                        className={`mode-btn ${analysisMode === 'binary' ? 'active' : ''}`}
                        onClick={() => switchMode('binary')}
                    >
                        🔬 Binary Analysis
                    </button>
                    <button
                        className={`mode-btn ${analysisMode === 'source' ? 'active' : ''}`}
                        onClick={() => switchMode('source')}
                    >
                        📝 Source Code Analysis
                    </button>
                </div>

                {analysisMode === 'binary' ? (
                    <>
                        {/* ── VirusTotal Disclaimer (always visible before upload) ── */}
                        <div className="vt-disclaimer" id="vt-disclaimer">
                            <span className="vt-disclaimer-icon">⚠️</span>
                            <span>
                                Files submitted to VirusTotal are stored permanently in their database.
                                Do not upload sensitive or private binaries.
                            </span>
                        </div>

                {/* ── Upload Zone ── */}
                <section>
                    <div
                        className={`dropzone-wrapper${dragOver ? ' drag-over' : ''}`}
                        onDragOver={onDragOver}
                        onDragLeave={onDragLeave}
                        onDrop={onDrop}
                    >
                        <div className="dropzone-border" />
                        <div
                            className={`dropzone-inner${loading ? ' disabled' : ''}`}
                            onClick={() => inputRef.current?.click()}
                            role="button"
                            tabIndex={0}
                            aria-label="Upload a binary file"
                        >
                            <div className="dropzone-icon-container">
                                <span className="material-symbols-outlined dropzone-icon">cloud_upload</span>
                                <div className="dropzone-icon-badge">
                                    <span className="material-symbols-outlined">add</span>
                                </div>
                            </div>
                            <h3 className="dropzone-title">Drag &amp; Drop Binary</h3>
                            <p className="dropzone-desc">
                                Drop your binary file here for analysis. Maximum file size:{' '}
                                <span className="highlight">5MB</span>
                            </p>
                            <div className="format-badges">
                                <span className="format-badge">.ELF</span>
                                <span className="format-badge">.EXE</span>
                                <span className="format-badge">.BIN</span>
                                <span className="format-badge">.SO</span>
                                <span className="format-badge">.DLL</span>
                                <span className="format-badge">.ZIP</span>
                                <span className="format-badge">No Ext</span>
                            </div>
                            <button
                                className="browse-btn"
                                onClick={(e) => {
                                    e.stopPropagation();
                                    inputRef.current?.click();
                                }}
                                type="button"
                            >
                                Browse Files
                            </button>
                            <input
                                ref={inputRef}
                                type="file"
                                className="file-input"
                                onChange={onFileChange}
                            />
                        </div>
                    </div>
                </section>

                {/* ── Staged File Bar ── */}
                {file && !loading && (
                    <div className="staged-file-bar">
                        <div className="staged-file-info">
                            <span className="material-symbols-outlined">description</span>
                            <span>{file.name} ({formatBytes(file.size)})</span>
                        </div>
                        <button className="staged-file-remove" onClick={clearFile} title="Remove file">
                            <span className="material-symbols-outlined">close</span>
                        </button>
                    </div>
                )}

                {/* ── VirusTotal Checkbox ── */}
                {file && !loading && (
                    <div className="vt-checkbox-wrapper">
                        <label className="vt-checkbox-label" htmlFor="vt-checkbox">
                            <input
                                type="checkbox"
                                id="vt-checkbox"
                                checked={submitToVt}
                                onChange={e => setSubmitToVt(e.target.checked)}
                            />
                            🛡️ Submit to VirusTotal <span className="vt-checkbox-hint">(disable for CTF challenges)</span>
                        </label>
                    </div>
                )}

                {/* ── Analyze Button ── */}
                {file && !loading && (
                    <button className="analyze-btn" onClick={upload}>
                        ▶ Analyze File
                    </button>
                )}

                {/* ── Loading ── */}
                {loading && (
                    <div className="terminal-loading">
                        <div className="terminal-line">
                            <span className="prompt">&gt;</span>
                            <span className="text">{loadingMsg}</span>
                            <span className="cursor-blink" />
                        </div>
                    </div>
                )}

                {/* ── Error ── */}
                {error && (
                    <div className={`error-box ${rateLimitSeconds > 0 ? 'error-box--rate-limit' : ''}`} id="error-display">
                        <div className="error-text">{error}</div>
                        {rateLimitSeconds > 0 && (
                            <div className="error-countdown">
                                ⏱️ Retry in: {Math.floor(rateLimitSeconds / 60)}:{String(rateLimitSeconds % 60).padStart(2, '0')}
                            </div>
                        )}
                    </div>
                )}
                </>
                ) : (
                    <>
                        {/* ── Source Code Upload & Paste Zone ── */}
                        <section className="source-input-section">
                            <div className="source-upload-wrapper">
                                <div
                                    className="dropzone-inner source-dropzone"
                                    onClick={() => sourceInputRef.current?.click()}
                                    role="button"
                                    tabIndex={0}
                                >
                                    <div className="dropzone-icon-container">
                                        <span className="material-symbols-outlined dropzone-icon">code</span>
                                    </div>
                                    <h3 className="dropzone-title">Upload Source File</h3>
                                    <p className="dropzone-desc">
                                        Accepted: {SOURCE_CODE_EXTENSIONS.join(', ')}
                                    </p>
                                    <input
                                        ref={sourceInputRef}
                                        type="file"
                                        className="file-input"
                                        onChange={(e) => stageSourceFile(e.target.files[0])}
                                    />
                                </div>
                                {sourceFile && (
                                    <div className="staged-file-bar source-staged">
                                        <div className="staged-file-info">
                                            <span className="material-symbols-outlined">description</span>
                                            <span>{sourceFile.name}</span>
                                        </div>
                                        <button className="staged-file-remove" onClick={() => { setSourceFile(null); setSourceCode(''); }} title="Remove file">
                                            <span className="material-symbols-outlined">close</span>
                                        </button>
                                    </div>
                                )}
                            </div>

                            <div className="source-divider"><span>OR PASTE CODE</span></div>

                            <div className="source-textarea-wrapper">
                                <textarea
                                    className="source-textarea"
                                    placeholder="Paste your C, Python, JavaScript, Rust, or Go code here..."
                                    value={sourceCode}
                                    onChange={(e) => setSourceCode(e.target.value)}
                                    maxLength={MAX_SOURCE_CODE_CHARS}
                                />
                                <div className="char-counter">
                                    {sourceCode.length} / {MAX_SOURCE_CODE_CHARS}
                                </div>
                            </div>
                            
                            <button 
                                className="analyze-btn" 
                                onClick={analyzeSourceCode} 
                                disabled={sourceLoading || (!sourceCode.trim() && !sourceFile)}
                            >
                                {sourceLoading ? 'Analyzing...' : '▶ Analyze Code'}
                            </button>

                            {sourceLoading && (
                                <div className="terminal-loading">
                                    <div className="terminal-line">
                                        <span className="prompt">&gt;</span>
                                        <span className="text">Analyzing source code...</span>
                                        <span className="cursor-blink" />
                                    </div>
                                </div>
                            )}

                            {sourceError && (
                                <div className="error-box">
                                    <div className="error-text">{sourceError}</div>
                                </div>
                            )}
                        </section>
                    </>
                )}

                {/* ═══ Binary Results ═══ */}
                {analysisMode === 'binary' && result && (
                    <>
                        {/* File info bar */}
                        <div className="analysis-meta-bar">
                            <div className="meta-item">
                                <span className="meta-label">File:</span>
                                <span style={{ fontFamily: 'Courier New, monospace', fontSize: 13, color: 'var(--on-surface)' }}>
                                    {result.filename}
                                </span>
                            </div>
                            <div className="meta-item">
                                <span className="meta-label">Size:</span>
                                <span style={{ fontFamily: 'Courier New, monospace', fontSize: 13, color: 'var(--on-surface-variant)' }}>
                                    {formatBytes(result.size_bytes)}
                                </span>
                            </div>
                            <div className="meta-item">
                                <span className="meta-label">Strings:</span>
                                <span style={{ fontFamily: 'Courier New, monospace', fontSize: 13, color: 'var(--primary)' }}>
                                    {result.strings_count}
                                </span>
                            </div>
                        </div>

                        {/* ── Accordion Results Stack ── */}
                        <div className="accordion-stack">

                            {/* 🎯 CTF Category — prominently at top */}
                            {result.ctf_category && result.ctf_category.category !== 'unknown' && (
                                <AccordionCard
                                    id="ctf-category"
                                    icon="🎯"
                                    title="CTF Category"
                                    summary={`${result.ctf_category.category.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())} — ${result.ctf_category.confidence} confidence`}
                                    open={openSections.ctfCategory}
                                    onToggle={() => toggleSection('ctfCategory')}
                                    variant={`ctf-${result.ctf_category.confidence.toLowerCase()}`}
                                >
                                    <div className="ctf-category-card">
                                        <div className="ctf-category-header">
                                            <span className={`ctf-category-badge ctf-category-badge--${result.ctf_category.confidence.toLowerCase()}`}>
                                                {result.ctf_category.category.replace(/_/g, ' ').toUpperCase()}
                                            </span>
                                            <span className={`ctf-confidence-badge ctf-confidence-badge--${result.ctf_category.confidence.toLowerCase()}`}>
                                                {result.ctf_category.confidence} Confidence
                                            </span>
                                        </div>
                                        <p className="ctf-category-explanation">{result.ctf_category.explanation}</p>
                                    </div>
                                </AccordionCard>
                            )}

                            {/* 📊 CVSS Score */}
                            {result.cvss_score !== undefined && (
                                <AccordionCard
                                    id="cvss-score"
                                    icon="📊"
                                    title="CVSS 3.1 Scoring"
                                    summary={`${result.cvss_score}/10.0 ${result.cvss_severity}`}
                                    open={openSections.cvss}
                                    onToggle={() => toggleSection('cvss')}
                                    variant={`cvss-${result.cvss_severity.toLowerCase()}`}
                                >
                                    <div className={`risk-card risk-card--${result.cvss_severity.toLowerCase()}`}>
                                        <div className="risk-header">
                                            <div className="risk-score-circle">
                                                <span className="risk-score-number">{result.cvss_score}</span>
                                                <span className="risk-score-max">/10.0</span>
                                            </div>
                                            <div className="risk-info">
                                                <span className={`risk-badge risk-badge--${result.cvss_severity.toLowerCase()}`}>
                                                    {result.cvss_severity}
                                                </span>
                                                <span className="risk-label">Base Score Equivalent</span>
                                            </div>
                                        </div>
                                        <div className="risk-bar-track">
                                            <div
                                                className={`risk-bar-fill risk-bar-fill--${result.cvss_severity.toLowerCase()}`}
                                                style={{ width: `${(result.cvss_score / 10.0) * 100}%` }}
                                            />
                                        </div>
                                    </div>
                                </AccordionCard>
                            )}

                            {/* 📜 Function List */}
                            {result.function_list && result.function_list.length > 0 && (
                                <AccordionCard
                                    id="function-list"
                                    icon="📜"
                                    title="Function List"
                                    summary={`${result.function_list.length} functions`}
                                    open={openSections.functions}
                                    onToggle={() => toggleSection('functions')}
                                    variant="functions"
                                >
                                    <div className="table-container">
                                        <table className="info-table">
                                            <thead><tr><th>Address</th><th>Size</th><th>Name</th></tr></thead>
                                            <tbody>
                                                {result.function_list.map((fn, i) => (
                                                    <tr key={i}>
                                                        <td style={{fontFamily: 'monospace', color: 'var(--primary)'}}>{fn.address}</td>
                                                        <td style={{color: 'var(--on-surface-variant)'}}>{fn.size}</td>
                                                        <td>{fn.name}</td>
                                                    </tr>
                                                ))}
                                            </tbody>
                                        </table>
                                    </div>
                                </AccordionCard>
                            )}

                            {/* 🚪 Imports / Exports */}
                            {(result.imports_exports?.imports?.length > 0 || result.imports_exports?.exports?.length > 0) && (
                                <AccordionCard
                                    id="imports-exports"
                                    icon="🚪"
                                    title="Imports & Exports"
                                    summary={`${result.imports_exports.imports.length} imports, ${result.imports_exports.exports.length} exports`}
                                    open={openSections.imports}
                                    onToggle={() => toggleSection('imports')}
                                    variant="imports"
                                >
                                    <div className="two-column-layout">
                                        <div className="column">
                                            <h4 className="column-title">Imports</h4>
                                            <ul className="info-list">
                                                {result.imports_exports.imports.map((imp, i) => <li key={i}>{imp}</li>)}
                                            </ul>
                                        </div>
                                        <div className="column">
                                            <h4 className="column-title">Exports</h4>
                                            <ul className="info-list">
                                                {result.imports_exports.exports.map((exp, i) => <li key={i}>{exp}</li>)}
                                            </ul>
                                        </div>
                                    </div>
                                </AccordionCard>
                            )}

                            {/* 🌊 Data Flow Analysis */}
                            {result.data_flows && result.data_flows.length > 0 && (
                                <AccordionCard
                                    id="data-flows"
                                    icon="🌊"
                                    title="Data Flow Analysis"
                                    summary={`${result.data_flows.length} flows`}
                                    open={openSections.dataFlows}
                                    onToggle={() => toggleSection('dataFlows')}
                                    variant="data-flows"
                                >
                                    <ul className="data-flow-list">
                                        {result.data_flows.map((flow, i) => (
                                            <li key={i} className="data-flow-item">{flow}</li>
                                        ))}
                                    </ul>
                                </AccordionCard>
                            )}

                            {/* 🔒 Security Protections */}
                            {result.checksec && result.checksec.nx !== null && (
                                <AccordionCard
                                    id="checksec-results"
                                    icon="🔒"
                                    title="Security Protections"
                                    summary={checksecSummary}
                                    open={openSections.checksec}
                                    onToggle={() => toggleSection('checksec')}
                                    variant="checksec"
                                >
                                    <div className="checksec-badges">
                                        {[
                                            { key: 'nx', label: 'NX', desc: 'No-Execute' },
                                            { key: 'pie', label: 'PIE', desc: 'Position Independent' },
                                            { key: 'canary', label: 'Canary', desc: 'Stack Canary' },
                                            { key: 'relro', label: 'RELRO', desc: 'Read-Only Relocations' },
                                            { key: 'fortify', label: 'Fortify', desc: 'Fortify Source' },
                                        ].map(({ key, label, desc }) => (
                                            <div
                                                className={`checksec-badge checksec-badge--${result.checksec[key] ? 'enabled' : 'disabled'}`}
                                                key={key}
                                                title={desc}
                                            >
                                                <span className="checksec-badge-icon">
                                                    {result.checksec[key] ? '✓' : '✗'}
                                                </span>
                                                <span className="checksec-badge-label">{label}</span>
                                                <span className="checksec-badge-status">
                                                    {result.checksec[key] ? 'Enabled' : 'Disabled'}
                                                </span>
                                            </div>
                                        ))}
                                    </div>
                                </AccordionCard>
                            )}

                            {/* 🔗 ROP Gadgets */}
                            {result.rop_gadgets && result.rop_gadgets.length > 0 && (
                                <AccordionCard
                                    id="rop-gadgets"
                                    icon="🔗"
                                    title="ROP Gadgets"
                                    summary={`${result.rop_gadgets.length} gadget${result.rop_gadgets.length !== 1 ? 's' : ''} found`}
                                    open={openSections.ropGadgets}
                                    onToggle={() => toggleSection('ropGadgets')}
                                    variant="rop"
                                >
                                    <div className="table-container">
                                        <table className="info-table">
                                            <thead><tr><th>Address</th><th>Gadget</th></tr></thead>
                                            <tbody>
                                                {result.rop_gadgets.map((g, i) => (
                                                    <tr key={i}>
                                                        <td style={{fontFamily: 'monospace', color: 'var(--primary)'}}>{g.address}</td>
                                                        <td style={{fontFamily: 'monospace'}}>{g.gadget}</td>
                                                    </tr>
                                                ))}
                                            </tbody>
                                        </table>
                                    </div>
                                </AccordionCard>
                            )}

                            {/* ⚠️ Format String */}
                            {result.format_string && (
                                <AccordionCard
                                    id="format-string"
                                    icon="⚠️"
                                    title="Format String"
                                    summary={result.format_string.vulnerable ? `Vulnerable — ${result.format_string.severity}` : 'Safe'}
                                    open={openSections.formatString}
                                    onToggle={() => toggleSection('formatString')}
                                    variant={result.format_string.vulnerable ? `fmtstr-${result.format_string.severity.toLowerCase()}` : 'fmtstr-safe'}
                                >
                                    <div className="fmtstr-card">
                                        <div className="fmtstr-header">
                                            <span className={`fmtstr-badge fmtstr-badge--${result.format_string.vulnerable ? result.format_string.severity.toLowerCase() : 'safe'}`}>
                                                {result.format_string.vulnerable ? `⚠ VULNERABLE — ${result.format_string.severity}` : '✓ SAFE'}
                                            </span>
                                        </div>
                                        {result.format_string.evidence.length > 0 && (
                                            <ul className="fmtstr-evidence">
                                                {result.format_string.evidence.map((e, i) => (
                                                    <li key={i} className="fmtstr-evidence-item">{e}</li>
                                                ))}
                                            </ul>
                                        )}
                                    </div>
                                </AccordionCard>
                            )}

                            {/* 📚 Libc Info */}
                            {result.libc_info && result.libc_info.glibc_version && (
                                <AccordionCard
                                    id="libc-info"
                                    icon="📚"
                                    title="Libc Info"
                                    summary={`GLIBC ${result.libc_info.glibc_version} — ${result.libc_info.likely_os}`}
                                    open={openSections.libcInfo}
                                    onToggle={() => toggleSection('libcInfo')}
                                    variant="libc"
                                >
                                    <div className="libc-card">
                                        <div className="libc-row">
                                            <span className="libc-label">GLIBC Version</span>
                                            <span className="libc-value">{result.libc_info.glibc_version}</span>
                                        </div>
                                        {result.libc_info.all_versions.length > 1 && (
                                            <div className="libc-row">
                                                <span className="libc-label">All Versions</span>
                                                <span className="libc-value">{result.libc_info.all_versions.join(', ')}</span>
                                            </div>
                                        )}
                                        <div className="libc-row">
                                            <span className="libc-label">Likely OS</span>
                                            <span className="libc-value libc-value--os">{result.libc_info.likely_os}</span>
                                        </div>
                                        {result.libc_info.gcc_version && (
                                            <div className="libc-row">
                                                <span className="libc-label">GCC Version</span>
                                                <span className="libc-value">{result.libc_info.gcc_version}</span>
                                            </div>
                                        )}
                                        {result.libc_info.libc_db_url && (
                                            <div className="libc-row">
                                                <span className="libc-label">Libc Database</span>
                                                <a
                                                    href={result.libc_info.libc_db_url}
                                                    target="_blank"
                                                    rel="noopener noreferrer"
                                                    className="libc-link"
                                                >
                                                    🔍 Search libc.blukat.me →
                                                </a>
                                            </div>
                                        )}
                                    </div>
                                </AccordionCard>
                            )}

                            {/* 🔐 Encodings Detected */}
                            {result.encodings && Object.keys(result.encodings).length > 0 && (
                                <AccordionCard
                                    id="encodings-card"
                                    icon="🔐"
                                    title="Encodings Detected"
                                    summary={`${Object.values(result.encodings).flat().length} match${Object.values(result.encodings).flat().length !== 1 ? 'es' : ''}`}
                                    open={openSections.encodings}
                                    onToggle={() => toggleSection('encodings')}
                                    variant="encodings"
                                >
                                    {Object.entries(result.encodings).map(([category, items]) => (
                                        <div className="finding-category" key={category}>
                                            <span className="finding-label">
                                                {category === 'base64' && '📦 Base64'}
                                                {category === 'hex_strings' && '🔢 Hex Strings'}
                                                {category === 'xor_hints' && '🔑 XOR / Encryption'}
                                                {category === 'rot13_flags' && '🔄 ROT13 Hidden Flags'}
                                            </span>
                                            {items.map((item, j) => (
                                                <div className="section-item section-item--encoding" key={j}>{item}</div>
                                            ))}
                                        </div>
                                    ))}
                                </AccordionCard>
                            )}

                            {/* 🛡️ VirusTotal */}
                            {submitToVt && (vtResult || vtScanId) && result.virustotal?.status !== 'disabled' && (
                                <AccordionCard
                                    id="vt-results"
                                    icon="🛡️"
                                    title="VirusTotal Scan"
                                    summary={
                                        !vtResult ? 'Scanning...' :
                                        vtResult.status === 'pending' ? 'Analysis in progress' :
                                        vtResult.status === 'error' ? 'Scan error' :
                                        vtResult.status === 'clean' ? `0/${vtResult.total_engines} engines flagged` :
                                        `${vtResult.detection_count}/${vtResult.total_engines} engines flagged`
                                    }
                                    open={openSections.vt}
                                    onToggle={() => toggleSection('vt')}
                                    variant={`vt-${vtResult?.status || 'scanning'}`}
                                >
                                    {/* Scanning spinner */}
                                    {!vtResult && (
                                        <div className="vt-scanning" id="vt-scanning">
                                            <div className="vt-spinner" />
                                            <span className="vt-scanning-text">Scanning across 70+ engines...</span>
                                        </div>
                                    )}

                                    {/* Error */}
                                    {vtResult?.status === 'error' && (
                                        <div className="section-empty" style={{ color: 'var(--error)' }}>
                                            {vtResult.message || 'VirusTotal scan encountered an error.'}
                                        </div>
                                    )}

                                    {/* Pending */}
                                    {vtResult?.status === 'pending' && (
                                        <div className="vt-pending">
                                            <div className="vt-pending-text">
                                                ⏳ {vtResult.message || 'Analysis is still in progress.'}
                                            </div>
                                            {vtResult.permalink && (
                                                <a href={vtResult.permalink} target="_blank" rel="noopener noreferrer" className="vt-link" id="vt-permalink">
                                                    View on VirusTotal →
                                                </a>
                                            )}
                                        </div>
                                    )}

                                    {/* Completed results */}
                                    {vtResult && ['clean', 'suspicious', 'malicious'].includes(vtResult.status) && (
                                        <div className="vt-results-body">
                                            <div className="vt-detection-row">
                                                <div className={`vt-ratio vt-ratio--${vtResult.status}`}>
                                                    <span className="vt-ratio-count">{vtResult.detection_count}</span>
                                                    <span className="vt-ratio-separator">/</span>
                                                    <span className="vt-ratio-total">{vtResult.total_engines}</span>
                                                </div>
                                                <div className="vt-detection-info">
                                                    <span className={`vt-verdict vt-verdict--${vtResult.status}`}>
                                                        {vtResult.status === 'clean' && `✅ Clean — 0 / ${vtResult.total_engines} engines flagged`}
                                                        {vtResult.status === 'suspicious' && `⚠️ Suspicious — ${vtResult.detection_count} / ${vtResult.total_engines} engines flagged`}
                                                        {vtResult.status === 'malicious' && `🚨 Malicious — ${vtResult.detection_count} / ${vtResult.total_engines} engines flagged`}
                                                    </span>
                                                </div>
                                            </div>
                                            <div className="vt-bar-track">
                                                <div
                                                    className={`vt-bar-fill vt-bar-fill--${vtResult.status}`}
                                                    style={{
                                                        width: vtResult.total_engines > 0
                                                            ? `${(vtResult.detection_count / vtResult.total_engines) * 100}%`
                                                            : '0%'
                                                    }}
                                                />
                                            </div>
                                            {vtResult.threat_name && (
                                                <div className="vt-threat">
                                                    <span className="vt-threat-label">Threat:</span>
                                                    <span className="vt-threat-name">{vtResult.threat_name}</span>
                                                </div>
                                            )}
                                            {vtResult.behavior_summary && (
                                                <div className="vt-behavior">{vtResult.behavior_summary}</div>
                                            )}
                                            {vtResult.permalink && (
                                                <a href={vtResult.permalink} target="_blank" rel="noopener noreferrer" className="vt-link" id="vt-permalink">
                                                    View Full Report →
                                                </a>
                                            )}
                                        </div>
                                    )}
                                </AccordionCard>
                            )}

                            {/* 🔍 Hex View */}
                            {result.hex_view && result.hex_view.length > 0 && (
                                <AccordionCard
                                    id="hex-viewer"
                                    icon="🔍"
                                    title="Hex View"
                                    summary={`First ${result.hex_view.length * 16} bytes`}
                                    open={openSections.hex}
                                    onToggle={() => toggleSection('hex')}
                                    variant="hex"
                                >
                                    <div className="hex-viewer-body">
                                        <div className="hex-row hex-row--header">
                                            <span className="hex-col-offset">Offset</span>
                                            <span className="hex-col-hex">00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f</span>
                                            <span className="hex-col-ascii">ASCII</span>
                                        </div>
                                        {result.hex_view.map((row, i) => (
                                            <div className="hex-row" key={i}>
                                                <span className="hex-col-offset">{row.offset}</span>
                                                <span className="hex-col-hex">{row.hex}</span>
                                                <span className="hex-col-ascii">{row.ascii}</span>
                                            </div>
                                        ))}
                                    </div>
                                </AccordionCard>
                            )}

                            {/* 🔬 Disassembly */}
                            {result.disassembly && result.disassembly.length > 0 && (
                                <AccordionCard
                                    id="disasm-viewer"
                                    icon="🔬"
                                    title="Disassembly"
                                    summary={`${result.disassembly_function || 'main'}\u00a0— ${result.disassembly.length} instructions`}
                                    open={openSections.disasm}
                                    onToggle={() => toggleSection('disasm')}
                                    variant="disasm"
                                >
                                    <div className="disasm-body">
                                        <div className="disasm-row disasm-row--header">
                                            <span className="disasm-col-addr">Address</span>
                                            <span className="disasm-col-mnemonic">Mnemonic</span>
                                            <span className="disasm-col-operands">Operands</span>
                                        </div>
                                        {result.disassembly.map((insn, i) => {
                                            const mn = insn.mnemonic.toLowerCase();
                                            const isDangerous = ['call', 'jmp', 'je', 'jne', 'jz', 'jnz', 'jg', 'jl', 'jge', 'jle', 'ja', 'jb', 'ret', 'retn', 'syscall', 'int'].includes(mn);
                                            const isPrologue = (mn === 'push' && insn.op_str.match(/[re]bp/)) ||
                                                               (mn === 'mov' && insn.op_str.match(/[re]bp,\s*[re]sp/)) ||
                                                               (mn === 'endbr64' || mn === 'endbr32');
                                            return (
                                                <div
                                                    className={`disasm-row ${isDangerous ? 'disasm-row--danger' : ''} ${isPrologue ? 'disasm-row--prologue' : ''}`}
                                                    key={i}
                                                >
                                                    <span className="disasm-col-addr">{insn.address}</span>
                                                    <span className={`disasm-col-mnemonic ${isDangerous ? 'disasm-mnemonic--danger' : ''} ${isPrologue ? 'disasm-mnemonic--prologue' : ''}`}>{insn.mnemonic}</span>
                                                    <span className="disasm-col-operands">{insn.op_str || ''}</span>
                                                </div>
                                            );
                                        })}
                                    </div>
                                </AccordionCard>
                            )}

                            {/* 📋 Strings */}
                            <AccordionCard
                                id="strings-card"
                                icon="📋"
                                title="Strings"
                                summary={`${result.strings_count} string${result.strings_count !== 1 ? 's' : ''} extracted`}
                                open={openSections.strings}
                                onToggle={() => toggleSection('strings')}
                                variant="strings"
                            >
                                <div className="result-card-body">
                                    {result.strings.length === 0 ? (
                                        <div className="no-strings">No printable strings found.</div>
                                    ) : (
                                        result.strings.map((s, i) => (
                                            <div className="string-line" key={i}>
                                                <span className="string-index">{String(i + 1).padStart(4, '0')}</span>
                                                {s}
                                            </div>
                                        ))
                                    )}
                                </div>
                            </AccordionCard>

                            {/* 🚩 Flags Detected */}
                            <AccordionCard
                                id="flags-card"
                                icon="🚩"
                                title="Flags Detected"
                                summary={
                                    result.flags_detected && result.flags_detected.length > 0
                                        ? `${result.flags_detected.length} flag${result.flags_detected.length !== 1 ? 's' : ''} found`
                                        : 'None detected'
                                }
                                open={openSections.flags}
                                onToggle={() => toggleSection('flags')}
                                variant="flags"
                            >
                                <div className="result-card-body">
                                    {result.flags_detected && result.flags_detected.length > 0 ? (
                                        result.flags_detected.map((flag, i) => (
                                            <div className="section-item section-item--flag" key={i}>{flag}</div>
                                        ))
                                    ) : (
                                        <div className="section-empty">No flags detected in strings</div>
                                    )}
                                </div>
                            </AccordionCard>

                            {/* 🔍 Interesting Findings */}
                            <AccordionCard
                                id="findings-card"
                                icon="🔍"
                                title="Interesting Findings"
                                summary={
                                    result.patterns && Object.keys(result.patterns).length > 0
                                        ? `${Object.keys(result.patterns).length} categor${Object.keys(result.patterns).length !== 1 ? 'ies' : 'y'}`
                                        : 'No patterns'
                                }
                                open={openSections.findings}
                                onToggle={() => toggleSection('findings')}
                                variant="findings"
                            >
                                <div className="result-card-body">
                                    {result.patterns && Object.keys(result.patterns).length > 0 ? (
                                        Object.entries(result.patterns).map(([category, items]) => (
                                            <div className="finding-category" key={category}>
                                                <span className="finding-label">{category.replace(/_/g, ' ')}:</span>
                                                {items.map((item, j) => (
                                                    <div className="section-item section-item--finding" key={j}>{item}</div>
                                                ))}
                                            </div>
                                        ))
                                    ) : (
                                        <div className="section-empty">No interesting patterns detected</div>
                                    )}
                                </div>
                            </AccordionCard>

                            {/* ⚡ Pwntools Template */}
                            {result.pwn_template && result.extension !== '.zip' && (
                                <AccordionCard
                                    id="pwn-template"
                                    icon="⚡"
                                    title="Pwntools Template"
                                    summary="Ready to download"
                                    open={openSections.pwn}
                                    onToggle={() => toggleSection('pwn')}
                                    variant="pwn"
                                >
                                    <div className="pwn-template-actions">
                                        <button
                                            className="pwn-action-btn"
                                            onClick={() => {
                                                navigator.clipboard.writeText(result.pwn_template);
                                                const btn = document.getElementById('pwn-copy-btn');
                                                if (btn) { btn.textContent = '✓ Copied!'; setTimeout(() => btn.textContent = '📋 Copy Template', 1500); }
                                            }}
                                            id="pwn-copy-btn"
                                            type="button"
                                        >
                                            📋 Copy Template
                                        </button>
                                        <button
                                            className="pwn-action-btn"
                                            onClick={() => {
                                                const blob = new Blob([result.pwn_template], { type: 'text/x-python' });
                                                const url = URL.createObjectURL(blob);
                                                const a = document.createElement('a');
                                                a.href = url;
                                                a.download = 'exploit.py';
                                                a.click();
                                                URL.revokeObjectURL(url);
                                            }}
                                            id="pwn-download-btn"
                                            type="button"
                                        >
                                            ⬇️ Download exploit.py
                                        </button>
                                    </div>
                                    <div className="pwn-template-body">
                                        <pre className="pwn-code">{result.pwn_template.split('\n').map((line, i) => (
                                            <div className="pwn-line" key={i}>
                                                <span className="pwn-line-num">{String(i + 1).padStart(3, ' ')}</span>
                                                <span className={`pwn-line-text${
                                                    line.trimStart().startsWith('#') ? ' pwn-comment' :
                                                    line.includes('from pwn') || line.includes('#!/') ? ' pwn-import' :
                                                    line.includes('def ') ? ' pwn-func' :
                                                    /\b(flat|process|remote|cyclic|asm|shellcraft|ELF|ROP)\b/.test(line) ? ' pwn-keyword' :
                                                    ''
                                                }`}>{line || ' '}</span>
                                            </div>
                                        ))}</pre>
                                    </div>
                                </AccordionCard>
                            )}

                            {/* 💡 AI Hints + Kill Chain — open by default */}
                            <AccordionCard
                                id="ai-hints"
                                icon="💡"
                                title="AI Hints + Kill Chain"
                                summary={result.hints ? 'Analysis available' : 'Unavailable'}
                                open={openSections.hints}
                                onToggle={() => toggleSection('hints')}
                                variant="hints"
                            >
                                <div className="result-card-body">
                                    {result.hints ? (
                                        result.hints.split(/\n/).filter(line => line.trim()).map((line, i) => (
                                            <div className="section-item section-item--hint" key={i}>{line}</div>
                                        ))
                                    ) : (
                                        <div className="section-empty">AI hints unavailable</div>
                                    )}

                                    {/* Thumbs Up / Down Feedback */}
                                    {result.hints && (
                                        <div className="hints-feedback" id="hints-feedback">
                                            {feedbackGiven ? (
                                                <div className="hints-feedback-thanks">✅ Thanks for your feedback!</div>
                                            ) : (
                                                <>
                                                    <span className="hints-feedback-label">Were these hints helpful?</span>
                                                    <button
                                                        className="hints-feedback-btn hints-feedback-btn--up"
                                                        onClick={async () => {
                                                            setFeedbackGiven('up');
                                                            try {
                                                                await fetch(`${BACKEND_URL}/feedback`, {
                                                                    method: 'POST',
                                                                    headers: { 'Content-Type': 'application/json' },
                                                                    body: JSON.stringify({ vote: 'up', filename: result.filename }),
                                                                });
                                                            } catch { /* silent */ }
                                                        }}
                                                        type="button"
                                                        id="feedback-up-btn"
                                                    >
                                                        👍 Helpful
                                                    </button>
                                                    <button
                                                        className="hints-feedback-btn hints-feedback-btn--down"
                                                        onClick={async () => {
                                                            setFeedbackGiven('down');
                                                            try {
                                                                await fetch(`${BACKEND_URL}/feedback`, {
                                                                    method: 'POST',
                                                                    headers: { 'Content-Type': 'application/json' },
                                                                    body: JSON.stringify({ vote: 'down', filename: result.filename }),
                                                                });
                                                            } catch { /* silent */ }
                                                        }}
                                                        type="button"
                                                        id="feedback-down-btn"
                                                    >
                                                        👎 Not helpful
                                                    </button>
                                                </>
                                            )}
                                        </div>
                                    )}
                                </div>
                            </AccordionCard>

                            {/* 💬 Follow-up Chat — open by default */}
                            <AccordionCard
                                id="chat-section"
                                icon="💬"
                                title="Follow-up Chat"
                                summary={chatMessages.length > 0 ? `${chatMessages.length} message${chatMessages.length !== 1 ? 's' : ''}` : 'Ask questions'}
                                open={openSections.chat}
                                onToggle={() => toggleSection('chat')}
                                variant="chat"
                            >
                                <div className="chat-messages" id="chat-messages">
                                    {chatMessages.map((msg, i) => (
                                        <div
                                            className={`chat-bubble chat-bubble--${msg.role}`}
                                            key={i}
                                        >
                                            <span className="chat-bubble-label">
                                                {msg.role === 'user' ? 'You' : 'AI Mentor'}
                                            </span>
                                            {msg.image && (
                                                <img src={msg.image} alt="Attached screenshot" className="chat-image-preview-bubble" />
                                            )}
                                            <div className="chat-bubble-content">
                                                {msg.content.split(/\n/).filter(l => l.trim()).map((line, j) => (
                                                    <div key={j}>{line}</div>
                                                ))}
                                            </div>
                                        </div>
                                    ))}
                                    {chatLoading && (
                                        <div className="chat-bubble chat-bubble--assistant">
                                            <span className="chat-bubble-label">AI Mentor</span>
                                            <div className="chat-bubble-content">
                                                <span className="chat-typing">Thinking<span className="chat-dots">...</span></span>
                                            </div>
                                        </div>
                                    )}
                                    <div ref={chatEndRef} />
                                </div>
                                {/* Image preview bar */}
                                {chatImage && (
                                    <div className="chat-image-bar">
                                        <img src={chatImagePreview} alt="Preview" className="chat-image-thumb" />
                                        <span className="chat-image-name">{chatImage.name}</span>
                                        <button className="chat-image-remove" onClick={clearChatImage} title="Remove image">
                                            <span className="material-symbols-outlined">close</span>
                                        </button>
                                    </div>
                                )}
                                <div className="chat-input-row">
                                    <button
                                        className="chat-image-btn"
                                        onClick={() => chatImageRef.current?.click()}
                                        disabled={chatLoading}
                                        title="Attach screenshot"
                                        type="button"
                                    >
                                        📷
                                    </button>
                                    <input
                                        ref={chatImageRef}
                                        type="file"
                                        accept="image/png,image/jpeg,image/gif,image/webp"
                                        onChange={onChatImageSelect}
                                        style={{ display: 'none' }}
                                    />
                                    <input
                                        className="chat-input"
                                        type="text"
                                        placeholder={chatImage ? 'Add a message about your screenshot...' : 'Ask about this binary...'}
                                        value={chatInput}
                                        onChange={e => setChatInput(e.target.value.slice(0, MAX_CHAT_CHARS))}
                                        onKeyDown={onChatKeyDown}
                                        disabled={chatLoading}
                                        maxLength={MAX_CHAT_CHARS}
                                        id="chat-input"
                                    />
                                    <button
                                        className="chat-send-btn"
                                        onClick={sendChat}
                                        disabled={chatLoading || (!chatInput.trim() && !chatImage)}
                                        id="chat-send-btn"
                                    >
                                        {chatLoading ? '...' : '▶ Send'}
                                    </button>
                                </div>
                            </AccordionCard>
                        </div>
                    </>
                )}

                {/* ═══ Source Code Results ═══ */}
                {analysisMode === 'source' && sourceResult && (
                    <>
                        <div className="analysis-meta-bar">
                            <div className="meta-item">
                                <span className="meta-label">File:</span>
                                <span style={{ fontFamily: 'Courier New, monospace', fontSize: 13, color: 'var(--on-surface)' }}>
                                    {sourceResult.filename}
                                </span>
                            </div>
                            <div className="meta-item">
                                <span className="meta-label">Code:</span>
                                <span>{sourceResult.line_count} lines ({formatBytes(sourceResult.char_count)})</span>
                            </div>
                        </div>

                        <div className="accordion-stack">
                            {/* 1. Language */}
                            <AccordionCard
                                title="Language Detected"
                                icon="language"
                                sectionKey="srcLang"
                                summary={sourceResult.language}
                                variant="source-lang"
                                openSections={openSections}
                                toggleSection={toggleSection}
                            >
                                <div className="section-padding">
                                    <p>Identified via static heuristic matching.</p>
                                    {sourceResult.risk_score && (
                                        <p><strong>Risk Score:</strong> <span className={`risk-badge risk-badge--${sourceResult.risk_score.toLowerCase()}`}>{sourceResult.risk_score}</span></p>
                                    )}
                                </div>
                            </AccordionCard>

                            {/* 2. Vulnerabilities */}
                            <AccordionCard
                                title="Vulnerabilities"
                                icon="warning"
                                sectionKey="srcVuln"
                                summary={`${sourceResult.vulnerabilities.split('\n').filter(l => l.startsWith('•')).length || 0} found`}
                                variant="source-vuln"
                                openSections={openSections}
                                toggleSection={toggleSection}
                            >
                                <div className="flag-list">
                                    {sourceResult.vulnerabilities ? (
                                        sourceResult.vulnerabilities.split('\n').filter(val => val.trim()).map((line, i) => (
                                            <div key={i} className="flag-item">
                                                <span className="flag-icon">⚠️</span>
                                                <span className="flag-text">{line.replace(/^•\s*/, '')}</span>
                                            </div>
                                        ))
                                    ) : (
                                        <div className="section-empty">No obvious vulnerabilities detected.</div>
                                    )}
                                </div>
                            </AccordionCard>

                            {/* 3. Dangerous Functions */}
                            <AccordionCard
                                title="Dangerous Functions"
                                icon="pest_control"
                                sectionKey="srcDanger"
                                summary={`${sourceResult.dangerous_functions.length || 0} detected`}
                                variant="source-danger"
                                openSections={openSections}
                                toggleSection={toggleSection}
                            >
                                <div className="flag-list">
                                    {sourceResult.dangerous_functions.length > 0 ? (
                                        sourceResult.dangerous_functions.map((fn, i) => (
                                            <div key={i} className="flag-item">
                                                <span className="flag-icon">🔴</span>
                                                <span className="flag-text">
                                                    Line {fn.line}: <strong>{fn.function}</strong> &mdash; {fn.description}
                                                </span>
                                            </div>
                                        ))
                                    ) : (
                                        <div className="section-empty">No dangerous function calls detected.</div>
                                    )}
                                </div>
                            </AccordionCard>

                            {/* 4. AI Hints */}
                            <AccordionCard
                                title="CTF Hints"
                                icon="lightbulb"
                                sectionKey="srcHints"
                                summary="Strategic guidance"
                                variant="source-hints"
                                openSections={openSections}
                                toggleSection={toggleSection}
                            >
                                <div className="ai-hints-body">
                                    <div className="ai-bullets">
                                        {sourceResult.hints ? (
                                            sourceResult.hints.split('\n').filter(val => val.trim()).map((line, i) => (
                                                <div key={i} className="ai-bullet">
                                                    <span className="bullet-point"></span>
                                                    <span dangerouslySetInnerHTML={{ __html: line.replace(/^•\s*/, '').replace(/`(.*?)`/g, '<code class="inline-code">$1</code>') }} />
                                                </div>
                                            ))
                                        ) : (
                                            <div className="section-empty">No hints generated.</div>
                                        )}
                                    </div>
                                    {sourceResult.next_steps && (
                                        <div className="ai-kill-chain">
                                            <div className="kill-chain-header">
                                                <span className="material-symbols-outlined">play_circle</span>
                                                Next Steps
                                            </div>
                                            <div className="ai-bullets">
                                                {sourceResult.next_steps.split('\n').filter(val => val.trim()).map((line, i) => (
                                                    <div key={i} className="ai-bullet" style={{ color: 'var(--on-surface-variant)' }}>
                                                        <span className="bullet-point" style={{ background: 'var(--on-surface-variant)' }}></span>
                                                        <span dangerouslySetInnerHTML={{ __html: line.replace(/^•\s*/, '').replace(/`(.*?)`/g, '<code class="inline-code">$1</code>') }} />
                                                    </div>
                                                ))}
                                            </div>
                                        </div>
                                    )}
                                </div>
                            </AccordionCard>

                            {/* 5. Source Code View */}
                            <AccordionCard
                                title="Source Code"
                                icon="code"
                                sectionKey="srcCode"
                                summary="View full source"
                                variant="source-code"
                                openSections={openSections}
                                toggleSection={toggleSection}
                            >
                                <div className="hex-viewer-body">
                                    <pre className="hex-pre">
                                        <code>{sourceCode}</code>
                                    </pre>
                                </div>
                            </AccordionCard>

                            {/* 6. Chat Component reused entirely */}
                        </div>
                    </>
                )}

                {/* Footer */}
                <footer className="footer">
                    BinExplain performs static analysis only. Uploaded files are deleted
                    immediately after analysis. No binaries are ever executed.
                </footer>
            </div>

            {/* ── Password Modal (for protected ZIPs) ── */}
            {passwordModal && (
                <div className="pwd-overlay" id="password-modal-overlay" onClick={() => {
                    if (!passwordLoading) {
                        setPasswordModal(false);
                        setPasswordInput('');
                        setPasswordError('');
                        passwordFileRef.current = null;
                    }
                }}>
                    <div className="pwd-modal" id="password-modal" onClick={e => e.stopPropagation()}>
                        <div className="pwd-modal-header">
                            <span className="pwd-modal-icon">🔒</span>
                            <h2 className="pwd-modal-title">Password Protected ZIP</h2>
                        </div>
                        <p className="pwd-modal-desc">
                            This archive is encrypted. Enter the password to unlock and analyze its contents.
                        </p>

                        {passwordError && (
                            <div className="pwd-modal-error" id="password-error">
                                <span className="pwd-modal-error-icon">⚠️</span>
                                {passwordError}
                            </div>
                        )}

                        <div className="pwd-input-group">
                            <input
                                className="pwd-input"
                                id="password-input"
                                type="password"
                                placeholder="Enter ZIP password..."
                                value={passwordInput}
                                onChange={e => setPasswordInput(e.target.value)}
                                onKeyDown={e => {
                                    if (e.key === 'Enter' && passwordInput && !passwordLoading) {
                                        uploadWithPassword();
                                    }
                                }}
                                disabled={passwordLoading}
                                autoFocus
                                maxLength={256}
                            />
                        </div>

                        <div className="pwd-modal-actions">
                            <button
                                className="pwd-btn pwd-btn--cancel"
                                id="password-cancel-btn"
                                onClick={() => {
                                    setPasswordModal(false);
                                    setPasswordInput('');
                                    setPasswordError('');
                                    passwordFileRef.current = null;
                                }}
                                disabled={passwordLoading}
                                type="button"
                            >
                                Cancel
                            </button>
                            <button
                                className="pwd-btn pwd-btn--submit"
                                id="password-submit-btn"
                                onClick={uploadWithPassword}
                                disabled={!passwordInput || passwordLoading}
                                type="button"
                            >
                                {passwordLoading ? (
                                    <>
                                        <span className="pwd-spinner" />
                                        Unlocking...
                                    </>
                                ) : (
                                    '🔓 Unlock & Analyze'
                                )}
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}
