import { useState, useRef, useCallback, useEffect } from 'react';

/* ── Config ────────────────────────────────────────────────────────── */
const BACKEND_URL = 'http://localhost:8000';

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
    const dot = name.lastIndexOf('.');
    return dot === -1 ? '' : name.slice(dot).toLowerCase();
}

/* ── App ───────────────────────────────────────────────────────────── */
const MAX_CHAT_CHARS = 2000;
const MAX_CHAT_MESSAGES = 10;

export default function App() {
    const [file, setFile] = useState(null);
    const [dragOver, setDragOver] = useState(false);
    const [loading, setLoading] = useState(false);
    const [loadingMsg, setLoadingMsg] = useState('');
    const [result, setResult] = useState(null);
    const [error, setError] = useState('');
    const inputRef = useRef(null);

    /* ── Chat state (lives in React only — lost on refresh by design) ── */
    const [chatMessages, setChatMessages] = useState([]);
    const [chatInput, setChatInput] = useState('');
    const [chatLoading, setChatLoading] = useState(false);
    const [chatImage, setChatImage] = useState(null);
    const [chatImagePreview, setChatImagePreview] = useState('');
    const chatEndRef = useRef(null);
    const chatImageRef = useRef(null);
    const analysisContextRef = useRef('');

    /* ── VirusTotal polling state ── */
    const [vtScanId, setVtScanId] = useState(null);
    const [vtResult, setVtResult] = useState(null);

    /* ── Hex viewer toggle ── */
    const [hexViewOpen, setHexViewOpen] = useState(false);

    /* ── Disassembly viewer toggle ── */
    const [disasmOpen, setDisasmOpen] = useState(false);

    /* ── AI Hints feedback ── */
    const [feedbackGiven, setFeedbackGiven] = useState(null);

    /* ── Rate limit countdown ── */
    const [rateLimitSeconds, setRateLimitSeconds] = useState(0);

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

        const ext = getExtension(f.name);
        // Allow extensionless files (auto-detected by backend via magic bytes)
        if (ext !== '' && !ALLOWED_EXTENSIONS.includes(ext)) {
            setError(`❌ Unsupported file type "${ext}". Accepted: ELF, EXE, BIN, SO, DLL, ZIP or extensionless binaries.`);
            return;
        }
        const sizeLimit = ext === '.zip' ? MAX_ZIP_SIZE : MAX_FILE_SIZE;
        const sizeLimitLabel = ext === '.zip' ? '10 MB' : '5 MB';
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

            const res = await fetch(`${BACKEND_URL}/analyze`, {
                method: 'POST',
                body: form,
            });

            const data = await res.json().catch(() => ({}));

            if (!res.ok) {
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
            setResult(data);
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
                setVtResult(data.virustotal || null);
            }

            /* Initialize chat with AI hints as first assistant message */
            if (data.hints) {
                setChatMessages([{ role: 'assistant', content: data.hints }]);
                analysisContextRef.current = data.hints;
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

                {/* ═══ Results ═══ */}
                {result && (
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

                        {/* ── Risk Score Badge ── */}
                        {result.risk_score && (
                            <div className={`risk-card risk-card--${result.risk_score.level.toLowerCase()}`}>
                                <div className="risk-header">
                                    <div className="risk-score-circle">
                                        <span className="risk-score-number">{result.risk_score.score}</span>
                                        <span className="risk-score-max">/100</span>
                                    </div>
                                    <div className="risk-info">
                                        <span className={`risk-badge risk-badge--${result.risk_score.level.toLowerCase()}`}>
                                            {result.risk_score.level === 'Clean' && '✓ '}
                                            {result.risk_score.level === 'Warning' && '⚠ '}
                                            {result.risk_score.level === 'Critical' && '🔴 '}
                                            {result.risk_score.level}
                                        </span>
                                        <span className="risk-label">Risk Assessment</span>
                                    </div>
                                </div>
                                <div className="risk-bar-track">
                                    <div
                                        className={`risk-bar-fill risk-bar-fill--${result.risk_score.level.toLowerCase()}`}
                                        style={{ width: `${result.risk_score.score}%` }}
                                    />
                                </div>
                                {result.risk_score.reasons && result.risk_score.reasons.length > 0 && (
                                    <ul className="risk-reasons">
                                        {result.risk_score.reasons.map((reason, i) => (
                                            <li key={i} className="risk-reason">{reason}</li>
                                        ))}
                                    </ul>
                                )}
                            </div>
                        )}

                        {/* ── Checksec Security Protections ── */}
                        {result.checksec && result.checksec.nx !== null && (
                            <div className="checksec-card" id="checksec-results">
                                <div className="result-card-header result-card-header--checksec">
                                    <span>🔒 Security Protections</span>
                                    <span className="result-card-meta">checksec</span>
                                </div>
                                <div className="result-card-body">
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
                                </div>
                            </div>
                        )}

                        {/* ── Entropy Bar ── */}
                        {result.entropy !== undefined && (
                            <div className={`entropy-card entropy-card--${
                                result.entropy < 5 ? 'low' :
                                result.entropy < 6.5 ? 'medium' :
                                result.entropy < 7 ? 'high' : 'veryhigh'
                            }`}>
                                <div className="entropy-header">
                                    <div className="entropy-score-group">
                                        <span className="entropy-score">{result.entropy.toFixed(3)}</span>
                                        <span className="entropy-max">/8.0</span>
                                    </div>
                                    <div className="entropy-info">
                                        <span className={`entropy-badge entropy-badge--${
                                            result.entropy < 5 ? 'low' :
                                            result.entropy < 6.5 ? 'medium' :
                                            result.entropy < 7 ? 'high' : 'veryhigh'
                                        }`}>
                                            {result.entropy_label}
                                        </span>
                                        <span className="entropy-label-text">Shannon Entropy</span>
                                    </div>
                                </div>
                                <div className="entropy-bar-track">
                                    <div
                                        className={`entropy-bar-fill entropy-bar-fill--${
                                            result.entropy < 5 ? 'low' :
                                            result.entropy < 6.5 ? 'medium' :
                                            result.entropy < 7 ? 'high' : 'veryhigh'
                                        }`}
                                        style={{ width: `${(result.entropy / 8) * 100}%` }}
                                    />
                                </div>
                                <div className="entropy-hint">
                                    {result.entropy < 5 && 'Normal binary — code and data sections are readable.'}
                                    {result.entropy >= 5 && result.entropy < 6.5 && 'Moderate density — may contain compressed resources.'}
                                    {result.entropy >= 6.5 && result.entropy < 7 && 'High density — sections may be compressed or obfuscated.'}
                                    {result.entropy >= 7 && '⚠ Very high entropy — binary is likely packed, encrypted, or compressed. Consider unpacking first.'}
                                </div>
                            </div>
                        )}

                        {/* ── Encodings Detected ── */}
                        {result.encodings && Object.keys(result.encodings).length > 0 && (
                            <div className="result-card" style={{ marginTop: 20 }}>
                                <div className="result-card-header result-card-header--encodings">
                                    <span>🔐 Encodings Detected</span>
                                    <span className="result-card-meta">
                                        {Object.values(result.encodings).flat().length} match{Object.values(result.encodings).flat().length !== 1 ? 'es' : ''}
                                    </span>
                                </div>
                                <div className="result-card-body">
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
                                </div>
                            </div>
                        )}

                        {/* ── YARA Matches ── */}
                        {result.yara_matches && result.yara_matches.length > 0 && (
                            <div className="result-card" style={{ marginTop: 20 }}>
                                <div className="result-card-header result-card-header--yara">
                                    <span>🎯 YARA Matches</span>
                                    <span className="result-card-meta">
                                        {result.yara_matches.length} rule{result.yara_matches.length !== 1 ? 's' : ''} triggered
                                    </span>
                                </div>
                                <div className="result-card-body">
                                    {result.yara_matches.map((rule, i) => (
                                        <div className="yara-rule" key={i}>
                                            <div className="yara-rule-header">
                                                <span className="yara-rule-name">{rule.label}</span>
                                                <span className="yara-rule-count">{rule.count} match{rule.count !== 1 ? 'es' : ''}</span>
                                            </div>
                                            <div className="yara-rule-desc">{rule.description}</div>
                                            {rule.matches.map((m, j) => (
                                                <div className="section-item section-item--yara" key={j}>{m}</div>
                                            ))}
                                        </div>
                                    ))}
                                </div>
                            </div>
                        )}

                        {/* ── VirusTotal Section (async) ── */}
                        {/* Only show if VT is not disabled */}
                        {result.virustotal?.status !== 'disabled' && (
                            <div className={`vt-card vt-card--${vtResult?.status || 'scanning'}`} id="vt-results">
                                <div className="result-card-header result-card-header--vt">
                                    <span>🛡️ VirusTotal Scan</span>
                                    <span className="result-card-meta">
                                        {!vtResult && 'Scanning...'}
                                        {vtResult?.status === 'pending' && 'Analysis in progress'}
                                        {vtResult?.status === 'error' && 'Scan error'}
                                        {vtResult?.status === 'clean' && 'No threats detected'}
                                        {vtResult?.status === 'suspicious' && 'Low-confidence detections'}
                                        {vtResult?.status === 'malicious' && 'Threats detected'}
                                    </span>
                                </div>
                                <div className="result-card-body">
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
                                                <a
                                                    href={vtResult.permalink}
                                                    target="_blank"
                                                    rel="noopener noreferrer"
                                                    className="vt-link"
                                                    id="vt-permalink"
                                                >
                                                    View on VirusTotal →
                                                </a>
                                            )}
                                        </div>
                                    )}

                                    {/* Completed results */}
                                    {vtResult && ['clean', 'suspicious', 'malicious'].includes(vtResult.status) && (
                                        <div className="vt-results-body">
                                            {/* Detection Ratio */}
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

                                            {/* Detection Bar */}
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

                                            {/* Threat Name */}
                                            {vtResult.threat_name && (
                                                <div className="vt-threat">
                                                    <span className="vt-threat-label">Threat:</span>
                                                    <span className="vt-threat-name">{vtResult.threat_name}</span>
                                                </div>
                                            )}

                                            {/* Behavior Summary */}
                                            {vtResult.behavior_summary && (
                                                <div className="vt-behavior">
                                                    {vtResult.behavior_summary}
                                                </div>
                                            )}

                                            {/* Permalink */}
                                            {vtResult.permalink && (
                                                <a
                                                    href={vtResult.permalink}
                                                    target="_blank"
                                                    rel="noopener noreferrer"
                                                    className="vt-link"
                                                    id="vt-permalink"
                                                >
                                                    View Full Report →
                                                </a>
                                            )}
                                        </div>
                                    )}
                                </div>
                            </div>
                        )}

                        {/* ── Hex Viewer (collapsible) ── */}
                        {result.hex_view && result.hex_view.length > 0 && (
                            <div className="hex-viewer-card" id="hex-viewer">
                                <button
                                    className="hex-viewer-toggle"
                                    onClick={() => setHexViewOpen(prev => !prev)}
                                    type="button"
                                    id="hex-toggle-btn"
                                >
                                    <span className="hex-viewer-toggle-icon">{hexViewOpen ? '▼' : '▶'}</span>
                                    <span>🔍 Hex View — First {result.hex_view.length * 16} bytes</span>
                                </button>
                                {hexViewOpen && (
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
                                )}
                            </div>
                        )}

                        {/* ── Disassembly Viewer (collapsible) ── */}
                        {result.disassembly && result.disassembly.length > 0 && (
                            <div className="disasm-card" id="disasm-viewer">
                                <button
                                    className="disasm-toggle"
                                    onClick={() => setDisasmOpen(prev => !prev)}
                                    type="button"
                                    id="disasm-toggle-btn"
                                >
                                    <span className="disasm-toggle-icon">{disasmOpen ? '▼' : '▶'}</span>
                                    <span>🔬 Disassembly — {result.disassembly_function || 'unknown'} ({result.disassembly.length} instructions)</span>
                                </button>
                                {disasmOpen && (
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
                                )}
                            </div>
                        )}

                        {/* ── Pwntools Exploit Template ── */}
                        {result.pwn_template && result.extension !== '.zip' && (
                            <div className="pwn-template-card" id="pwn-template">
                                <div className="result-card-header result-card-header--pwn">
                                    <span>⚡ Pwntools Exploit Template</span>
                                    <div className="pwn-actions">
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
                            </div>
                        )}

                        <div className="results-grid">
                            {/* Strings */}
                            <div className="result-card">
                                <div className="result-card-header result-card-header--strings">
                                    <span>$ strings {result.filename}</span>
                                    <span className="result-card-meta">
                                        {result.strings_count} string{result.strings_count !== 1 ? 's' : ''}
                                    </span>
                                </div>
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
                            </div>

                            {/* 🚩 Flags Detected */}
                            <div className="result-card">
                                <div className="result-card-header result-card-header--flags">
                                    <span>🚩 Flags Detected</span>
                                </div>
                                <div className="result-card-body">
                                    {result.flags_detected && result.flags_detected.length > 0 ? (
                                        result.flags_detected.map((flag, i) => (
                                            <div className="section-item section-item--flag" key={i}>{flag}</div>
                                        ))
                                    ) : (
                                        <div className="section-empty">No flags detected in strings</div>
                                    )}
                                </div>
                            </div>

                            {/* 🔍 Interesting Findings */}
                            <div className="result-card">
                                <div className="result-card-header result-card-header--findings">
                                    <span>🔍 Interesting Findings</span>
                                </div>
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
                            </div>

                            {/* 💡 AI Hints */}
                            <div className="result-card">
                                <div className="result-card-header result-card-header--hints">
                                    <span>💡 AI Hints</span>
                                </div>
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
                            </div>
                        </div>

                        {/* 💬 Follow-up Chat */}
                        <section className="chat-container">
                            <div className="chat-title-bar">
                                <span className="material-symbols-outlined chat-title-icon">forum</span>
                                <span className="chat-title-text">Ask Follow-Up Questions</span>
                            </div>
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
                        </section>
                    </>
                )}

                {/* Footer */}
                <footer className="footer">
                    BinExplain performs static analysis only. Uploaded files are deleted
                    immediately after analysis. No binaries are ever executed.
                </footer>
            </div>
        </div>
    );
}
