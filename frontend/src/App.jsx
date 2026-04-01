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

    /* Validate & stage a file */
    const stageFile = useCallback((f) => {
        setError('');
        setResult(null);

        const ext = getExtension(f.name);
        // Allow extensionless files (auto-detected by backend via magic bytes)
        if (ext !== '' && !ALLOWED_EXTENSIONS.includes(ext)) {
            setError(`Invalid file type "${ext}". Accepted: ${ALLOWED_EXTENSIONS.join(', ')} or no extension (auto-detect).`);
            return;
        }
        const sizeLimit = ext === '.zip' ? MAX_ZIP_SIZE : MAX_FILE_SIZE;
        const sizeLimitLabel = ext === '.zip' ? '10 MB' : '5 MB';
        if (f.size > sizeLimit) {
            setError(`File is too large (${formatBytes(f.size)}). Maximum: ${sizeLimitLabel}.`);
            return;
        }
        if (f.size === 0) {
            setError('File is empty.');
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

            const data = await res.json();

            if (!res.ok) {
                setError(data.detail || `Server error (${res.status})`);
                return;
            }

            setResult(data);
            setFile(null);

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
                    ? 'Cannot reach the backend. Is it running on ' + BACKEND_URL + '?'
                    : `Upload failed: ${err.message}`
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
                {error && <div className="error-box">✖ {error}</div>}

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
