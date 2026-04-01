import { useState, useRef, useCallback, useEffect } from 'react';

/* ── Config ────────────────────────────────────────────────────────── */
const BACKEND_URL = 'http://localhost:8000';

const ALLOWED_EXTENSIONS = ['.bin', '.elf', '.exe'];
const MAX_FILE_SIZE = 5 * 1024 * 1024; // 5 MB

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
    const chatEndRef = useRef(null);
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
        if (!ALLOWED_EXTENSIONS.includes(ext)) {
            setError(`Invalid file type "${ext}". Accepted: ${ALLOWED_EXTENSIONS.join(', ')}`);
            return;
        }
        if (f.size > MAX_FILE_SIZE) {
            setError(`File is too large (${formatBytes(f.size)}). Maximum: 5 MB.`);
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

    /* Send a follow-up chat message */
    const sendChat = async () => {
        const text = chatInput.trim();
        if (!text || chatLoading) return;
        if (text.length > MAX_CHAT_CHARS) return;

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
                                accept=".bin,.elf,.exe"
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
                            <div className="chat-input-row">
                                <input
                                    className="chat-input"
                                    type="text"
                                    placeholder="Ask about this binary..."
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
                                    disabled={chatLoading || !chatInput.trim()}
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
