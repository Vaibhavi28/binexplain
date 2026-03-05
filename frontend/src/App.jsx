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
export default function App() {
    const [file, setFile] = useState(null);
    const [dragOver, setDragOver] = useState(false);
    const [loading, setLoading] = useState(false);
    const [loadingMsg, setLoadingMsg] = useState('');
    const [result, setResult] = useState(null);
    const [error, setError] = useState('');
    const inputRef = useRef(null);

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

    /* ── Render ──────────────────────────────────────────────────────── */
    return (
        <div className="app">
            {/* Header */}
            <header className="header">
                <h1 className="title">BinExplain</h1>
                <p className="subtitle">
                    Binary Analysis for CTF Beginners — Free &amp; Open Source
                </p>
            </header>

            {/* Warning */}
            <div className="warning">
                <span className="warning-icon">⚠️</span>
                <span>Only upload files you own or have permission to analyze</span>
            </div>

            {/* Drop zone */}
            <div
                className={`dropzone${dragOver ? ' drag-over' : ''}${loading ? ' disabled' : ''}`}
                onDragOver={onDragOver}
                onDragLeave={onDragLeave}
                onDrop={onDrop}
                onClick={() => inputRef.current?.click()}
                role="button"
                tabIndex={0}
                aria-label="Upload a binary file"
            >
                <span className="dropzone-icon">📂</span>
                <span className="dropzone-label">
                    Drag &amp; drop a binary file here, or click to browse
                </span>
                <span className="dropzone-hint">
                    Accepted: .bin .elf .exe &nbsp;|&nbsp; Max size: 5 MB
                </span>
                <input
                    ref={inputRef}
                    type="file"
                    className="file-input"
                    accept=".bin,.elf,.exe"
                    onChange={onFileChange}
                />
            </div>

            {/* Selected file */}
            {file && !loading && (
                <div className="selected-file">
                    <span>📄 {file.name} ({formatBytes(file.size)})</span>
                    <button onClick={clearFile} title="Remove file">✕</button>
                </div>
            )}

            {/* Upload button */}
            {file && !loading && (
                <button className="upload-btn" onClick={upload}>
                    ▶ Analyze File
                </button>
            )}

            {/* Loading */}
            {loading && (
                <div className="terminal-loading">
                    <div className="terminal-line">
                        <span className="prompt">&gt;</span>
                        <span className="text">{loadingMsg}</span>
                        <span className="cursor-blink" />
                    </div>
                </div>
            )}

            {/* Error */}
            {error && <div className="error-box">✖ {error}</div>}

            {/* Results */}
            {result && (
                <section className="results">
                    <div className="results-header">
                        <span>
                            $ strings {result.filename}
                        </span>
                        <span className="results-meta">
                            {result.strings_count} string{result.strings_count !== 1 ? 's' : ''} &nbsp;|&nbsp; {formatBytes(result.size_bytes)}
                        </span>
                    </div>

                    <div className="results-body">
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
                </section>
            )}

            {/* Footer */}
            <footer className="footer">
                BinExplain performs static analysis only. Uploaded files are deleted
                immediately after analysis. No binaries are ever executed.
            </footer>
        </div>
    );
}
