import { useState, useRef, useCallback, useEffect, useMemo } from 'react';

/* â”€â”€ Config â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
const BACKEND_URL = import.meta.env.VITE_BACKEND_URL || 'http://localhost:8000';

const ALLOWED_EXTENSIONS = ['.bin', '.elf', '.exe', '.so', '.dll', '.out', '.o', '.zip'];
const MAX_FILE_SIZE = 5 * 1024 * 1024; // 5 MB
const MAX_ZIP_SIZE = 10 * 1024 * 1024; // 10 MB

const LOADING_MESSAGES = [
    'Reading file headers...',
    'Extracting strings...',
    'Analyzing patterns...',
];

/* â”€â”€ Helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
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
    // Trailing dot (e.g. "file.") â†’ treat as extensionless
    return ext === '.' ? '' : ext;
}

/* â”€â”€ Accordion Card â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
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
                <span className={`accordion-arrow${isOpen ? ' accordion-arrow--open' : ''}`}>â–¶</span>
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

/* â”€â”€ Carousel â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
function Carousel({ title, icon, children }) {
    const [idx, setIdx] = useState(0);
    const [cpv, setCpv] = useState(4);
    const ptrRef = useRef(null);

    useEffect(() => {
        const upd = () => {
            const w = window.innerWidth;
            setCpv(w < 640 ? 1 : w < 1024 ? 2 : 4);
        };
        upd();
        window.addEventListener('resize', upd);
        return () => window.removeEventListener('resize', upd);
    }, []);

    const cards = Array.isArray(children) ? children.filter(Boolean) : children ? [children] : [];
    if (cards.length === 0) return null;
    const maxIdx = Math.max(0, cards.length - cpv);
    const slideW = 100 / cpv;
    const showNav = cards.length > cpv;

    const prev = () => setIdx(i => Math.max(0, i - 1));
    const next = () => setIdx(i => Math.min(maxIdx, i + 1));

    return (
        <section className="carousel-section">
            <div className="carousel-header">
                <span className="carousel-header-icon">{icon}</span>
                <h3 className="carousel-header-title">{title}</h3>
                {showNav && (
                    <div className="carousel-nav">
                        <button className="carousel-arrow" onClick={prev} disabled={idx === 0} aria-label="Previous">â€¹</button>
                        <button className="carousel-arrow" onClick={next} disabled={idx >= maxIdx} aria-label="Next">â€º</button>
                    </div>
                )}
            </div>
            <div
                className="carousel-track"
                onPointerDown={e => { ptrRef.current = e.clientX; }}
                onPointerUp={e => {
                    if (ptrRef.current === null) return;
                    const d = ptrRef.current - e.clientX;
                    if (Math.abs(d) > 50) { d > 0 ? next() : prev(); }
                    ptrRef.current = null;
                }}
            >
                <div className="carousel-inner" style={{ transform: `translateX(-${idx * slideW}%)` }}>
                    {cards.map((c, i) => (
                        <div className="carousel-slide" key={i} style={{ width: `${slideW}%` }}>{c}</div>
                    ))}
                </div>
            </div>
            {showNav && (
                <div className="carousel-dots">
                    {Array.from({ length: maxIdx + 1 }, (_, i) => (
                        <button key={i} className={`carousel-dot${i === idx ? ' carousel-dot--active' : ''}`} onClick={() => setIdx(i)} />
                    ))}
                </div>
            )}
        </section>
    );
}

/* â”€â”€ Compact Carousel Card â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
function CCard({ icon, title, stat, statColor, accent, onClick }) {
    return (
        <div className="carousel-card" style={{ '--card-accent': accent || 'var(--primary)' }} onClick={onClick} role="button" tabIndex={0}>
            <div className="ccard-icon">{icon}</div>
            <div className="ccard-title">{title}</div>
            <div className="ccard-stat" style={statColor ? { color: statColor } : undefined}>{stat}</div>
            <div className="ccard-hint">Click to expand â†’</div>
        </div>
    );
}

/* â”€â”€ Card Detail Modal â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
function CardModal({ title, icon, accent, onClose, children }) {
    useEffect(() => {
        const h = (e) => { if (e.key === 'Escape') onClose(); };
        document.addEventListener('keydown', h);
        document.body.style.overflow = 'hidden';
        return () => { document.removeEventListener('keydown', h); document.body.style.overflow = ''; };
    }, [onClose]);

    return (
        <div className="card-modal-overlay" onClick={onClose}>
            <div className="card-modal" onClick={e => e.stopPropagation()} style={{ '--modal-accent': accent || 'var(--primary)' }}>
                <div className="card-modal-top">
                    <span className="card-modal-icon">{icon}</span>
                    <h2 className="card-modal-title">{title}</h2>
                    <button className="card-modal-close" onClick={onClose} aria-label="Close">âœ•</button>
                </div>
                <div className="card-modal-body">{children}</div>
            </div>
        </div>
    );
}

/* â”€â”€ App â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
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

    /* â”€â”€ Analysis mode toggle â”€â”€ */
    const [analysisMode, setAnalysisMode] = useState('binary');  // 'binary' | 'source'

    /* â”€â”€ Source code analysis state â”€â”€ */
    const [sourceCode, setSourceCode] = useState('');
    const [sourceFile, setSourceFile] = useState(null);
    const [sourceResult, setSourceResult] = useState(null);
    const [sourceLoading, setSourceLoading] = useState(false);
    const [sourceError, setSourceError] = useState('');
    const sourceInputRef = useRef(null);

    /* â”€â”€ Chat state (lives in React only â€” lost on refresh by design) â”€â”€ */
    const [chatMessages, setChatMessages] = useState([]);
    const [chatInput, setChatInput] = useState('');
    const [chatLoading, setChatLoading] = useState(false);
    const [chatImage, setChatImage] = useState(null);
    const [chatImagePreview, setChatImagePreview] = useState('');
    const chatEndRef = useRef(null);
    const chatImageRef = useRef(null);
    const analysisContextRef = useRef('');

    /* â”€â”€ Password modal state (for protected ZIPs) â”€â”€ */
    const [passwordModal, setPasswordModal] = useState(false);
    const [passwordInput, setPasswordInput] = useState('');
    const [passwordError, setPasswordError] = useState('');
    const [passwordLoading, setPasswordLoading] = useState(false);
    const passwordFileRef = useRef(null);

    /* â”€â”€ VirusTotal polling state â”€â”€ */
    const [submitToVt, setSubmitToVt] = useState(false);
    const [vtScanId, setVtScanId] = useState(null);
    const [vtResult, setVtResult] = useState(null);

    /* â”€â”€ Accordion section open/close state â”€â”€ */
    const [openSections, setOpenSections] = useState({
        ctfCategory: true,  // open by default â€” prominent
        difficulty: false,
        quickCommands: true, // open by default
        cvss: false,
        functions: false,
        imports: false,
        dataFlows: false,
        checksec: false,
        ropGadgets: false,
        formatString: false,
        libcInfo: false,
        pltGot: false,
        overflowOffset: false,
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

    /* â”€â”€ AI Hints feedback â”€â”€ */
    const [feedbackGiven, setFeedbackGiven] = useState(null);

    /* â”€â”€ Rate limit countdown â”€â”€ */
    const [rateLimitSeconds, setRateLimitSeconds] = useState(0);

    /* â”€â”€ Card detail modal â”€â”€ */
    const [modalData, setModalData] = useState(null);
    const openModal = useCallback((d) => setModalData(d), []);
    const closeModal = useCallback(() => setModalData(null), []);

    /* Toggle an accordion section */
    const toggleSection = useCallback((key) => {
        setOpenSections(prev => ({ ...prev, [key]: !prev[key] }));
    }, []);

    /* Build checksec summary for header (e.g. "NXâœ“ PIEâœ— Canaryâœ“") */
    const checksecSummary = useMemo(() => {
        if (!result?.checksec || result.checksec.nx === null) return '';
        const badges = [
            { key: 'nx', label: 'NX' },
            { key: 'pie', label: 'PIE' },
            { key: 'canary', label: 'Canary' },
            { key: 'relro', label: 'RELRO' },
            { key: 'fortify', label: 'Fortify' },
        ];
        return badges.map(b => `${b.label}${result.checksec[b.key] ? 'âœ“' : 'âœ—'}`).join(' ');
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
                // Network error â€” keep polling
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
            setError('âŒ Invalid file. Please select a valid binary.');
            return;
        }

        const ext = getExtension(f.name);
        const isZip = ext === '.zip' || (f.type && f.type === 'application/zip') || (f.type && f.type === 'application/x-zip-compressed');

        // Allow extensionless files (auto-detected by backend via magic bytes)
        // Allow .zip files explicitly (backend supports them)
        if (ext !== '' && !isZip && !ALLOWED_EXTENSIONS.includes(ext)) {
            setError(`âŒ Unsupported file type "${ext}". Accepted: ELF, EXE, BIN, SO, DLL, ZIP or extensionless binaries.`);
            return;
        }
        const sizeLimit = (ext === '.zip' || isZip) ? MAX_ZIP_SIZE : MAX_FILE_SIZE;
        const sizeLimitLabel = (ext === '.zip' || isZip) ? '10 MB' : '5 MB';
        if (f.size > sizeLimit) {
            setError(`ðŸ“¦ File too large (${formatBytes(f.size)}). Maximum size is ${sizeLimitLabel}.`);
            return;
        }
        if (f.size === 0) {
            setError('âŒ File is empty. Please select a valid binary.');
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
                    // Rate limited â€” parse retry-after
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
                    setError(`â³ Rate limit reached â€” you can analyze 10 files per hour. Please wait ~${mins} minute${mins !== 1 ? 's' : ''} before trying again.`);
                } else {
                    setError(data.detail || `âŒ Server error (${res.status})`);
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
                    ? 'ðŸ”Œ Cannot connect to backend. Make sure it\'s running on ' + BACKEND_URL
                    : `âŒ Upload failed: ${err.message}`
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
                    setError('â³ Rate limit reached. Please wait before trying again.');
                    return;
                }
                setPasswordError(data.detail || `Error (${res.status})`);
                return;
            }

            // Success â€” close modal, clear password, show results
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
            setChatMessages(prev => [...prev, { role: 'assistant', content: 'âš  Invalid image type. Accepted: PNG, JPG, GIF, WEBP.' }]);
            return;
        }
        if (f.size > 5 * 1024 * 1024) {
            setChatMessages(prev => [...prev, { role: 'assistant', content: 'âš  Image too large. Maximum: 5 MB.' }]);
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
            const userMsg = { role: 'user', content: text || 'ðŸ“· [Screenshot attached]', image: chatImagePreview };
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
                    setChatMessages(prev => [...prev, { role: 'assistant', content: `âš  Error: ${data.detail || 'Image analysis failed.'}` }]);
                    return;
                }

                setChatMessages(prev => [...prev, { role: 'assistant', content: data.response }]);
            } catch (err) {
                setChatMessages(prev => [...prev, { role: 'assistant', content: `âš  ${err.message === 'Failed to fetch' ? 'Cannot reach backend.' : err.message}` }]);
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
                    { role: 'assistant', content: `âš  Error: ${data.detail || 'Something went wrong.'}` },
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
                { role: 'assistant', content: `âš  ${err.message === 'Failed to fetch' ? 'Cannot reach backend.' : err.message}` },
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
    /* â”€â”€ Source code handlers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
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

    /* â”€â”€ Render â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
    return (
        <div className="app-wrapper">
            <div className="content-wrapper">

                {/* â”€â”€ Title â”€â”€ */}
                <header className="hero-header">
                    <h1 className="hero-title">BinExplain</h1>
                    <p className="hero-subtitle">
                        Secure, sandboxed static analysis for binary executables.
                        Upload a binary to extract strings, detect CTF flags, and get AI-powered hints.
                    </p>
                </header>

                {/* â”€â”€ Mode Toggle â”€â”€ */}
                <div className="mode-toggle">
                    <button
                        className={`mode-btn ${analysisMode === 'binary' ? 'active' : ''}`}
                        onClick={() => switchMode('binary')}
                    >
                        ðŸ”¬ Binary Analysis
                    </button>
                    <button
                        className={`mode-btn ${analysisMode === 'source' ? 'active' : ''}`}
                        onClick={() => switchMode('source')}
                    >
                        ðŸ“ Source Code Analysis
                    </button>
                </div>

                {analysisMode === 'binary' ? (
                    <>
                        {/* â”€â”€ VirusTotal Disclaimer (always visible before upload) â”€â”€ */}
                        <div className="vt-disclaimer" id="vt-disclaimer">
                            <span className="vt-disclaimer-icon">âš ï¸</span>
                            <span>
                                Files submitted to VirusTotal are stored permanently in their database.
                                Do not upload sensitive or private binaries.
                            </span>
                        </div>

                {/* â”€â”€ Upload Zone â”€â”€ */}
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

                {/* â”€â”€ Staged File Bar â”€â”€ */}
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

                {/* â”€â”€ VirusTotal Checkbox â”€â”€ */}
                {file && !loading && (
                    <div className="vt-checkbox-wrapper">
                        <label className="vt-checkbox-label" htmlFor="vt-checkbox">
                            <input
                                type="checkbox"
                                id="vt-checkbox"
                                checked={submitToVt}
                                onChange={e => setSubmitToVt(e.target.checked)}
                            />
                            ðŸ›¡ï¸ Submit to VirusTotal <span className="vt-checkbox-hint">(disable for CTF challenges)</span>
                        </label>
                    </div>
                )}

                {/* â”€â”€ Analyze Button â”€â”€ */}
                {file && !loading && (
                    <button className="analyze-btn" onClick={upload}>
                        â–¶ Analyze File
                    </button>
                )}

                {/* â”€â”€ Loading â”€â”€ */}
                {loading && (
                    <div className="terminal-loading">
                        <div className="terminal-line">
                            <span className="prompt">&gt;</span>
                            <span className="text">{loadingMsg}</span>
                            <span className="cursor-blink" />
                        </div>
                    </div>
                )}

                {/* â”€â”€ Error â”€â”€ */}
                {error && (
                    <div className={`error-box ${rateLimitSeconds > 0 ? 'error-box--rate-limit' : ''}`} id="error-display">
                        <div className="error-text">{error}</div>
                        {rateLimitSeconds > 0 && (
                            <div className="error-countdown">
                                â±ï¸ Retry in: {Math.floor(rateLimitSeconds / 60)}:{String(rateLimitSeconds % 60).padStart(2, '0')}
                            </div>
                        )}
                    </div>
                )}
                </>
                ) : (
                    <>
                        {/* â”€â”€ Source Code Upload & Paste Zone â”€â”€ */}
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
                                {sourceLoading ? 'Analyzing...' : 'â–¶ Analyze Code'}
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

                {/* â•â•â• Binary Results â•â•â• */}
                {analysisMode === 'binary' && result && (() => {
                    const cvssC = (s) => s === 'Critical' ? '#ef4444' : s === 'High' ? '#f97316' : s === 'Medium' ? '#eab308' : '#22c55e';
                    const om = (title, icon, accent, content) => openModal({ title, icon, accent, content });
                    return (
                    <>
                        {/* File info bar */}
                        <div className="analysis-meta-bar">
                            <div className="meta-item">
                                <span className="meta-label">File:</span>
                                <span style={{ fontFamily: 'Courier New, monospace', fontSize: 13, color: 'var(--on-surface)' }}>{result.filename}</span>
                            </div>
                            <div className="meta-item">
                                <span className="meta-label">Size:</span>
                                <span style={{ fontFamily: 'Courier New, monospace', fontSize: 13, color: 'var(--on-surface-variant)' }}>{formatBytes(result.size_bytes)}</span>
                            </div>
                            <div className="meta-item">
                                <span className="meta-label">Strings:</span>
                                <span style={{ fontFamily: 'Courier New, monospace', fontSize: 13, color: 'var(--primary)' }}>{result.strings_count}</span>
                            </div>
                        </div>

                        {/* â”€â”€ Section 1: Hero Row â”€â”€ */}
                        <div className="hero-row">
                            {result.ctf_category && result.ctf_category.category !== 'unknown' && (
                                <div className={`hero-card hero-card--${result.ctf_category.confidence.toLowerCase()}`}>
                                    <div className="hero-card-label">ðŸŽ¯ CTF Category</div>
                                    <div className="hero-card-main">
                                        <span className={`ctf-category-badge ctf-category-badge--${result.ctf_category.confidence.toLowerCase()}`}>{result.ctf_category.category.replace(/_/g, ' ').toUpperCase()}</span>
                                        <span className={`ctf-confidence-badge ctf-confidence-badge--${result.ctf_category.confidence.toLowerCase()}`}>{result.ctf_category.confidence}</span>
                                    </div>
                                    <p className="hero-card-desc">{result.ctf_category.explanation}</p>
                                </div>
                            )}
                            {result.difficulty && (
                                <div className={`hero-card hero-card--diff-${result.difficulty.difficulty.toLowerCase()}`}>
                                    <div className="hero-card-label">ðŸŽ² Difficulty</div>
                                    <div className="hero-card-main">
                                        <span className={`difficulty-badge difficulty-badge--${result.difficulty.difficulty.toLowerCase()}`}>{result.difficulty.difficulty}</span>
                                    </div>
                                    <p className="hero-card-desc">{result.difficulty.reason}</p>
                                </div>
                            )}
                        </div>

                        {/* â”€â”€ Section 2: Vulnerability Analysis â”€â”€ */}
                        <Carousel title="Vulnerability Analysis" icon="ðŸ”’">
                            {result.checksec && result.checksec.nx !== null && <CCard icon="ðŸ›¡ï¸" title="Security Protections" stat={checksecSummary} statColor="#60a5fa" accent="#3b82f6" onClick={() => om('Security Protections','ðŸ›¡ï¸','#3b82f6',
                                <div className="checksec-badges">{[{key:'nx',label:'NX',desc:'No-Execute'},{key:'pie',label:'PIE',desc:'Position Independent'},{key:'canary',label:'Canary',desc:'Stack Canary'},{key:'relro',label:'RELRO',desc:'Read-Only Relocations'},{key:'fortify',label:'Fortify',desc:'Fortify Source'}].map(({key,label,desc})=>(<div className={`checksec-badge checksec-badge--${result.checksec[key]?'enabled':'disabled'}`} key={key} title={desc}><span className="checksec-badge-icon">{result.checksec[key]?'âœ“':'âœ—'}</span><span className="checksec-badge-label">{label}</span><span className="checksec-badge-status">{result.checksec[key]?'Enabled':'Disabled'}</span></div>))}</div>
                            )} />}
                            {result.cvss_score !== undefined && <CCard icon="ðŸ“Š" title="CVSS Score" stat={`${result.cvss_score}/10.0 ${result.cvss_severity}`} statColor={cvssC(result.cvss_severity)} accent={cvssC(result.cvss_severity)} onClick={() => om('CVSS 3.1 Scoring','ðŸ“Š',cvssC(result.cvss_severity),
                                <div className={`risk-card risk-card--${result.cvss_severity.toLowerCase()}`}><div className="risk-header"><div className="risk-score-circle"><span className="risk-score-number">{result.cvss_score}</span><span className="risk-score-max">/10.0</span></div><div className="risk-info"><span className={`risk-badge risk-badge--${result.cvss_severity.toLowerCase()}`}>{result.cvss_severity}</span><span className="risk-label">Base Score Equivalent</span></div></div><div className="risk-bar-track"><div className={`risk-bar-fill risk-bar-fill--${result.cvss_severity.toLowerCase()}`} style={{width:`${(result.cvss_score/10)*100}%`}}/></div></div>
                            )} />}
                            {result.overflow_hint && result.overflow_hint.likely_offset && <CCard icon="ðŸ“" title="Overflow Offset" stat={`${result.overflow_hint.likely_offset} bytes â€” ${result.overflow_hint.confidence}`} statColor="var(--primary)" accent="var(--primary)" onClick={() => om('Overflow Offset','ðŸ“','var(--primary)',
                                <div className="overflow-card"><div className="overflow-header"><span className="overflow-offset-value">{result.overflow_hint.likely_offset}</span><span className="overflow-offset-label">bytes to RIP</span><span className={`ctf-confidence-badge ctf-confidence-badge--${result.overflow_hint.confidence.toLowerCase()}`}>{result.overflow_hint.confidence}</span></div>{result.overflow_hint.stack_size&&<div className="overflow-detail"><span className="overflow-detail-label">Stack frame:</span><span className="overflow-detail-value">0x{result.overflow_hint.stack_size.toString(16)} ({result.overflow_hint.stack_size} bytes)</span></div>}<p className="overflow-evidence">{result.overflow_hint.evidence}</p></div>
                            )} />}
                            {result.rop_gadgets && result.rop_gadgets.length > 0 && <CCard icon="ðŸ”—" title="ROP Gadgets" stat={`${result.rop_gadgets.length} gadgets`} statColor="#c084fc" accent="#a855f7" onClick={() => om('ROP Gadgets','ðŸ”—','#a855f7',
                                <div className="table-container"><table className="info-table"><thead><tr><th>Address</th><th>Gadget</th></tr></thead><tbody>{result.rop_gadgets.map((g,i)=><tr key={i}><td style={{fontFamily:'monospace',color:'var(--primary)'}}>{g.address}</td><td style={{fontFamily:'monospace'}}>{g.gadget}</td></tr>)}</tbody></table></div>
                            )} />}
                        </Carousel>

                        {/* â”€â”€ Section 3: AI Analysis â”€â”€ */}
                        <Carousel title="AI Analysis" icon="ðŸ§ ">
                            <CCard icon="ðŸ’¡" title="AI Hints + Kill Chain" stat={result.hints?'Analysis available':'Unavailable'} statColor="var(--secondary)" accent="var(--secondary-dim)" onClick={() => om('AI Hints + Kill Chain','ðŸ’¡','var(--secondary-dim)',
                                <div className="result-card-body">{result.hints?result.hints.split(/\n/).filter(l=>l.trim()).map((line,i)=><div className="section-item section-item--hint" key={i}>{line}</div>):<div className="section-empty">AI hints unavailable</div>}{result.hints&&<div className="hints-feedback">{feedbackGiven?<div className="hints-feedback-thanks">âœ… Thanks for your feedback!</div>:<><span className="hints-feedback-label">Were these hints helpful?</span><button className="hints-feedback-btn hints-feedback-btn--up" onClick={async()=>{setFeedbackGiven('up');try{await fetch(`${BACKEND_URL}/feedback`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({vote:'up',filename:result.filename})})}catch{}}} type="button">ðŸ‘ Helpful</button><button className="hints-feedback-btn hints-feedback-btn--down" onClick={async()=>{setFeedbackGiven('down');try{await fetch(`${BACKEND_URL}/feedback`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({vote:'down',filename:result.filename})})}catch{}}} type="button">ðŸ‘Ž Not helpful</button></>}</div>}</div>
                            )} />
                            {result.data_flows && result.data_flows.length > 0 && <CCard icon="ðŸŒŠ" title="Data Flow" stat={`${result.data_flows.length} flows`} statColor="#3b82f6" accent="#3b82f6" onClick={() => om('Data Flow Analysis','ðŸŒŠ','#3b82f6',
                                <ul className="data-flow-list">{result.data_flows.map((f,i)=><li key={i} className="data-flow-item">{f}</li>)}</ul>
                            )} />}
                            {result.format_string && <CCard icon="âš ï¸" title="Format String" stat={result.format_string.vulnerable?`Vulnerable â€” ${result.format_string.severity}`:'Safe'} statColor={result.format_string.vulnerable?'#f87171':'#4ade80'} accent={result.format_string.vulnerable?'#ef4444':'#22c55e'} onClick={() => om('Format String','âš ï¸',result.format_string.vulnerable?'#ef4444':'#22c55e',
                                <div className="fmtstr-card"><div className="fmtstr-header"><span className={`fmtstr-badge fmtstr-badge--${result.format_string.vulnerable?result.format_string.severity.toLowerCase():'safe'}`}>{result.format_string.vulnerable?`âš  VULNERABLE â€” ${result.format_string.severity}`:'âœ“ SAFE'}</span></div>{result.format_string.evidence.length>0&&<ul className="fmtstr-evidence">{result.format_string.evidence.map((e,i)=><li key={i} className="fmtstr-evidence-item">{e}</li>)}</ul>}</div>
                            )} />}
                            {result.libc_info && result.libc_info.glibc_version && <CCard icon="ðŸ“š" title="Libc Info" stat={`GLIBC ${result.libc_info.glibc_version}`} statColor="#22d3ee" accent="#06b6d4" onClick={() => om('Libc Info','ðŸ“š','#06b6d4',
                                <div className="libc-card"><div className="libc-row"><span className="libc-label">GLIBC Version</span><span className="libc-value">{result.libc_info.glibc_version}</span></div><div className="libc-row"><span className="libc-label">Likely OS</span><span className="libc-value libc-value--os">{result.libc_info.likely_os}</span></div>{result.libc_info.gcc_version&&<div className="libc-row"><span className="libc-label">GCC</span><span className="libc-value">{result.libc_info.gcc_version}</span></div>}{result.libc_info.libc_db_url&&<div className="libc-row"><span className="libc-label">Libc DB</span><a href={result.libc_info.libc_db_url} target="_blank" rel="noopener noreferrer" className="libc-link">ðŸ” Search â†’</a></div>}</div>
                            )} />}
                        </Carousel>

                        {/* â”€â”€ Section 4: Binary Internals â”€â”€ */}
                        <Carousel title="Binary Internals" icon="ðŸ”¬">
                            {result.disassembly && result.disassembly.length > 0 && <CCard icon="ðŸ”¬" title="Disassembly" stat={`${result.disassembly_function||'main'} â€” ${result.disassembly.length} insns`} statColor="#67e8f9" accent="#22d3ee" onClick={() => om('Disassembly','ðŸ”¬','#22d3ee',
                                <div className="disasm-body"><div className="disasm-row disasm-row--header"><span className="disasm-col-addr">Address</span><span className="disasm-col-mnemonic">Mnemonic</span><span className="disasm-col-operands">Operands</span></div>{result.disassembly.map((insn,i)=>{const mn=insn.mnemonic.toLowerCase();const d=['call','jmp','je','jne','jz','jnz','ret','retn','syscall','int'].includes(mn);return(<div className={`disasm-row${d?' disasm-row--danger':''}`} key={i}><span className="disasm-col-addr">{insn.address}</span><span className={`disasm-col-mnemonic${d?' disasm-mnemonic--danger':''}`}>{insn.mnemonic}</span><span className="disasm-col-operands">{insn.op_str||''}</span></div>)})}</div>
                            )} />}
                            {result.hex_view && result.hex_view.length > 0 && <CCard icon="ðŸ”" title="Hex View" stat={`First ${result.hex_view.length*16} bytes`} statColor="#60a5fa" accent="#3b82f6" onClick={() => om('Hex View','ðŸ”','#3b82f6',
                                <div className="hex-viewer-body"><div className="hex-row hex-row--header"><span className="hex-col-offset">Offset</span><span className="hex-col-hex">00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f</span><span className="hex-col-ascii">ASCII</span></div>{result.hex_view.map((row,i)=><div className="hex-row" key={i}><span className="hex-col-offset">{row.offset}</span><span className="hex-col-hex">{row.hex}</span><span className="hex-col-ascii">{row.ascii}</span></div>)}</div>
                            )} />}
                            {result.function_list && result.function_list.length > 0 && <CCard icon="ðŸ“œ" title="Function List" stat={`${result.function_list.length} functions`} statColor="#8b5cf6" accent="#8b5cf6" onClick={() => om('Function List','ðŸ“œ','#8b5cf6',
                                <div className="table-container"><table className="info-table"><thead><tr><th>Address</th><th>Size</th><th>Name</th></tr></thead><tbody>{result.function_list.map((fn,i)=><tr key={i}><td style={{fontFamily:'monospace',color:'var(--primary)'}}>{fn.address}</td><td style={{color:'var(--on-surface-variant)'}}>{fn.size}</td><td>{fn.name}</td></tr>)}</tbody></table></div>
                            )} />}
                            {(result.imports_exports?.imports?.length>0||result.imports_exports?.exports?.length>0) && <CCard icon="ðŸšª" title="Imports / Exports" stat={`${result.imports_exports.imports.length} imp, ${result.imports_exports.exports.length} exp`} statColor="#ec4899" accent="#ec4899" onClick={() => om('Imports & Exports','ðŸšª','#ec4899',
                                <div className="two-column-layout"><div className="column"><h4 className="column-title">Imports</h4><ul className="info-list">{result.imports_exports.imports.map((imp,i)=><li key={i}>{imp}</li>)}</ul></div><div className="column"><h4 className="column-title">Exports</h4><ul className="info-list">{result.imports_exports.exports.map((exp,i)=><li key={i}>{exp}</li>)}</ul></div></div>
                            )} />}
                        </Carousel>

                        {/* â”€â”€ Section 5: Tools â”€â”€ */}
                        <Carousel title="Tools" icon="âš¡">
                            {result.pwn_template && result.extension !== '.zip' && <CCard icon="âš¡" title="Pwntools Template" stat="Ready to download" statColor="#fbbf24" accent="#f59e0b" onClick={() => om('Pwntools Template','âš¡','#f59e0b',
                                <><div className="pwn-template-actions"><button className="pwn-action-btn" onClick={()=>navigator.clipboard.writeText(result.pwn_template)} type="button">ðŸ“‹ Copy</button><button className="pwn-action-btn" onClick={()=>{const b=new Blob([result.pwn_template],{type:'text/x-python'});const u=URL.createObjectURL(b);const a=document.createElement('a');a.href=u;a.download='exploit.py';a.click();URL.revokeObjectURL(u)}} type="button">â¬‡ï¸ Download</button></div><div className="pwn-template-body"><pre className="pwn-code">{result.pwn_template.split('\n').map((line,i)=><div className="pwn-line" key={i}><span className="pwn-line-num">{String(i+1).padStart(3,' ')}</span><span className={`pwn-line-text${line.trimStart().startsWith('#')?' pwn-comment':line.includes('from pwn')||line.includes('#!/')?' pwn-import':''}`}>{line||' '}</span></div>)}</pre></div></>
                            )} />}
                            <CCard icon="ðŸ“‹" title="Strings" stat={`${result.strings_count} extracted`} statColor="var(--primary)" accent="var(--primary)" onClick={() => om('Strings','ðŸ“‹','var(--primary)',
                                <div className="result-card-body">{result.strings.length===0?<div className="no-strings">No printable strings found.</div>:result.strings.map((s,i)=><div className="string-line" key={i}><span className="string-index">{String(i+1).padStart(4,'0')}</span>{s}</div>)}</div>
                            )} />
                            <CCard icon="ðŸš©" title="Flags Detected" stat={result.flags_detected?.length>0?`${result.flags_detected.length} found`:'None'} statColor={result.flags_detected?.length>0?'#f87171':'var(--on-surface-variant)'} accent="var(--error)" onClick={() => om('Flags Detected','ðŸš©','var(--error)',
                                <div className="result-card-body">{result.flags_detected?.length>0?result.flags_detected.map((f,i)=><div className="section-item section-item--flag" key={i}>{f}</div>):<div className="section-empty">No flags detected</div>}</div>
                            )} />
                            <CCard icon="ðŸ”" title="Interesting Findings" stat={result.patterns&&Object.keys(result.patterns).length>0?`${Object.keys(result.patterns).length} categories`:'None'} statColor="var(--secondary)" accent="var(--secondary)" onClick={() => om('Interesting Findings','ðŸ”','var(--secondary)',
                                <div className="result-card-body">{result.patterns&&Object.keys(result.patterns).length>0?Object.entries(result.patterns).map(([cat,items])=><div className="finding-category" key={cat}><span className="finding-label">{cat.replace(/_/g,' ')}:</span>{items.map((item,j)=><div className="section-item section-item--finding" key={j}>{item}</div>)}</div>):<div className="section-empty">No interesting patterns detected</div>}</div>
                            )} />
                        </Carousel>

                        {/* â”€â”€ Section 6: Quick Commands (always visible) â”€â”€ */}
                        <div className="bottom-section">
                            <div className="bottom-section-header"><span className="bottom-section-icon">ðŸ“‹</span><h3 className="bottom-section-title">Quick Commands</h3></div>
                            <div className="quick-commands">
                                {[`file ./${result.filename}`,`checksec ./${result.filename}`,`strings ./${result.filename} | grep -i flag`,`ltrace ./${result.filename}`,`strace ./${result.filename}`,`gdb -q ./${result.filename}`,`objdump -d ./${result.filename} | grep -A 20 '<main>'`,`ROPgadget --binary ./${result.filename} --rop | head -20`,`one_gadget libc.so.6`,`python3 -c "from pwn import *; cyclic(200)" | ./${result.filename}`].map((cmd,i)=>(
                                    <div className="quick-cmd-row" key={i}><code className="quick-cmd-text">{cmd}</code><button className="quick-cmd-copy" title="Copy" onClick={()=>{navigator.clipboard.writeText(cmd);const btn=document.querySelectorAll('.quick-cmd-copy')[i];if(btn){btn.textContent='âœ“';setTimeout(()=>btn.textContent='ðŸ“‹',1200)}}}>ðŸ“‹</button></div>
                                ))}
                            </div>
                        </div>

                        {/* â”€â”€ Chat (always visible) â”€â”€ */}
                        <div className="bottom-section">
                            <div className="bottom-section-header"><span className="bottom-section-icon">ðŸ’¬</span><h3 className="bottom-section-title">Follow-up Chat</h3></div>
                            <div className="chat-messages" id="chat-messages">
                                {chatMessages.map((msg,i)=>(<div className={`chat-bubble chat-bubble--${msg.role}`} key={i}><span className="chat-bubble-label">{msg.role==='user'?'You':'AI Mentor'}</span>{msg.image&&<img src={msg.image} alt="Attached" className="chat-image-preview-bubble"/>}<div className="chat-bubble-content">{msg.content.split(/\n/).filter(l=>l.trim()).map((line,j)=><div key={j}>{line}</div>)}</div></div>))}
                                {chatLoading&&<div className="chat-bubble chat-bubble--assistant"><span className="chat-bubble-label">AI Mentor</span><div className="chat-bubble-content"><span className="chat-typing">Thinking<span className="chat-dots">...</span></span></div></div>}
                                <div ref={chatEndRef}/>
                            </div>
                            {chatImage&&<div className="chat-image-bar"><img src={chatImagePreview} alt="Preview" className="chat-image-thumb"/><span className="chat-image-name">{chatImage.name}</span><button className="chat-image-remove" onClick={clearChatImage} title="Remove image"><span className="material-symbols-outlined">close</span></button></div>}
                            <div className="chat-input-row">
                                <button className="chat-image-btn" onClick={()=>chatImageRef.current?.click()} disabled={chatLoading} title="Attach screenshot" type="button">ðŸ“·</button>
                                <input ref={chatImageRef} type="file" accept="image/png,image/jpeg,image/gif,image/webp" onChange={onChatImageSelect} style={{display:'none'}}/>
                                <input className="chat-input" type="text" placeholder={chatImage?'Add a message about your screenshot...':'Ask about this binary...'} value={chatInput} onChange={e=>setChatInput(e.target.value.slice(0,MAX_CHAT_CHARS))} onKeyDown={onChatKeyDown} disabled={chatLoading} maxLength={MAX_CHAT_CHARS} id="chat-input"/>
                                <button className="chat-send-btn" onClick={sendChat} disabled={chatLoading||(!chatInput.trim()&&!chatImage)} id="chat-send-btn">{chatLoading?'...':'â–¶ Send'}</button>
                            </div>
                        </div>
                    </>
                    );
                })()}


                {/* â•â•â• Source Code Results â•â•â• */}
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
                                summary={`${sourceResult.vulnerabilities.split('\n').filter(l => l.startsWith('â€¢')).length || 0} found`}
                                variant="source-vuln"
                                openSections={openSections}
                                toggleSection={toggleSection}
                            >
                                <div className="flag-list">
                                    {sourceResult.vulnerabilities ? (
                                        sourceResult.vulnerabilities.split('\n').filter(val => val.trim()).map((line, i) => (
                                            <div key={i} className="flag-item">
                                                <span className="flag-icon">âš ï¸</span>
                                                <span className="flag-text">{line.replace(/^â€¢\s*/, '')}</span>
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
                                                <span className="flag-icon">ðŸ”´</span>
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
                                                    <span dangerouslySetInnerHTML={{ __html: line.replace(/^â€¢\s*/, '').replace(/`(.*?)`/g, '<code class="inline-code">$1</code>') }} />
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
                                                        <span dangerouslySetInnerHTML={{ __html: line.replace(/^â€¢\s*/, '').replace(/`(.*?)`/g, '<code class="inline-code">$1</code>') }} />
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

            {/* ── Card Detail Modal ── */}
            {modalData && (
                <CardModal title={modalData.title} icon={modalData.icon} accent={modalData.accent} onClose={closeModal}>
                    {modalData.content}
                </CardModal>
            )}

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
                            <span className="pwd-modal-icon">ðŸ”’</span>
                            <h2 className="pwd-modal-title">Password Protected ZIP</h2>
                        </div>
                        <p className="pwd-modal-desc">
                            This archive is encrypted. Enter the password to unlock and analyze its contents.
                        </p>

                        {passwordError && (
                            <div className="pwd-modal-error" id="password-error">
                                <span className="pwd-modal-error-icon">âš ï¸</span>
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
                                    'ðŸ”“ Unlock & Analyze'
                                )}
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}
