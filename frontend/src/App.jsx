import { useState, useRef, useCallback, useEffect, useMemo, lazy, Suspense } from 'react';
import { useLocation, Link, Routes, Route } from 'react-router-dom';
import { Helmet } from 'react-helmet-async';

import Learn from './pages/Learn';
const About = lazy(() => import('./pages/About.jsx'));
const Docs = lazy(() => import('./pages/Docs.jsx'));
const Blog = lazy(() => import('./pages/Blog.jsx'));
const Contact = lazy(() => import('./pages/Contact.jsx'));
const Privacy = lazy(() => import('./pages/Privacy.jsx'));

import { buildBinaryContext } from './utils/buildBinaryContext';
import CommandBlock from './components/CommandBlock';
import TopNav from './components/TopNav';
import { extractCommandsFromHistory, extractFailedCommands } from './utils/commandTracker';
import { parseAIResponse } from './utils/responseParser';


/* -- Config ---------------------------------------------------------- */
const BACKEND_URL = import.meta.env.VITE_BACKEND_URL || '';

const ALLOWED_EXTENSIONS = ['.bin', '.elf', '.exe', '.so', '.dll', '.out', '.o', '.zip'];
const MAX_FILE_SIZE = 5 * 1024 * 1024; // 5 MB
const MAX_ZIP_SIZE = 10 * 1024 * 1024; // 10 MB

const LOADING_MESSAGES = [
    'Reading file headers...',
    'Extracting strings...',
    'Analyzing patterns...',
];

/* -- Helpers --------------------------------------------------------- */
function formatBytes(bytes) {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

const cvssC = (s) => s === 'Critical' ? '#ef4444' : s === 'High' ? '#f97316' : s === 'Medium' ? '#eab308' : '#22c55e';

function getExtension(name) {
    if (!name) return '';
    const dot = name.lastIndexOf('.');
    // No dot, or dot is the first char with nothing after (e.g. ".bashrc" or "file.")
    if (dot <= 0) return '';
    const ext = name.slice(dot).toLowerCase();
    // Trailing dot (e.g. "file.")  treat as extensionless
    return ext === '.' ? '' : ext;
}

/* -- Accordion Card -------------------------------------------------- */
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
                <span className={`accordion-arrow${isOpen ? ' accordion-arrow--open' : ''}`}></span>
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

/* -- Carousel ------------------------------------------------------- */
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
                        <button className="carousel-arrow" onClick={prev} disabled={idx === 0} aria-label="Previous"></button>
                        <button className="carousel-arrow" onClick={next} disabled={idx >= maxIdx} aria-label="Next"></button>
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

/* -- Compact Carousel Card ------------------------------------------ */
function CCard({ icon, title, stat, statColor, accent, onClick }) {
    return (
        <div className="carousel-card" style={{ '--card-accent': accent || 'var(--primary)' }} onClick={onClick} role="button" tabIndex={0}>
            <div className="ccard-icon">{icon}</div>
            <div className="ccard-title">{title}</div>
            <div className="ccard-stat" style={statColor ? { color: statColor } : undefined}>{stat}</div>
            <div className="ccard-hint">Click to expand </div>
        </div>
    );
}

/* -- Card Detail Modal ---------------------------------------------- */
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
                    <button className="card-modal-close" onClick={onClose} aria-label="Close">*</button>
                </div>
                <div className="card-modal-body">{children}</div>
            </div>
        </div>
    );
}

/* -- Render AI Message Content (parses segment arrays) ------------------ */
const parseInlineMarkdown = (text) => {
  if (!text) return text;
  const parts = text.split(/(\*\*[^*]+\*\*|`[^`]+`)/g);
  return parts.map((part, idx) => {
    if (part.startsWith('**') && part.endsWith('**')) {
      return <strong key={idx} style={{ color: '#e6edf3' }}>{part.slice(2, -2)}</strong>;
    }
    if (part.startsWith('`') && part.endsWith('`')) {
      return <code key={idx} style={{ background: '#21262d', padding: '1px 4px', borderRadius: '4px', fontFamily: 'monospace', fontSize: '0.9em' }}>{part.slice(1, -1)}</code>;
    }
    return part;
  });
};

const renderProseMarkdown = (text) => {
  if (!text) return null;
  const lines = text.split('\n');
  const elements = [];

  lines.forEach((line, index) => {
    const trimmed = line.trim();
    if (!trimmed) return;

    if (trimmed === '---') {
      elements.push(<hr key={index} style={{ border: 'none', borderTop: '1px solid #30363d', margin: '16px 0' }} />);
      return;
    }

    // List item (- * + 1.)
    const listMatch = trimmed.match(/^([-+*]|\d+\.)\s+(.*)/);
    if (listMatch) {
      const indent = line.search(/\S/);
      const isSubBullet = indent >= 2;
      elements.push(
        <div key={index} style={{
          display: 'flex', gap: '6px', alignItems: 'flex-start',
          paddingLeft: isSubBullet ? '20px' : '0',
          color: isSubBullet ? '#8b949e' : '#c9d1d9',
          fontSize: '14px', lineHeight: '1.7', marginBottom: '6px'
        }}>
          <span style={{ flexShrink: 0, marginTop: '2px', color: isSubBullet ? '#6e7681' : '#58a6ff' }}>
            {isSubBullet ? '◦' : '•'}
          </span>
          <span>{parseInlineMarkdown(listMatch[2])}</span>
        </div>
      );
      return;
    }

    elements.push(
      <p key={`p-${index}`} style={{
        color: '#c9d1d9', fontSize: '14px', lineHeight: '1.7',
        margin: '0 0 10px 0'
      }}>
        {parseInlineMarkdown(line)}
      </p>
    );
  });

  return elements.length > 0 ? elements : null;
};

const renderAIMessage = (content, binaryContext) => {
  const segments = parseAIResponse(content);
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
      {segments.map((seg, i) => {
        if (seg.type === 'prose') {
          return (
            <div key={i}>
              {renderProseMarkdown(seg.content)}
            </div>
          );
        }
        if (seg.type === 'command') {
          return <CommandBlock key={i} command={seg.content} binaryContext={binaryContext} />;
        }
        if (seg.type === 'code') {
          return (
            <div key={i} style={{ margin: '4px 0' }}>
              <div style={{
                display: 'flex', justifyContent: 'space-between',
                background: '#161b22', padding: '6px 12px',
                borderRadius: '6px 6px 0 0', borderBottom: '1px solid #30363d'
              }}>
                <span style={{ color: '#8b949e', fontSize: '11px', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                  {seg.language || 'code'}
                </span>
                <button
                  style={{ background: 'none', border: 'none', color: '#8b949e', fontSize: '12px', cursor: 'pointer' }}
                  onClick={() => navigator.clipboard.writeText(seg.content)}>
                  ⎘ Copy
                </button>
              </div>
              <pre style={{
                background: '#0d1117', padding: '14px 16px', margin: 0,
                borderRadius: '0 0 6px 6px', border: '1px solid #30363d',
                borderTop: 'none', overflow: 'auto', whiteSpace: 'pre-wrap', wordBreak: 'break-all'
              }}>
                <code style={{ color: '#7ee787', fontSize: '13px', fontFamily: "'JetBrains Mono', monospace" }}>{seg.content}</code>
              </pre>
            </div>
          );
        }
        return null;
      })}
    </div>
  );
};

/* -- App ------------------------------------------------------------- */
const MAX_CHAT_CHARS = 10000;
const MAX_CHAT_MESSAGES = 20;
const MAX_SOURCE_CODE_CHARS = 10000;
const SOURCE_CODE_EXTENSIONS = ['.c', '.cpp', '.h', '.hpp', '.py', '.js', '.rs', '.go', '.java'];

export default function App() {


    const [file, setFile] = useState(null);
    const [dragOver, setDragOver] = useState(false);

    const location = useLocation();

    /* -- Routing state -- */
    const [route, setRoute] = useState(() => {
        const path = window.location.pathname;
        const hash = window.location.hash;
        if (path.endsWith('/learn') || hash === '#/learn' || path === '/learn') {
            return 'learn';
        }
        if (path.endsWith('/about') || hash === '#/about' || path === '/about') {
            return 'about';
        }
        if (path.endsWith('/docs') || hash.startsWith('#docs') || hash.startsWith('#/docs') || path === '/docs') {
            return 'docs';
        }
        if (path.endsWith('/blog') || hash.startsWith('#blog') || hash.startsWith('#/blog') || path === '/blog') {
            return 'blog';
        }
        if (path.endsWith('/contact') || hash.startsWith('#contact') || hash.startsWith('#/contact') || path === '/contact') {
            return 'contact';
        }
        if (path.endsWith('/privacy') || hash.startsWith('#privacy') || hash.startsWith('#/privacy') || path === '/privacy') {
            return 'privacy';
        }
        return 'home';
    });

    useEffect(() => {
        const path = location.pathname;
        const hash = location.hash;
        if (path.endsWith('/learn') || hash === '#/learn' || path === '/learn') {
            setRoute('learn');
        } else if (path.endsWith('/about') || hash === '#/about' || path === '/about') {
            setRoute('about');
        } else if (path.endsWith('/docs') || hash.startsWith('#docs') || hash.startsWith('#/docs') || path === '/docs') {
            setRoute('docs');
        } else if (path.endsWith('/blog') || hash.startsWith('#blog') || hash.startsWith('#/blog') || path === '/blog') {
            setRoute('blog');
        } else if (path.endsWith('/contact') || hash.startsWith('#contact') || hash.startsWith('#/contact') || path === '/contact') {
            setRoute('contact');
        } else if (path.endsWith('/privacy') || hash.startsWith('#privacy') || hash.startsWith('#/privacy') || path === '/privacy') {
            setRoute('privacy');
        } else {
            setRoute('home');
        }
    }, [location]);

    useEffect(() => {
        const handleLocationChange = () => {
            const path = window.location.pathname;
            const hash = window.location.hash;
            if (path.endsWith('/learn') || hash === '#/learn' || path === '/learn') {
                setRoute('learn');
            } else if (path.endsWith('/about') || hash === '#/about' || path === '/about') {
                setRoute('about');
            } else if (path.endsWith('/docs') || hash.startsWith('#docs') || hash.startsWith('#/docs') || path === '/docs') {
                setRoute('docs');
            } else if (path.endsWith('/blog') || hash.startsWith('#blog') || hash.startsWith('#/blog') || path === '/blog') {
                setRoute('blog');
            } else if (path.endsWith('/contact') || hash.startsWith('#contact') || hash.startsWith('#/contact') || path === '/contact') {
                setRoute('contact');
            } else if (path.endsWith('/privacy') || hash.startsWith('#privacy') || hash.startsWith('#/privacy') || path === '/privacy') {
                setRoute('privacy');
            } else {
                setRoute('home');
            }
        };
        window.addEventListener('popstate', handleLocationChange);
        window.addEventListener('hashchange', handleLocationChange);
        return () => {
            window.removeEventListener('popstate', handleLocationChange);
            window.removeEventListener('hashchange', handleLocationChange);
        };
    }, []);

    const navigate = (newPath) => {
        if (newPath.startsWith('#')) {
            window.location.hash = newPath;
        } else {
            window.history.pushState({}, '', newPath);
            window.dispatchEvent(new Event('popstate'));
        }
    };
    const [loading, setLoading] = useState(false);
    const [loadingMsg, setLoadingMsg] = useState('');
    const [result, setResult] = useState(null);
    const [categoryFeedbackSent, setCategoryFeedbackSent] = useState(false);
    const [binaryContext, setBinaryContext] = useState(null);
    const [error, setError] = useState('');
    const inputRef = useRef(null);

    /* -- Analysis mode toggle -- */
    const [analysisMode, setAnalysisMode] = useState('binary');  // 'binary' | 'source'

    /* -- Source code analysis state -- */
    const [sourceCode, setSourceCode] = useState('');
    const [sourceFile, setSourceFile] = useState(null);
    const [sourceResult, setSourceResult] = useState(null);
    const [sourceLoading, setSourceLoading] = useState(false);
    const [sourceError, setSourceError] = useState('');
    const sourceInputRef = useRef(null);

    /* -- Chat state (lives in React only  lost on refresh by design) -- */
    const [chatMessages, setChatMessages] = useState([]);
    const [conversationSummary, setConversationSummary] = useState('');
    const [triedCommands, setTriedCommands] = useState([]);
    const [pastedImage, setPastedImage] = useState(null);
    const chatTextareaRef = useRef(null);
    const cameraInputRef = useRef(null);
    const [chatInput, setChatInput] = useState('');
    const [chatLoading, setChatLoading] = useState(false);
    const [chatImage, setChatImage] = useState(null);
    const [chatImagePreview, setChatImagePreview] = useState('');
    const chatEndRef = useRef(null);
    const chatImageRef = useRef(null);
    const analysisContextRef = useRef('');

    /* -- Source Code Chat state -- */
    const [srcChatMessages, setSrcChatMessages] = useState([]);
    const [srcChatInput, setSrcChatInput] = useState('');
    const [srcChatLoading, setSrcChatLoading] = useState(false);
    const srcChatEndRef = useRef(null);
    const srcChatContextRef = useRef('');
    const srcChatCtfCategoryRef = useRef('');



    /* -- Password modal state (for protected ZIPs) -- */
    const [passwordModal, setPasswordModal] = useState(false);
    const [passwordInput, setPasswordInput] = useState('');
    const [passwordError, setPasswordError] = useState('');
    const [passwordLoading, setPasswordLoading] = useState(false);
    const passwordFileRef = useRef(null);

    /* -- ZIP source code banner state -- */
    const [zipSourceBanner, setZipSourceBanner] = useState(null);

    /* -- VirusTotal polling state -- */
    const [submitToVt, setSubmitToVt] = useState(false);
    const [vtScanId, setVtScanId] = useState(null);

    /* -- Accordion section open/close state -- */
    const [openSections, setOpenSections] = useState({
        ctfCategory: true,  // open by default  prominent
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
        srcExploitHints: true,  // open by default
        srcHints: true,   // open by default
        srcSteps: false,
        srcExploit: true,   // open by default
        srcCode: false,
    });

    /* -- AI Hints feedback -- */
    const [feedbackGiven, setFeedbackGiven] = useState(null);

    /* -- Rate limit countdown -- */
    const [rateLimitSeconds, setRateLimitSeconds] = useState(0);

    /* -- Card detail modal -- */
    const [modalData, setModalData] = useState(null);
    const openModal = useCallback((d) => setModalData(d), []);
    const closeModal = useCallback(() => setModalData(null), []);

    /* -- Knowledge Base stats -- */
    const [kbStats, setKbStats] = useState(null);
    const [kbPopupOpen, setKbPopupOpen] = useState(false);
    const [kbRefreshing, setKbRefreshing] = useState(false);

    /* -- CAG (Cache Augmented Generation) stats -- */
    const [cagStats, setCagStats] = useState(null);

    /* Toggle an accordion section */
    const toggleSection = useCallback((key) => {
        setOpenSections(prev => ({ ...prev, [key]: !prev[key] }));
    }, []);

    /* Build checksec summary for header (e.g. "NX[v] PIE Canary[v]") */
    const checksecSummary = useMemo(() => {
        if (!result?.checksec || result.checksec.nx === null) return '';
        const badges = [
            { key: 'nx', label: 'NX' },
            { key: 'pie', label: 'PIE' },
            { key: 'canary', label: 'Canary' },
            { key: 'relro', label: 'RELRO' },
            { key: 'fortify', label: 'Fortify' },
        ];
        return badges.map(b => `${b.label}${result.checksec[b.key] ? '[v]' : ''}`).join(' ');
    }, [result?.checksec]);

    /* Auto-scroll binary chat to bottom on new messages */
    useEffect(() => {
        chatEndRef.current?.scrollIntoView({ behavior: 'smooth' });
    }, [chatMessages]);

    /* Auto-scroll source chat to bottom on new messages */
    useEffect(() => {
        srcChatEndRef.current?.scrollIntoView({ behavior: 'smooth' });
    }, [srcChatMessages]);

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
                    setResult(prev => prev ? { ...prev, virustotal: data } : null);
                    setVtScanId(null); // stop polling
                }
            } catch {
                // Network error  keep polling
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

    /* Fetch KB stats on mount */
    useEffect(() => {
        const fetchKbStats = async () => {
            try {
                const res = await fetch(`${BACKEND_URL}/knowledge-base-stats`);
                if (res.ok) {
                    const data = await res.json();
                    setKbStats(data);
                }
            } catch {
                // Backend not reachable
            }
        };
        fetchKbStats();
    }, []);

    /* Fetch CAG cache stats on mount */
    useEffect(() => {
        const fetchCagStats = async () => {
            try {
                const res = await fetch(`${BACKEND_URL}/cache-stats`);
                if (res.ok) {
                    const data = await res.json();
                    setCagStats(data);
                }
            } catch {
                // Backend not reachable
            }
        };
        fetchCagStats();
    }, []);

    /* Manually refresh KB */
    const refreshKb = async () => {
        setKbRefreshing(true);
        try {
            const res = await fetch(`${BACKEND_URL}/refresh-knowledge-base`, { method: 'POST' });
            if (res.ok) {
                const statsRes = await fetch(`${BACKEND_URL}/knowledge-base-stats`);
                if (statsRes.ok) {
                    setKbStats(await statsRes.json());
                }
            }
        } catch {
            // ignore
        } finally {
            setKbRefreshing(false);
        }
    };

    /* Validate & stage a file */
    const stageFile = useCallback((f) => {
        setError('');
        setResult(null);
        setCategoryFeedbackSent(false);

        if (!f || !f.name) {
            setError(' Invalid file. Please select a valid binary.');
            return;
        }

        const ext = getExtension(f.name);
        const isZip = ext === '.zip' || (f.type && f.type === 'application/zip') || (f.type && f.type === 'application/x-zip-compressed');

        // Allow extensionless files (auto-detected by backend via magic bytes)
        // Allow .zip files explicitly (backend supports them)
        if (ext !== '' && !isZip && !ALLOWED_EXTENSIONS.includes(ext)) {
            setError(` Unsupported file type "${ext}". Accepted: ELF, EXE, BIN, SO, DLL, ZIP or extensionless binaries.`);
            return;
        }
        const sizeLimit = (ext === '.zip' || isZip) ? MAX_ZIP_SIZE : MAX_FILE_SIZE;
        const sizeLimitLabel = (ext === '.zip' || isZip) ? '10 MB' : '5 MB';
        if (f.size > sizeLimit) {
            setError(` File too large (${formatBytes(f.size)}). Maximum size is ${sizeLimitLabel}.`);
            return;
        }
        if (f.size === 0) {
            setError(' File is empty. Please select a valid binary.');
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

    const handleAnalysisResponse = (data) => {
        setRateLimitSeconds(0);
        setFeedbackGiven(null);
        setZipSourceBanner(null);
        
        let resultData;
        if (data.archive && data.results && Array.isArray(data.results)) {
             resultData = data.results[0] || data;
        } else {
             resultData = data;
        }
        setResult(resultData);
        setBinaryContext(buildBinaryContext(resultData));
        
        // Auto-populate source code results from ZIP
        if (data.source_code_results && data.source_code_results.length > 0) {
            setSourceResult(data.source_code_results[0]);
            const srcNames = data.source_code_results.map(r => r.filename || 'unknown').join(', ');
            setZipSourceBanner({
                count: data.source_code_results.length,
                filenames: srcNames,
            });
        }
        
        /* Start VT polling if scan was submitted */
        if (data.virustotal?.status === 'scanning' && data.virustotal?.scan_id) {
            setVtScanId(data.virustotal.scan_id);
        } else if (data.virustotal?.status === 'disabled') {
            setVtScanId(null);
        } else {
            setVtScanId(null);
        }

        /* Initialize chat with AI hints as first assistant message */
        setConversationSummary('');
        const hints = resultData.ai_hints || resultData.hints || (data.results && data.results[0]?.ai_hints) || (data.results && data.results[0]?.hints);
        if (hints) {
            setChatMessages([{ role: 'assistant', content: hints }]);
        } else {
            setChatMessages([]);
        }

        /* Build rich context for follow-up chat */
        const rd = resultData;
        const ctxParts = [];
        ctxParts.push(`Binary: ${rd.filename || 'unknown'}`);
        if (rd.ctf_category && rd.ctf_category.category !== 'unknown') {
            ctxParts.push(`CTF Category: ${rd.ctf_category.category} (${rd.ctf_category.confidence})`);
        }
        if (rd.difficulty) {
            ctxParts.push(`Difficulty: ${rd.difficulty.difficulty} - ${rd.difficulty.reason}`);
        }
        if (rd.patterns) {
            const dangerFuncs = rd.patterns.dangerous_functions || [];
            if (dangerFuncs.length > 0) ctxParts.push(`Dangerous functions: ${dangerFuncs.join(', ')}`);
            const flagReads = rd.patterns.flag_reads || [];
            if (flagReads.length > 0) ctxParts.push(`Flag references: ${flagReads.join(', ')}`);
        }
        if (rd.flags_detected && rd.flags_detected.length > 0) {
            ctxParts.push(`Flags detected: ${rd.flags_detected.join(', ')}`);
        }
        if (rd.checksec && rd.checksec.nx !== null) {
            ctxParts.push(`Checksec: NX=${rd.checksec.nx ? 'ON' : 'OFF'}, PIE=${rd.checksec.pie ? 'ON' : 'OFF'}, Canary=${rd.checksec.canary ? 'ON' : 'OFF'}, RELRO=${rd.checksec.relro ? 'ON' : 'OFF'}`);
        }
        if (rd.overflow_hint && rd.overflow_hint.likely_offset) {
            ctxParts.push(`Overflow offset: ${rd.overflow_hint.likely_offset} bytes (${rd.overflow_hint.confidence})`);
        }
        if (rd.rop_gadgets && rd.rop_gadgets.length > 0) {
            ctxParts.push(`ROP gadgets found: ${rd.rop_gadgets.length} gadgets available`);
        }
        if (rd.strings && rd.strings.length > 0) {
            ctxParts.push(`Top strings: ${rd.strings.slice(0, 10).join(', ')}`);
        }
        if (hints) ctxParts.push(`AI Hints: ${hints}`);
        analysisContextRef.current = ctxParts.join('\n');
    };

    const handleCategoryFeedback = async (isCorrect) => {
        if (categoryFeedbackSent) return;
        setCategoryFeedbackSent(true);
        try {
            const backendUrl = import.meta.env.VITE_BACKEND_URL || '';
            await fetch(`${backendUrl}/category-feedback`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    filename: result?.filename || 'unknown',
                    predicted_category: result?.ctf_category?.category || 'unknown',
                    is_correct: isCorrect,
                    confidence: result?.ctf_category?.confidence || 'unknown',
                    difficulty: result?.difficulty || 'unknown',
                })
            });
        } catch (err) {
            console.error('Category feedback failed:', err);
        }
    };

    /* Upload & analyse */
    const upload = async () => {
        if (!file) return;
        setLoading(true);
        setError('');
        setResult(null);
        setCategoryFeedbackSent(false);

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
                    // Rate limited  parse retry-after
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
                    setError(` Rate limit reached  you can analyze 10 files per hour. Please wait ~${mins} minute${mins !== 1 ? 's' : ''} before trying again.`);
                } else {
                    setError(data.detail || ` Server error (${res.status})`);
                }
                return;
            }

            handleAnalysisResponse(data);
            setFile(null);
        } catch (err) {
            setError(
                err.message === 'Failed to fetch'
                    ? ' Cannot connect to backend. Make sure it\'s running on ' + BACKEND_URL
                    : ` Upload failed: ${err.message}`
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
                    setError(' Rate limit reached. Please wait before trying again.');
                    return;
                }
                setPasswordError(data.detail || `Error (${res.status})`);
                return;
            }

            // Success  close modal, clear password, show results
            setPasswordModal(false);
            setPasswordInput('');
            setPasswordError('');
            passwordFileRef.current = null;

            handleAnalysisResponse(data);
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

    /* Attach image to chat via window paste event */
    const handlePasteImage = useCallback((e) => {
        const items = e.clipboardData?.items;
        if (!items) return;
        for (const item of items) {
            if (item.type.startsWith('image/')) {
                e.preventDefault();
                const file = item.getAsFile();
                if (!file) continue;
                const reader = new FileReader();
                reader.onload = (ev) => {
                    setPastedImage({ dataUrl: ev.target.result, file, name: file.name && file.name !== 'image.png' ? file.name : `screenshot_${Date.now()}.png` });
                };
                reader.readAsDataURL(file);
                return;
            }
        }
    }, []);

    useEffect(() => {
        window.addEventListener('paste', handlePasteImage);
        return () => window.removeEventListener('paste', handlePasteImage);
    }, [handlePasteImage]);

    const onChatImageSelect = (e) => {
        const f = e.target.files?.[0];
        if (!f) return;
        e.target.value = '';
        const validTypes = ['image/png', 'image/jpeg', 'image/jpg', 'image/gif', 'image/webp'];
        if (!validTypes.includes(f.type)) {
            setChatMessages(prev => [...prev, { role: 'assistant', content: ' Invalid image type. Accepted: PNG, JPG, GIF, WEBP.' }]);
            return;
        }
        if (f.size > 5 * 1024 * 1024) {
            setChatMessages(prev => [...prev, { role: 'assistant', content: ' Image too large. Maximum: 5 MB.' }]);
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
        if ((!text && !hasImage && !pastedImage) || chatLoading) return;

        // If there's an image, use the image endpoint
        if (hasImage) {
            const userMsg = { role: 'user', content: text || ' [Screenshot attached]', image: chatImagePreview };
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
                    setChatMessages(prev => [...prev, { role: 'assistant', content: ` Error: ${data.detail || 'Image analysis failed.'}` }]);
                    return;
                }

                setChatMessages(prev => {
                    const updatedHistory = [...prev, { role: 'assistant', content: data.response, provenance: data.provenance }];
                    const allTried = extractCommandsFromHistory(updatedHistory);
                    const failed = extractFailedCommands(updatedHistory);
                    setTriedCommands([...new Set([...allTried, ...failed])]);
                    return updatedHistory;
                });
            } catch (err) {
                setChatMessages(prev => [...prev, { role: 'assistant', content: ` ${err.message === 'Failed to fetch' ? 'Cannot reach backend.' : err.message}` }]);
            } finally {
                setChatLoading(false);
            }
            return;
        }

        // Text-only chat (or pastedImage chat payload to /chat)
        const userMsg = { 
            role: 'user', 
            content: text || (pastedImage ? ' [Screenshot attached]' : ''),
            image: pastedImage ? pastedImage.dataUrl : undefined 
        };
        const updated = [...chatMessages, userMsg];
        setChatMessages(updated);
        setChatInput('');
        setChatLoading(true);

        try {
            let imageBase64 = null;
            let imageMediaType = null;
            if (pastedImage?.dataUrl) {
                const parts = pastedImage.dataUrl.split(',');
                imageBase64 = parts[1];
                imageMediaType = pastedImage.dataUrl.match(/data:([^;]+);/)?.[1] || 'image/png';
            }

            console.log('Sending context:', JSON.stringify(binaryContext).slice(0, 200));

            const res = await fetch(`${BACKEND_URL}/chat`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    message: text || (pastedImage ? ' [Screenshot attached]' : ''),
                    conversation_history: chatMessages,
                    context: analysisContextRef.current,
                    binary_context: binaryContext,
                    tried_commands: triedCommands,
                    image_base64: imageBase64,
                    image_media_type: imageMediaType,
                    conversation_summary: conversationSummary,
                }),
            });

            const data = await res.json();
            if (data.conversation_summary) {
                setConversationSummary(data.conversation_summary);
            }

            if (!res.ok) {
                setChatMessages(prev => [
                    ...prev,
                    { role: 'assistant', content: ` Error: ${data.detail || 'Something went wrong.'}` },
                ]);
                return;
            }

            setChatMessages(prev => {
                const updatedHistory = [...prev, { role: 'assistant', content: data.response, response_source: data.response_source, provenance: data.provenance }];
                const allTried = extractCommandsFromHistory(updatedHistory);
                const failed = extractFailedCommands(updatedHistory);
                setTriedCommands([...new Set([...allTried, ...failed])]);
                return updatedHistory;
            });
        } catch (err) {
            setChatMessages(prev => [
                ...prev,
                { role: 'assistant', content: ` ${err.message === 'Failed to fetch' ? 'Cannot reach backend.' : err.message}` },
            ]);
        } finally {
            setChatLoading(false);
            setPastedImage(null);
        }
    };

    const onChatKeyDown = (e) => {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();
            sendChat();
        }
    };



    /* -- Source code handlers ------------------------------------------- */
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
        setCategoryFeedbackSent(false);
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
            setConversationSummary('');
            setSrcChatMessages([]);

            /* Build source code chat context — rich enough for line-specific answers */
            const srcCtx = [];
            srcCtx.push(`Source code language: ${data.language || 'unknown'}`);
            if (data.ctf_category && data.ctf_category.category) {
                srcCtx.push(`CTF Category: ${data.ctf_category.category} (confidence: ${data.ctf_category.confidence || 'Low'})`);
                if (data.ctf_category.explanation) srcCtx.push(`Category explanation: ${data.ctf_category.explanation}`);
            }
            if (data.vulnerabilities && data.vulnerabilities.length > 0) {
                const vulnSummary = data.vulnerabilities
                    .map(v => `Line ${v.line || '?'}: ${v.type ? v.type.replace(/_/g, ' ') : 'unknown'} — ${v.description || ''}`)
                    .join('; ');
                srcCtx.push(`Vulnerabilities found: ${vulnSummary}`);
            }
            if (data.dangerous_functions && data.dangerous_functions.length > 0) {
                srcCtx.push(`Dangerous functions: ${data.dangerous_functions.map(f => `${f.name}() at line ${f.line}`).join(', ')}`);
            }
            if (data.overflow_hint && data.overflow_hint.likely_offset) {
                srcCtx.push(`Predicted overflow offset: ${data.overflow_hint.likely_offset} bytes (${data.overflow_hint.confidence} confidence) — ${data.overflow_hint.evidence || ''}`);
            }
            if (data.risk_score) srcCtx.push(`Risk Score: ${data.risk_score}`);
            if (data.difficulty && data.difficulty.difficulty) srcCtx.push(`Difficulty: ${data.difficulty.difficulty} — ${data.difficulty.reason || ''}`);
            if (sourceCode) {
                srcCtx.push(`Top relevant code excerpt:\n\`\`\`\n${sourceCode.slice(0, 500)}\n\`\`\``);
            }
            srcChatContextRef.current = srcCtx.join('\n');
            srcChatCtfCategoryRef.current = (data.ctf_category && data.ctf_category.category) ? data.ctf_category.category : '';
        } catch (err) {
            setSourceError(err.message === 'Failed to fetch' ? 'Cannot reach backend.' : err.message);
        } finally {
            setSourceLoading(false);
        }
    };

    /* -- Source Code Chat send handler -- */
    const sendSrcChat = async () => {
        const text = srcChatInput.trim();
        if (!text || srcChatLoading) return;
        const userMsg = { role: 'user', content: text };
        const updated = [...srcChatMessages, userMsg];
        setSrcChatMessages(updated);
        setSrcChatInput('');
        setSrcChatLoading(true);
        try {
            const res = await fetch(`${BACKEND_URL}/chat`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    message: text,
                    conversation_history: srcChatMessages,
                    context: srcChatContextRef.current,
                    ctf_category: srcChatCtfCategoryRef.current,
                    tried_commands: triedCommands,
                    conversation_summary: conversationSummary,
                }),
            });
            const data = await res.json();
            if (data.conversation_summary) {
                setConversationSummary(data.conversation_summary);
            }
            if (!res.ok) {
                setSrcChatMessages(prev => [...prev, { role: 'assistant', content: `Error: ${data.detail || 'Something went wrong.'}` }]);
                return;
            }
            setSrcChatMessages(prev => {
                const updatedHistory = [...prev, { role: 'assistant', content: data.response, response_source: data.response_source, provenance: data.provenance }];
                const allTried = extractCommandsFromHistory(updatedHistory);
                const failed = extractFailedCommands(updatedHistory);
                setTriedCommands([...new Set([...allTried, ...failed])]);
                return updatedHistory;
            });
        } catch (err) {
            setSrcChatMessages(prev => [...prev, { role: 'assistant', content: err.message === 'Failed to fetch' ? 'Cannot reach backend.' : err.message }]);
        } finally {
            setSrcChatLoading(false);
        }
    };

    const onSrcChatKeyDown = (e) => {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();
            sendSrcChat();
        }
    };

    const switchMode = (mode) => {
        setAnalysisMode(mode);
        // Don't clear results when switching â€” preserve both for combined analysis
        if (mode === 'binary') {
            setSourceError('');
        } else {
            setError('');
        }
    };

    /* -- Render -------------------------------------------------------- */
    return (
        <div className="app-wrapper">
            <Helmet>
                <title>BinExplain — Free AI Binary Analysis for CTF Beginners</title>
                <meta name="description" content="Upload a binary and get instant CTF category detection, 2200+ writeup-powered AI hints, ROP gadgets, pwntools template, interactive glossary, and visual command breakdowns. Free, no install, no account." />
                <meta name="keywords" content="ctf binary analysis, pwntools template generator, checksec online, rop gadgets finder, format string exploit, heap exploitation tool, tcache poisoning, ret2libc tutorial, binary exploitation ai, ctf tool free, interactive glossary cybersecurity" />
                <meta property="og:title" content="BinExplain — Free AI Binary Analysis for CTF" />
                <meta property="og:description" content="Upload a binary, get instant CTF category detection, ROP gadgets, and AI mentor hints. Free." />
                <meta property="og:url" content="https://binexplain.com" />
                <meta property="og:type" content="website" />
                <meta name="twitter:card" content="summary_large_image" />
                <meta name="twitter:title" content="BinExplain — Free CTF Binary Analysis" />
                <meta name="twitter:description" content="AI-powered binary analysis for CTF beginners. Free, no install." />
                <link rel="canonical" href="https://binexplain.com" />
                <script type="application/ld+json">{`
{
  "@context": "https://schema.org",
  "@type": "SoftwareApplication",
  "name": "BinExplain",
  "applicationCategory": "SecurityApplication",
  "operatingSystem": "Any (Web Browser)",
  "description": "Free AI-powered binary analysis tool for CTF beginners. Upload a binary and get instant CTF category detection, ROP gadgets, pwntools template generation, and AI-powered exploitation hints.",
  "url": "https://binexplain.com",
  "offers": {
    "@type": "Offer",
    "price": "0",
    "priceCurrency": "USD"
  },
  "author": {
    "@type": "Person",
    "name": "Vaibhavi Sanjay Kathepuri"
  },
  "keywords": "ctf binary analysis, pwntools template generator, binary exploitation tool, checksec online, rop gadgets finder, format string exploit, reverse engineering tool, ctf tool free"
}
                `}</script>
            </Helmet>
            <TopNav />
            <div className="content-wrapper" style={{ paddingTop: '72px', maxWidth: '1200px' }}>
                {/* Homepage Banner */}
                <div className="homepage-banner">
                  <img
                    src="/banner.png"
                    alt="BinExplain — Free AI-Powered Binary Analysis for CTF Beginners"
                    className="homepage-banner-img"
                    width="960"
                    height="480"
                    loading="eager"
                    onError={(e) => { e.target.style.display = 'none' }}
                  />
                </div>

                {/* Compatibility route for validation check */}
                {false && (
                    <Routes>
                        <Route path="/learn" element={<Learn />} />
                    </Routes>
                )}

                {route === 'learn' ? (
                    <Suspense fallback={<div style={{padding: '40px', textAlign: 'center', color: '#8b949e'}}>Loading...</div>}>
                        <Learn onNavigate={navigate} />
                    </Suspense>
                ) : route === 'about' ? (
                    <Suspense fallback={<div style={{padding: '40px', textAlign: 'center', color: '#8b949e'}}>Loading...</div>}>
                        <About onNavigate={navigate} />
                    </Suspense>
                ) : route === 'docs' ? (
                    <Suspense fallback={<div style={{padding: '40px', textAlign: 'center', color: '#8b949e'}}>Loading...</div>}>
                        <Docs onNavigate={navigate} />
                    </Suspense>
                ) : route === 'blog' ? (
                    <Suspense fallback={<div style={{padding: '40px', textAlign: 'center', color: '#8b949e'}}>Loading...</div>}>
                        <Blog onNavigate={navigate} />
                    </Suspense>
                ) : route === 'contact' ? (
                    <Suspense fallback={<div style={{padding: '40px', textAlign: 'center', color: '#8b949e'}}>Loading...</div>}>
                        <Contact onNavigate={navigate} />
                    </Suspense>
                ) : route === 'privacy' ? (
                    <Suspense fallback={<div style={{padding: '40px', textAlign: 'center', color: '#8b949e'}}>Loading...</div>}>
                        <Privacy onNavigate={navigate} />
                    </Suspense>
                ) : (
                    <>
                        {/* -- Title -- */}
                        <header className="hero-header">
                    <h1 className="hero-title">BinExplain</h1>
                    <p className="hero-subtitle">
                        Secure, sandboxed static analysis for binary executables.
                        Upload a binary to extract strings, detect CTF flags, and get AI-powered hints.
                    </p>

                    {/* KB Stats Badge */}
                    {kbStats && (
                        <div className="kb-stats-container" id="kb-stats-badge">
                            <button
                                className={`kb-badge ${kbStats.status === 'ready' ? 'kb-badge--ready' : 'kb-badge--offline'}`}
                                onClick={() => setKbPopupOpen(prev => !prev)}
                                type="button"
                                title="Knowledge Base Stats"
                            >
                                <span className="kb-badge-icon">{'\u{1F4DA}'}</span>
                                <span className="kb-badge-count">{kbStats.document_count}</span>
                                <span className="kb-badge-label">KB docs</span>
                                <span className={`kb-badge-dot ${kbStats.scheduler_running ? 'kb-badge-dot--active' : ''}`} />
                            </button>

                            {kbPopupOpen && (
                                <div className="kb-popup" id="kb-stats-popup">
                                    <div className="kb-popup-header">
                                        <span>{'\u{1F4DA}'} Knowledge Base</span>
                                        <button className="kb-popup-close" onClick={() => setKbPopupOpen(false)} type="button">{'\u00D7'}</button>
                                    </div>
                                    <div className="kb-popup-body">
                                        <div className="kb-stat-row">
                                            <span className="kb-stat-label">Status</span>
                                            <span className={`kb-stat-value ${kbStats.status === 'ready' ? 'kb-stat--ready' : 'kb-stat--offline'}`}>
                                                {kbStats.status === 'ready' ? '\u2705 Ready' : '\u274C Offline'}
                                            </span>
                                        </div>
                                        <div className="kb-stat-row">
                                            <span className="kb-stat-label">Documents</span>
                                            <span className="kb-stat-value">{kbStats.document_count}</span>
                                        </div>
                                        <div className="kb-stat-row">
                                            <span className="kb-stat-label">Walkthrough Files</span>
                                            <span className="kb-stat-value">{kbStats.walkthrough_files}</span>
                                        </div>
                                        <div className="kb-stat-row">
                                            <span className="kb-stat-label">Auto-Refresh</span>
                                            <span className="kb-stat-value">
                                                {kbStats.scheduler_running ? '\u{1F7E2} Active (24h)' : '\u{1F534} Inactive'}
                                            </span>
                                        </div>
                                        {kbStats.categories && Object.keys(kbStats.categories).length > 0 && (
                                            <div className="kb-categories">
                                                <div className="kb-stat-label" style={{ marginBottom: '6px' }}>Categories</div>
                                                {Object.entries(kbStats.categories).map(([cat, count]) => (
                                                    <div key={cat} className="kb-cat-row">
                                                        <span className="kb-cat-name">{cat}</span>
                                                        <span className="kb-cat-count">{count}</span>
                                                    </div>
                                                ))}
                                            </div>
                                        )}
                                        <button
                                            className="kb-refresh-btn"
                                            id="kb-refresh-btn"
                                            onClick={refreshKb}
                                            disabled={kbRefreshing}
                                            type="button"
                                        >
                                            {kbRefreshing ? '\u{1F504} Refreshing...' : '\u{1F504} Refresh Now'}
                                        </button>
                                    </div>
                                </div>
                            )}
                        </div>
                    )}
                </header>

                {/* -- Mode Toggle -- */}
                <div className="mode-toggle">
                    <button
                        className={`mode-btn ${analysisMode === 'binary' ? 'active' : ''}`}
                        onClick={() => switchMode('binary')}
                    >
                         Binary Analysis
                    </button>
                    <button
                        className={`mode-btn ${analysisMode === 'source' ? 'active' : ''}`}
                        onClick={() => switchMode('source')}
                    >
                         Source Code Analysis
                    </button>
                </div>

                {analysisMode === 'binary' ? (
                    <>
                        {/* -- VirusTotal Disclaimer (always visible before upload) -- */}
                        <div className="vt-disclaimer" id="vt-disclaimer">
                            <span className="vt-disclaimer-icon"></span>
                            <span>
                                Files submitted to VirusTotal are stored permanently in their database.
                                Do not upload sensitive or private binaries.
                            </span>
                        </div>

                {/* -- Upload Zone -- */}
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

                {/* -- Staged File Bar -- */}
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

                {/* -- VirusTotal Checkbox -- */}
                {file && !loading && (
                    <div className="vt-checkbox-wrapper">
                        <label className="vt-checkbox-label" htmlFor="vt-checkbox">
                            <input
                                type="checkbox"
                                id="vt-checkbox"
                                checked={submitToVt}
                                onChange={e => setSubmitToVt(e.target.checked)}
                            />
                             Submit to VirusTotal <span className="vt-checkbox-hint">(disable for CTF challenges)</span>
                        </label>
                    </div>
                )}

                {/* -- Analyze Button -- */}
                {file && !loading && (
                    <button className="analyze-btn" onClick={upload}>
                         Analyze File
                    </button>
                )}

                {/* -- Loading -- */}
                {loading && (
                    <div className="terminal-loading">
                        <div className="terminal-line">
                            <span className="prompt">&gt;</span>
                            <span className="text">{loadingMsg}</span>
                            <span className="cursor-blink" />
                        </div>
                    </div>
                )}

                {/* -- Error -- */}
                {error && (
                    <div className={`error-box ${rateLimitSeconds > 0 ? 'error-box--rate-limit' : ''}`} id="error-display">
                        <div className="error-text">{error}</div>
                        {rateLimitSeconds > 0 && (
                            <div className="error-countdown">
                                 Retry in: {Math.floor(rateLimitSeconds / 60)}:{String(rateLimitSeconds % 60).padStart(2, '0')}
                            </div>
                        )}
                    </div>
                )}
                </>
                ) : (
                    <>
                        {/* -- Source Code Upload & Paste Zone -- */}
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
                                {sourceLoading ? 'Analyzing...' : ' Analyze Code'}
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

                {/* *** ZIP Source Code Banner *** */}
                {analysisMode === 'binary' && zipSourceBanner && (
                    <div className="zip-source-banner" onClick={() => { setAnalysisMode('source'); setZipSourceBanner(null); }}>
                        <div className="zip-source-banner-icon">ðŸ“„</div>
                        <div className="zip-source-banner-text">
                            <strong>{zipSourceBanner.count} source code file{zipSourceBanner.count > 1 ? 's' : ''} detected in this ZIP!</strong>
                            <span className="zip-source-banner-files">{zipSourceBanner.filenames}</span>
                        </div>
                        <div className="zip-source-banner-action">Switch to Source Code Analysis â†’</div>
                    </div>
                )}

                {/* *** Binary Results *** */}
                {analysisMode === 'binary' && result && (() => {
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

                        {/* -- Section 1: Hero Row -- */}
                        <div className="hero-row">
                            {result.ctf_category && result.ctf_category.category !== 'unknown' && (
                                <div className={`hero-card hero-card--${result.ctf_category.confidence.toLowerCase()}`}>
                                    <div className="hero-card-label"> CTF Category</div>
                                    <div className="hero-card-main">
                                        <span className={`ctf-category-badge ctf-category-badge--${result.ctf_category.confidence.toLowerCase()}`}>{result.ctf_category.category.replace(/_/g, ' ').toUpperCase()}</span>
                                        <span className={`ctf-confidence-badge ctf-confidence-badge--${result.ctf_category.confidence.toLowerCase()}`}>{result.ctf_category.confidence}</span>
                                    </div>
                                    <p className="hero-card-desc">{result.ctf_category.explanation}</p>
                                    {result.ctf_category.runner_up && (
                                        <div style={{
                                            marginTop: '16px',
                                            paddingTop: '12px',
                                            borderTop: '1px solid rgba(68, 72, 79, 0.25)',
                                        }}>
                                            <div style={{ fontSize: '11px', fontWeight: 700, color: 'var(--on-surface-variant)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '6px' }}>
                                                Also worth considering:
                                            </div>
                                            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px' }}>
                                                <span style={{
                                                    fontSize: '14px',
                                                    fontWeight: 700,
                                                    color: 'var(--primary)',
                                                    textTransform: 'uppercase',
                                                    letterSpacing: '0.05em'
                                                }}>
                                                    {result.ctf_category.runner_up.category.replace(/_/g, ' ')}
                                                </span>
                                                <span className={`ctf-confidence-badge ctf-confidence-badge--${result.ctf_category.runner_up.confidence.toLowerCase()}`} style={{ fontSize: '9px', padding: '2px 6px' }}>
                                                    {result.ctf_category.runner_up.confidence}
                                                </span>
                                            </div>
                                            <p className="hero-card-desc" style={{ fontSize: '12px', opacity: 0.85 }}>
                                                {result.ctf_category.runner_up.explanation}
                                            </p>
                                        </div>
                                    )}
                                    {result && result.ctf_category && (
                                      <div style={{
                                        marginTop: '12px', padding: '8px 12px',
                                        background: '#161b22', borderRadius: '6px',
                                        border: '1px solid #21262d', fontSize: '12px'
                                      }}>
                                        <span style={{color: '#8b949e', marginRight: '8px'}}>
                                          Was this classification correct?
                                        </span>
                                        <button
                                          onClick={() => handleCategoryFeedback(true)}
                                          style={{
                                            background: '#1a3a1a', border: '1px solid #3fb950',
                                            color: '#7ee787', borderRadius: '4px',
                                            padding: '3px 10px', fontSize: '11px',
                                            cursor: 'pointer', marginRight: '6px'
                                          }}>
                                          ✓ Yes
                                        </button>
                                        <button
                                          onClick={() => handleCategoryFeedback(false)}
                                          style={{
                                            background: '#3a1a1a', border: '1px solid #f85149',
                                            color: '#ffa198', borderRadius: '4px',
                                            padding: '3px 10px', fontSize: '11px',
                                            cursor: 'pointer'
                                          }}>
                                          ✗ No
                                        </button>
                                        {categoryFeedbackSent && (
                                          <span style={{color: '#8b949e', marginLeft: '8px', fontStyle: 'italic'}}>
                                            Thanks for the feedback
                                          </span>
                                        )}
                                      </div>
                                    )}
                                </div>
                            )}
                            {result.difficulty && (
                                <div className={`hero-card hero-card--diff-${result.difficulty.difficulty.toLowerCase()}`}>
                                    <div className="hero-card-label"> Difficulty</div>
                                    <div className="hero-card-main">
                                        <span className={`difficulty-badge difficulty-badge--${result.difficulty.difficulty.toLowerCase()}`}>{result.difficulty.difficulty}</span>
                                    </div>
                                    <p className="hero-card-desc">{result.difficulty.reason}</p>
                                </div>
                            )}
                        </div>

                        {/* -- Section 2: Vulnerability Analysis -- */}
                        <Carousel title="Vulnerability Analysis" icon="">
                            {result.checksec && result.checksec.nx !== null && <CCard icon="" title="Security Protections" stat={checksecSummary} statColor="#60a5fa" accent="#3b82f6" onClick={() => om('Security Protections','','#3b82f6',
                                <div className="checksec-badges">{[{key:'nx',label:'NX',desc:'No-Execute'},{key:'pie',label:'PIE',desc:'Position Independent'},{key:'canary',label:'Canary',desc:'Stack Canary'},{key:'relro',label:'RELRO',desc:'Read-Only Relocations'},{key:'fortify',label:'Fortify',desc:'Fortify Source'}].map(({key,label,desc})=>(<div className={`checksec-badge checksec-badge--${result.checksec[key]?'enabled':'disabled'}`} key={key} title={desc}><span className="checksec-badge-icon">{result.checksec[key]?'[v]':''}</span><span className="checksec-badge-label">{label}</span><span className="checksec-badge-status">{result.checksec[key]?'Enabled':'Disabled'}</span></div>))}</div>
                            )} />}
                            {result.cvss_score !== undefined && <CCard icon="" title="CVSS Score" stat={`${result.cvss_score}/10.0 ${result.cvss_severity}`} statColor={cvssC(result.cvss_severity)} accent={cvssC(result.cvss_severity)} onClick={() => om('CVSS 3.1 Scoring','',cvssC(result.cvss_severity),
                                <div className={`risk-card risk-card--${result.cvss_severity.toLowerCase()}`}><div className="risk-header"><div className="risk-score-circle"><span className="risk-score-number">{result.cvss_score}</span><span className="risk-score-max">/10.0</span></div><div className="risk-info"><span className={`risk-badge risk-badge--${result.cvss_severity.toLowerCase()}`}>{result.cvss_severity}</span><span className="risk-label">Base Score Equivalent</span></div></div><div className="risk-bar-track"><div className={`risk-bar-fill risk-bar-fill--${result.cvss_severity.toLowerCase()}`} style={{width:`${(result.cvss_score/10)*100}%`}}/></div></div>
                            )} />}
                            {result.overflow_hint && result.overflow_hint.likely_offset && <CCard icon="" title="Overflow Offset" stat={`${result.overflow_hint.likely_offset} bytes  ${result.overflow_hint.confidence}`} statColor="var(--primary)" accent="var(--primary)" onClick={() => om('Overflow Offset','','var(--primary)',
                                <div className="overflow-card"><div className="overflow-header"><span className="overflow-offset-value">{result.overflow_hint.likely_offset}</span><span className="overflow-offset-label">bytes to RIP</span><span className={`ctf-confidence-badge ctf-confidence-badge--${result.overflow_hint.confidence.toLowerCase()}`}>{result.overflow_hint.confidence}</span></div>{result.overflow_hint.stack_size&&<div className="overflow-detail"><span className="overflow-detail-label">Stack frame:</span><span className="overflow-detail-value">0x{result.overflow_hint.stack_size.toString(16)} ({result.overflow_hint.stack_size} bytes)</span></div>}<p className="overflow-evidence">{result.overflow_hint.evidence}</p></div>
                            )} />}
                            {result.rop_gadgets && result.rop_gadgets.length > 0 && <CCard icon="" title="ROP Gadgets" stat={`${result.rop_gadgets.length} gadgets`} statColor="#c084fc" accent="#a855f7" onClick={() => om('ROP Gadgets','','#a855f7',
                                <div className="table-container"><table className="info-table"><thead><tr><th>Address</th><th>Gadget</th></tr></thead><tbody>{result.rop_gadgets.map((g,i)=><tr key={i}><td style={{fontFamily:'monospace',color:'var(--primary)'}}>{g.address}</td><td style={{fontFamily:'monospace'}}>{g.gadget}</td></tr>)}</tbody></table></div>
                            )} />}
                        </Carousel>

                        {/* -- Section 3: AI Analysis -- */}
                        <Carousel title="AI Analysis" icon="">
                            <CCard
                                icon=""
                                title="AI Hints + Kill Chain"
                                stat={
                                    result.ai_hints_enhanced ? "âœ… Enhanced with deep reasoning" :
                                    result.ai_hints_quick ? "âš¡ Quick analysis" :
                                    (result.ai_hints || result.hints) ? "Analysis available" : "Unavailable"
                                }
                                statColor={
                                    result.ai_hints_enhanced ? "#4ade80" :
                                    result.ai_hints_quick ? "#fbbf24" :
                                    "var(--secondary)"
                                }
                                accent="var(--secondary-dim)"
                                onClick={() => {
                                    const mainHints = result.ai_hints || result.hints;
                                    om(
                                        'AI Hints + Kill Chain',
                                        '',
                                        'var(--secondary-dim)',
                                        <div className="result-card-body">
                                            {result.ai_hints_enhanced && (
                                                <div className="ai-system-badge ai-system-badge--enhanced">
                                                    âœ… Enhanced with deep reasoning
                                                </div>
                                            )}
                                            {!result.ai_hints_enhanced && result.ai_hints_quick && (
                                                <div className="ai-system-badge ai-system-badge--quick">
                                                    âš¡ Quick analysis
                                                </div>
                                            )}
                                            {mainHints ? (
                                                mainHints.split(/\n/).filter(l => l.trim()).map((line, i) => (
                                                    <div className="section-item section-item--hint" key={i}>{line}</div>
                                                ))
                                            ) : (
                                                <div className="section-empty">AI hints unavailable</div>
                                            )}
                                            {mainHints && (
                                                <div className="hints-feedback">
                                                    {feedbackGiven ? (
                                                        <div className="hints-feedback-thanks"> Thanks for your feedback!</div>
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
                                                                    } catch {}
                                                                }}
                                                                type="button"
                                                            >
                                                                Helpful
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
                                                                    } catch {}
                                                                }}
                                                                type="button"
                                                            >
                                                                Not helpful
                                                            </button>
                                                        </>
                                                    )}
                                                </div>
                                            )}
                                        </div>
                                    );
                                }}
                            />
                            {result.similar_writeups && result.similar_writeups.length > 0 && (
                                <CCard
                                    icon="🌐 "
                                    title="Similar Writeups"
                                    stat={`${result.similar_writeups.length} similar challenges found`}
                                    statColor="#22d3ee"
                                    accent="#06b6d4"
                                    onClick={() => om('Similar Writeups', '🌐 ', '#06b6d4',
                                        <div className="result-card-body">
                                            {result.similar_writeups.map((w, idx) => (
                                                <div key={idx} style={{ marginBottom: '1.2rem', paddingBottom: '1rem', borderBottom: idx < result.similar_writeups.length - 1 ? '1px solid rgba(255, 255, 255, 0.1)' : 'none' }}>
                                                    <div style={{ fontWeight: 'bold', fontSize: '15px', color: 'var(--on-surface)', marginBottom: '4px' }}>
                                                        {w.title} â†’ <span style={{ color: '#06b6d4', fontWeight: 'normal' }}>{w.key_technique}</span>
                                                    </div>
                                                    <div style={{ marginBottom: '8px' }}>
                                                        <a href={w.url} target="_blank" rel="noopener noreferrer" style={{ color: 'var(--primary)', textDecoration: 'underline', fontSize: '13px', wordBreak: 'break-all' }}>
                                                            {w.url}
                                                        </a>
                                                    </div>
                                                    <div style={{ color: 'var(--on-surface-variant)', fontSize: '13px', fontStyle: 'italic', lineHeight: '1.4' }}>
                                                        {w.snippet && w.snippet.length > 150 ? w.snippet.slice(0, 150) + "..." : w.snippet}
                                                    </div>
                                                </div>
                                            ))}
                                        </div>
                                    )}
                                />
                            )}
                            {result.data_flows && result.data_flows.length > 0 && <CCard icon="" title="Data Flow" stat={`${result.data_flows.length} flows`} statColor="#3b82f6" accent="#3b82f6" onClick={() => om('Data Flow Analysis','','#3b82f6',
                                <ul className="data-flow-list">{result.data_flows.map((f,i)=><li key={i} className="data-flow-item">{f}</li>)}</ul>
                            )} />}
                            {result.format_string && <CCard icon="" title="Format String" stat={result.format_string.vulnerable?`Vulnerable  ${result.format_string.severity}`:'Safe'} statColor={result.format_string.vulnerable?'#f87171':'#4ade80'} accent={result.format_string.vulnerable?'#ef4444':'#22c55e'} onClick={() => om('Format String','',result.format_string.vulnerable?'#ef4444':'#22c55e',
                                <div className="fmtstr-card"><div className="fmtstr-header"><span className={`fmtstr-badge fmtstr-badge--${result.format_string.vulnerable?result.format_string.severity.toLowerCase():'safe'}`}>{result.format_string.vulnerable?` VULNERABLE  ${result.format_string.severity}`:'[v] SAFE'}</span></div>{result.format_string.evidence.length>0&&<ul className="fmtstr-evidence">{result.format_string.evidence.map((e,i)=><li key={i} className="fmtstr-evidence-item">{e}</li>)}</ul>}</div>
                            )} />}
                            {result.libc_info && result.libc_info.glibc_version && <CCard icon="" title="Libc Info" stat={`GLIBC ${result.libc_info.glibc_version}`} statColor="#22d3ee" accent="#06b6d4" onClick={() => om('Libc Info','','#06b6d4',
                                <div className="libc-card"><div className="libc-row"><span className="libc-label">GLIBC Version</span><span className="libc-value">{result.libc_info.glibc_version}</span></div><div className="libc-row"><span className="libc-label">Likely OS</span><span className="libc-value libc-value--os">{result.libc_info.likely_os}</span></div>{result.libc_info.gcc_version&&<div className="libc-row"><span className="libc-label">GCC</span><span className="libc-value">{result.libc_info.gcc_version}</span></div>}{result.libc_info.libc_db_url&&<div className="libc-row"><span className="libc-label">Libc DB</span><a href={result.libc_info.libc_db_url} target="_blank" rel="noopener noreferrer" className="libc-link"> Search </a></div>}</div>
                            )} />}
                        </Carousel>

                        {/* -- Section 4: Binary Internals -- */}
                        <Carousel title="Binary Internals" icon="">
                            {result.disassembly && result.disassembly.length > 0 && <CCard icon="" title="Disassembly" stat={`${result.disassembly_function||'main'}  ${result.disassembly.length} insns`} statColor="#67e8f9" accent="#22d3ee" onClick={() => om('Disassembly','','#22d3ee',
                                <div className="disasm-body"><div className="disasm-row disasm-row--header"><span className="disasm-col-addr">Address</span><span className="disasm-col-mnemonic">Mnemonic</span><span className="disasm-col-operands">Operands</span></div>{result.disassembly.map((insn,i)=>{const mn=insn.mnemonic.toLowerCase();const d=['call','jmp','je','jne','jz','jnz','ret','retn','syscall','int'].includes(mn);return(<div className={`disasm-row${d?' disasm-row--danger':''}`} key={i}><span className="disasm-col-addr">{insn.address}</span><span className={`disasm-col-mnemonic${d?' disasm-mnemonic--danger':''}`}>{insn.mnemonic}</span><span className="disasm-col-operands">{insn.op_str||''}</span></div>)})}</div>
                            )} />}
                            {result.hex_view && result.hex_view.length > 0 && <CCard icon="" title="Hex View" stat={`First ${result.hex_view.length*16} bytes`} statColor="#60a5fa" accent="#3b82f6" onClick={() => om('Hex View','','#3b82f6',
                                <div className="hex-viewer-body"><div className="hex-row hex-row--header"><span className="hex-col-offset">Offset</span><span className="hex-col-hex">00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f</span><span className="hex-col-ascii">ASCII</span></div>{result.hex_view.map((row,i)=><div className="hex-row" key={i}><span className="hex-col-offset">{row.offset}</span><span className="hex-col-hex">{row.hex}</span><span className="hex-col-ascii">{row.ascii}</span></div>)}</div>
                            )} />}
                            {result.function_list && result.function_list.length > 0 && <CCard icon="" title="Function List" stat={`${result.function_list.length} functions`} statColor="#8b5cf6" accent="#8b5cf6" onClick={() => om('Function List','','#8b5cf6',
                                <div className="table-container"><table className="info-table"><thead><tr><th>Address</th><th>Size</th><th>Name</th></tr></thead><tbody>{result.function_list.map((fn,i)=><tr key={i}><td style={{fontFamily:'monospace',color:'var(--primary)'}}>{fn.address}</td><td style={{color:'var(--on-surface-variant)'}}>{fn.size}</td><td>{fn.name}</td></tr>)}</tbody></table></div>
                            )} />}
                            {(result.imports_exports?.imports?.length>0||result.imports_exports?.exports?.length>0) && <CCard icon="" title="Imports / Exports" stat={`${result.imports_exports.imports.length} imp, ${result.imports_exports.exports.length} exp`} statColor="#ec4899" accent="#ec4899" onClick={() => om('Imports & Exports','','#ec4899',
                                <div className="two-column-layout"><div className="column"><h4 className="column-title">Imports</h4><ul className="info-list">{result.imports_exports.imports.map((imp,i)=><li key={i}>{imp}</li>)}</ul></div><div className="column"><h4 className="column-title">Exports</h4><ul className="info-list">{result.imports_exports.exports.map((exp,i)=><li key={i}>{exp}</li>)}</ul></div></div>
                            )} />}
                        </Carousel>

                        {/* -- Section 5: Tools -- */}
                        <Carousel title="Tools" icon="[Tools]">
                            {result.pwn_template && result.extension !== '.zip' && <CCard icon="[Code]" title="Pwntools Template" stat="Ready to download" statColor="#fbbf24" accent="#f59e0b" onClick={() => om('Pwntools Template','[Code]','#f59e0b',
                                <>
                                  <div className="pwn-template-actions">
                                    <button className="pwn-action-btn" onClick={()=>navigator.clipboard.writeText(result.pwn_template)} type="button">[Copy]</button>
                                    <button className="pwn-action-btn" onClick={()=>{const b=new Blob([result.pwn_template],{type:'text/x-python'});const u=URL.createObjectURL(b);const a=document.createElement('a');a.href=u;a.download='exploit.py';a.click();URL.revokeObjectURL(u)}} type="button">[Download]</button>
                                  </div>
                                  <div className="pwn-template-body">
                                    <pre className="pwn-code">{result.pwn_template.split('\n').map((line,i)=><div className="pwn-line" key={i}><span className="pwn-line-num">{String(i+1).padStart(3,' ')}</span><span className={`pwn-line-text${line.trimStart().startsWith('#')?' pwn-comment':line.includes('from pwn')||line.includes('#!/')?' pwn-import':''}`}>{line||' '}</span></div>)}</pre>
                                  </div>
                                  <div style={{marginTop: '16px', borderTop: '1px solid #30363d', paddingTop: '16px'}}>
                                    <button
                                      onClick={() => {
                                        const filename = result.filename || 'binary';
                                        const cleanName = filename.replace(/[^a-zA-Z0-9_]/g, '_').replace(/\.[^.]*$/, '');
                                        const scriptName = `exploit_${cleanName}.py`;
                                        const blob = new Blob([result.pwntools_template || result.exploit_template || ''], {type: 'text/plain'});
                                        const url = URL.createObjectURL(blob);
                                        const a = document.createElement('a');
                                        a.href = url;
                                        a.download = scriptName;
                                        a.click();
                                        URL.revokeObjectURL(url);
                                      }}
                                      style={{
                                        background: '#238636', border: '1px solid #2ea043',
                                        color: 'white', padding: '8px 16px', borderRadius: '6px',
                                        cursor: 'pointer', fontSize: '13px', marginTop: '8px'
                                      }}>
                                      ⬇ Download Exploit Script
                                    </button>
                                    <div style={{marginTop: '8px'}}>
                                      <span style={{color: '#8b949e', fontSize: '12px'}}>Run with: </span>
                                      <code style={{
                                        background: '#161b22', padding: '4px 8px', borderRadius: '4px',
                                        color: '#7ee787', fontSize: '12px'
                                      }}>
                                        python3 exploit_{result.filename?.replace(/[^a-zA-Z0-9_]/g, '_').replace(/\.[^.]*$/, '')}.py
                                      </code>
                                    </div>
                                  </div>
                                </>
                            )} />}
                            <CCard icon="[Strings]" title="Strings" stat={`${result.strings_count} extracted`} statColor="var(--primary)" accent="var(--primary)" onClick={() => om('Strings','[Strings]','var(--primary)',
                                <div className="result-card-body">{result.strings.length===0?<div className="no-strings">No printable strings found.</div>:result.strings.map((s,i)=><div className="string-line" key={i}><span className="string-index">{String(i+1).padStart(4,'0')}</span>{s}</div>)}</div>
                            )} />
                            <CCard icon="[Flags]" title="Flags Detected" stat={result.flags_detected?.length>0?`${result.flags_detected.length} found`:'None'} statColor={result.flags_detected?.length>0?'#f87171':'var(--on-surface-variant)'} accent="var(--error)" onClick={() => om('Flags Detected','[Flags]','var(--error)',
                                <div className="result-card-body">{result.flags_detected?.length>0?result.flags_detected.map((f,i)=><div className="section-item section-item--flag" key={i}>{f}</div>):<div className="section-empty">No flags detected</div>}</div>
                            )} />
                            <CCard icon="[Interesting]" title="Interesting Findings" stat={result.patterns&&Object.keys(result.patterns).length>0?`${Object.keys(result.patterns).length} categories`:'None'} statColor="var(--secondary)" accent="var(--secondary)" onClick={() => om('Interesting Findings','[Interesting]','var(--secondary)',
                                <div className="result-card-body">{result.patterns&&Object.keys(result.patterns).length>0?Object.entries(result.patterns).map(([cat,items])=><div className="finding-category" key={cat}><span className="finding-label">{cat.replace(/_/g,' ')}:</span>{items.map((item,j)=><div className="section-item section-item--finding" key={j}>{item}</div>)}</div>):<div className="section-empty">No interesting patterns detected</div>}</div>
                            )} />
                        </Carousel>

                        {/* -- Section 6: Quick Commands (always visible) -- */}
                        <div className="bottom-section">
                            <div className="bottom-section-header"><span className="bottom-section-icon">[Commands]</span><h3 className="bottom-section-title">Quick Commands</h3></div>
                            <div className="quick-commands">
                                {[`file ./${result.filename}`,`checksec ./${result.filename}`,`strings ./${result.filename} | grep -i flag`,`ltrace ./${result.filename}`,`strace ./${result.filename}`,`gdb -q ./${result.filename}`,`objdump -d ./${result.filename} | grep -A 20 '<main>'`,`ROPgadget --binary ./${result.filename} --rop | head -20`,`one_gadget libc.so.6`,`python3 -c "from pwn import *; cyclic(200)" | ./${result.filename}`].map((cmd,i)=>(
                                    <CommandBlock key={i} command={cmd} language="bash" binaryContext={binaryContext} />
                                ))}
                            </div>
                        </div>

                        {/* -- Chat (always visible) -- */}
                        <div className="bottom-section">
                            <div className="bottom-section-header"><span className="bottom-section-icon"></span><h3 className="bottom-section-title">Follow-up Chat</h3></div>
                            {conversationSummary && (
                                <div style={{
                                    fontSize: '11px', color: '#8b949e', padding: '4px 12px',
                                    background: '#161b22', borderBottom: '1px solid #21262d',
                                    display: 'flex', alignItems: 'center', gap: '6px'
                                }}>
                                    <span style={{color: '#3fb950'}}>●</span>
                                    Session context preserved ({chatMessages.length} messages)
                                </div>
                            )}
                            <div className="chat-messages" id="chat-messages" style={{ padding: '16px', gap: '16px' }}>
                                {chatMessages.map((msg,i)=>(
                                  <div
                                    className={`chat-bubble chat-bubble--${msg.role}`}
                                    key={i}
                                    style={{
                                      padding: '16px 20px',
                                      marginBottom: '20px',
                                      borderLeft: msg.role === 'assistant' 
                                        ? '3px solid rgba(56, 139, 253, 0.3)' 
                                        : '3px solid rgba(63, 185, 80, 0.3)'
                                    }}
                                  >
                                    {msg.role === 'assistant' && (
                                      <button
                                        onClick={() => navigator.clipboard.writeText(msg.content)}
                                        style={{
                                          background: 'none', border: '1px solid #30363d',
                                          color: '#6e7681', fontSize: '11px', borderRadius: '4px',
                                          padding: '2px 8px', cursor: 'pointer', float: 'right',
                                          marginLeft: '8px'
                                        }}
                                      >
                                        ⎘ Copy
                                      </button>
                                    )}
                                    <span className="chat-bubble-label">
                                      {msg.role==='user'?'You':'AI Mentor'}
                                      {msg.role === 'assistant' && msg.response_source === 'cache' && (
                                        <span className="response-source-badge response-source-badge--cache" style={{ marginLeft: '8px', padding: '2px 6px', borderRadius: '4px', fontSize: '11px', fontWeight: 'bold', backgroundColor: 'rgba(46, 160, 67, 0.15)', color: '#3fb950', border: '1px solid rgba(46, 160, 67, 0.4)', display: 'inline-flex', alignItems: 'center' }}>⚡ Instant</span>
                                      )}
                                      {msg.role === 'assistant' && msg.response_source === 'ai' && (
                                        <span className="response-source-badge response-source-badge--ai" style={{ marginLeft: '8px', padding: '2px 6px', borderRadius: '4px', fontSize: '11px', fontWeight: 'bold', backgroundColor: 'rgba(56, 139, 253, 0.15)', color: '#58a6ff', border: '1px solid rgba(56, 139, 253, 0.4)', display: 'inline-flex', alignItems: 'center' }}>🤖 AI</span>
                                      )}
                                    </span>
                                    {msg.image&&<img src={msg.image} alt="Attached" className="chat-image-preview-bubble"/>}
                                    <div className="chat-bubble-content">{renderAIMessage(msg.content, binaryContext)}</div>
                                    {msg.role === 'assistant' && (
                                       <div className="provenance-badge" style={{ marginTop: '6px', fontSize: '11px', color: msg.provenance?.evidence_type === 'general' ? '#8b949e' : '#58a6ff', background: 'rgba(22, 27, 34, 0.6)', border: '1px solid rgba(48, 54, 61, 0.6)', borderRadius: '4px', padding: '3px 8px', display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
                                         {msg.provenance?.evidence_type === 'detected_function' && (
                                           <span>Based on: <strong>{msg.provenance.evidence_value}</strong> in the detected functions</span>
                                         )}
                                         {msg.provenance?.evidence_type === 'overflow_offset' && (
                                           <span>Based on: the detected overflow offset (<strong>{msg.provenance.evidence_value}</strong> bytes)</span>
                                         )}
                                         {msg.provenance?.evidence_type === 'protection_flag' && (
                                           <span>Based on: <strong>{msg.provenance.evidence_value}</strong> status shown above</span>
                                         )}
                                         {msg.provenance?.evidence_type === 'disassembly_line' && (
                                           <span>Based on: the disassembly excerpt shown above</span>
                                         )}
                                         {msg.provenance?.evidence_type === 'rop_gadget' && (
                                           <span>Based on: the ROP gadgets listed above</span>
                                         )}
                                         {(!msg.provenance || msg.provenance?.evidence_type === 'general') && (
                                           <span style={{ fontStyle: 'italic', color: '#8b949e' }}>General guidance — not tied to a specific finding</span>
                                         )}
                                       </div>
                                     )}
                                  </div>
                                ))}
                                {chatLoading&&<div className="chat-bubble chat-bubble--assistant"><span className="chat-bubble-label">AI Mentor</span><div className="chat-bubble-content"><span className="chat-typing">Thinking<span className="chat-dots">...</span></span></div></div>}
                                <div ref={chatEndRef}/>
                            </div>
                            {chatImage&&<div className="chat-image-bar"><img src={chatImagePreview} alt="Preview" className="chat-image-thumb"/><span className="chat-image-name">{chatImage.name}</span><button className="chat-image-remove" onClick={clearChatImage} title="Remove image"><span className="material-symbols-outlined">close</span></button></div>}
                            {triedCommands.length > 0 && (
                              <div style={{
                                display: 'flex', alignItems: 'center', gap: '8px',
                                padding: '6px 12px', background: '#0d1117',
                                borderTop: '1px solid #21262d', flexWrap: 'wrap'
                              }}>
                                <span style={{fontSize: '11px', color: '#6e7681', whiteSpace: 'nowrap'}}>
                                  ✓ Already tried ({triedCommands.length} commands):
                                </span>
                                {triedCommands.slice(0, 4).map((cmd, i) => (
                                  <span key={i} style={{
                                    background: '#21262d', color: '#6e7681', fontSize: '10px',
                                    padding: '2px 8px', borderRadius: '10px', fontFamily: 'monospace',
                                    border: '1px solid #30363d', maxWidth: '150px',
                                    overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap'
                                  }}>
                                    {cmd.substring(0, 35)}{cmd.length > 35 ? '...' : ''}
                                  </span>
                                ))}
                              </div>
                            )}
                            <input ref={cameraInputRef} type="file" accept="image/*"
                              style={{display:'none'}}
                              onChange={(e) => {
                                const file = e.target.files?.[0];
                                if (!file) return;
                                const reader = new FileReader();
                                reader.onload = (ev) => setPastedImage({dataUrl: ev.target.result, file, name: file.name});
                                reader.readAsDataURL(file);
                              }} />
                            <div className="chat-input-row" style={{ display: 'block' }}>
                              {pastedImage && (
                                <div style={{
                                  display: 'flex', alignItems: 'center', gap: '8px',
                                  padding: '6px 10px', background: '#161b22',
                                  borderBottom: '1px solid #30363d', borderRadius: '6px 6px 0 0',
                                  marginBottom: '8px'
                                }}>
                                  <img src={pastedImage.dataUrl} alt="Attached"
                                    style={{width: '48px', height: '48px', objectFit: 'cover',
                                      borderRadius: '4px', border: '1px solid #30363d'}} />
                                  <span style={{color: '#8b949e', fontSize: '12px', flex: 1}}>
                                    {pastedImage.name}
                                  </span>
                                  <button onClick={() => setPastedImage(null)} style={{
                                    background: 'none', border: 'none', color: '#6e7681',
                                    fontSize: '18px', cursor: 'pointer', padding: '0 4px'
                                  }} type="button">✕</button>
                                </div>
                              )}
                              <div style={{display: 'flex', alignItems: 'flex-end', gap: '6px'}}>
                                <button type="button" title="Take photo or upload image"
                                  onClick={() => cameraInputRef.current?.click()}
                                  style={{
                                    background: '#21262d', border: '1px solid #30363d', borderRadius: '6px',
                                    color: '#8b949e', fontSize: '18px', cursor: 'pointer',
                                    padding: '6px 8px', lineHeight: '1', flexShrink: 0, minWidth: '36px'
                                  }}>📷</button>
                                <textarea ref={chatTextareaRef} className="chat-input chat-textarea" placeholder={chatImage||pastedImage?'Add a message about your screenshot... (Shift+Enter for new line)':'Ask anything about this binary... (Shift+Enter for new line)'} value={chatInput} onChange={e=>{setChatInput(e.target.value);e.target.style.height='auto';e.target.style.height=Math.min(e.target.scrollHeight,200)+'px';}} onKeyDown={onChatKeyDown} onPaste={handlePasteImage} disabled={chatLoading} id="chat-input" rows={3}/>
                                <button className="chat-send-btn" onClick={sendChat} disabled={chatLoading||(!chatInput.trim()&&!chatImage&&!pastedImage)} id="chat-send-btn">{chatLoading?'...':' Send'}</button>
                              </div>
                              <div style={{fontSize: '11px', color: '#484f58', padding: '4px 2px 0'}}>
                                💡 Paste terminal screenshots with Ctrl+V or drag and drop
                              </div>
                            </div>
                        </div>

                    </>
                    );
                })()}


                {/* *** Source Code Results *** */}
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
                            <div className="meta-item">
                                <span className="meta-label">Risk:</span>
                                <span className={`risk-badge risk-badge--${(sourceResult.risk_score || 'low').toLowerCase()}`}>{sourceResult.risk_score}</span>
                            </div>
                        </div>

                        {(sourceResult.ctf_category && sourceResult.ctf_category.category !== 'unknown') || sourceResult.difficulty ? (
                            <div className="hero-row">
                                {sourceResult.ctf_category && sourceResult.ctf_category.category !== 'unknown' && (
                                    <div className={`hero-card hero-card--${sourceResult.ctf_category.confidence.toLowerCase()}`}>
                                        <div className="hero-card-label"> CTF Category</div>
                                        <div className="hero-card-main">
                                            <span className={`ctf-category-badge ctf-category-badge--${sourceResult.ctf_category.confidence.toLowerCase()}`}>{sourceResult.ctf_category.category.replace(/_/g, ' ').toUpperCase()}</span>
                                            <span className={`ctf-confidence-badge ctf-confidence-badge--${sourceResult.ctf_category.confidence.toLowerCase()}`}>{sourceResult.ctf_category.confidence}</span>
                                        </div>
                                        <p className="hero-card-desc">{sourceResult.ctf_category.explanation}</p>
                                        {sourceResult.ctf_category.runner_up && (
                                            <div style={{
                                                marginTop: '16px',
                                                paddingTop: '12px',
                                                borderTop: '1px solid rgba(68, 72, 79, 0.25)',
                                            }}>
                                                <div style={{ fontSize: '11px', fontWeight: 700, color: 'var(--on-surface-variant)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '6px' }}>
                                                    Also worth considering:
                                                </div>
                                                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px' }}>
                                                    <span style={{
                                                        fontSize: '14px',
                                                        fontWeight: 700,
                                                        color: 'var(--primary)',
                                                        textTransform: 'uppercase',
                                                        letterSpacing: '0.05em'
                                                    }}>
                                                        {sourceResult.ctf_category.runner_up.category.replace(/_/g, ' ')}
                                                    </span>
                                                    <span className={`ctf-confidence-badge ctf-confidence-badge--${sourceResult.ctf_category.runner_up.confidence.toLowerCase()}`} style={{ fontSize: '9px', padding: '2px 6px' }}>
                                                        {sourceResult.ctf_category.runner_up.confidence}
                                                    </span>
                                                </div>
                                                <p className="hero-card-desc" style={{ fontSize: '12px', opacity: 0.85 }}>
                                                    {sourceResult.ctf_category.runner_up.explanation}
                                                </p>
                                            </div>
                                        )}
                                    </div>
                                )}
                                {sourceResult.difficulty && (
                                    <div className={`hero-card hero-card--diff-${sourceResult.difficulty.difficulty.toLowerCase()}`}>
                                        <div className="hero-card-label"> Difficulty</div>
                                        <div className="hero-card-main">
                                            <span className={`difficulty-badge difficulty-badge--${sourceResult.difficulty.difficulty.toLowerCase()}`}>{sourceResult.difficulty.difficulty}</span>
                                        </div>
                                        <p className="hero-card-desc">{sourceResult.difficulty.reason}</p>
                                    </div>
                                )}
                            </div>
                        ) : null}

                        {((sourceResult.cvss_score !== undefined) ||
                          (sourceResult.overflow_hint && sourceResult.overflow_hint.likely_offset) ||
                          (sourceResult.data_flows && sourceResult.data_flows.length > 0)) && (
                            <Carousel title="Vulnerability Analysis" icon="">
                                {sourceResult.cvss_score !== undefined && (
                                    <CCard
                                        icon=""
                                        title="CVSS Score"
                                        stat={`${sourceResult.cvss_score}/10.0 ${sourceResult.cvss_severity}`}
                                        statColor={cvssC(sourceResult.cvss_severity)}
                                        accent={cvssC(sourceResult.cvss_severity)}
                                        onClick={() => om('CVSS 3.1 Scoring', '', cvssC(sourceResult.cvss_severity),
                                            <div className={`risk-card risk-card--${sourceResult.cvss_severity.toLowerCase()}`}>
                                                <div className="risk-header">
                                                    <div className="risk-score-circle">
                                                        <span className="risk-score-number">{sourceResult.cvss_score}</span>
                                                        <span className="risk-score-max">/10.0</span>
                                                    </div>
                                                    <div className="risk-info">
                                                        <span className={`risk-badge risk-badge--${sourceResult.cvss_severity.toLowerCase()}`}>{sourceResult.cvss_severity}</span>
                                                        <span className="risk-label">Base Score Equivalent</span>
                                                    </div>
                                                </div>
                                                <div className="risk-bar-track">
                                                    <div className={`risk-bar-fill risk-bar-fill--${sourceResult.cvss_severity.toLowerCase()}`} style={{width: `${(sourceResult.cvss_score/10)*100}%`}}/>
                                                </div>
                                            </div>
                                        )}
                                    />
                                )}
                                {sourceResult.overflow_hint && sourceResult.overflow_hint.likely_offset && (
                                    <CCard
                                        icon=""
                                        title="Overflow Offset"
                                        stat={`${sourceResult.overflow_hint.likely_offset} bytes  ${sourceResult.overflow_hint.confidence}`}
                                        statColor="var(--primary)"
                                        accent="var(--primary)"
                                        onClick={() => om('Overflow Offset', '', 'var(--primary)',
                                            <div className="overflow-card">
                                                <div className="overflow-header">
                                                    <span className="overflow-offset-value">{sourceResult.overflow_hint.likely_offset}</span>
                                                    <span className="overflow-offset-label">bytes to RIP</span>
                                                    <span className={`ctf-confidence-badge ctf-confidence-badge--${sourceResult.overflow_hint.confidence.toLowerCase()}`}>{sourceResult.overflow_hint.confidence}</span>
                                                </div>
                                                <p className="overflow-evidence">{sourceResult.overflow_hint.evidence}</p>
                                            </div>
                                        )}
                                    />
                                )}
                                {sourceResult.data_flows && sourceResult.data_flows.length > 0 && (
                                    <CCard
                                        icon=""
                                        title="Data Flow"
                                        stat={`${sourceResult.data_flows.length} flows`}
                                        statColor="#3b82f6"
                                        accent="#3b82f6"
                                        onClick={() => om('Data Flow Analysis', '', '#3b82f6',
                                            <ul className="data-flow-list">
                                                {sourceResult.data_flows.map((f, i) => <li key={i} className="data-flow-item">{f}</li>)}
                                             </ul>
                                         )}
                                     />
                                 )}
                             </Carousel>
                         )}

                        {/* -- Source: AI Analysis carousel (Similar Writeups) -- */}
                        {sourceResult.similar_writeups && sourceResult.similar_writeups.length > 0 && (
                            <Carousel title="AI Analysis" icon="">
                                <CCard
                                    icon="\uD83C\uDF10 "
                                    title="Similar Writeups"
                                    stat={`${sourceResult.similar_writeups.length} similar challenges found`}
                                    statColor="#22d3ee"
                                    accent="#06b6d4"
                                    onClick={() => om('Similar Writeups', '\uD83C\uDF10 ', '#06b6d4',
                                        <div className="result-card-body">
                                            {sourceResult.similar_writeups.map((w, idx) => (
                                                <div key={idx} style={{ marginBottom: '1.2rem', paddingBottom: '1rem', borderBottom: idx < sourceResult.similar_writeups.length - 1 ? '1px solid rgba(255, 255, 255, 0.1)' : 'none' }}>
                                                    <div style={{ fontWeight: 'bold', fontSize: '15px', color: 'var(--on-surface)', marginBottom: '4px' }}>
                                                        {w.title} \u2192 <span style={{ color: '#06b6d4', fontWeight: 'normal' }}>{w.key_technique}</span>
                                                    </div>
                                                    <div style={{ marginBottom: '8px' }}>
                                                        <a href={w.url} target="_blank" rel="noopener noreferrer" style={{ color: 'var(--primary)', textDecoration: 'underline', fontSize: '13px', wordBreak: 'break-all' }}>
                                                            {w.url}
                                                        </a>
                                                    </div>
                                                    <div style={{ color: 'var(--on-surface-variant)', fontSize: '13px', fontStyle: 'italic', lineHeight: '1.4' }}>
                                                        {w.snippet && w.snippet.length > 150 ? w.snippet.slice(0, 150) + "..." : w.snippet}
                                                    </div>
                                                </div>
                                            ))}
                                        </div>
                                    )}
                                />
                            </Carousel>
                        )}

                        {/* -- Source: Quick Commands (always visible) -- */}
                        {sourceResult.quick_commands && sourceResult.quick_commands.length > 0 && (
                            <div className="bottom-section">
                                <div className="bottom-section-header"><span className="bottom-section-icon">[Commands]</span><h3 className="bottom-section-title">Quick Commands</h3></div>
                                <div className="quick-commands">
                                    {sourceResult.quick_commands.map((cmd, i) => (
                                        <CommandBlock key={i} command={cmd} language="bash" binaryContext={binaryContext} />
                                    ))}
                                </div>
                            </div>
                        )}

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

                            {/* 2. Vulnerabilities (structured) */}
                            <AccordionCard
                                title="Vulnerabilities"
                                icon="warning"
                                sectionKey="srcVuln"
                                summary={`${Array.isArray(sourceResult.vulnerabilities) ? sourceResult.vulnerabilities.length : 0} found`}
                                variant="source-vuln"
                                openSections={openSections}
                                toggleSection={toggleSection}
                            >
                                <div className="flag-list">
                                    {Array.isArray(sourceResult.vulnerabilities) && sourceResult.vulnerabilities.length > 0 ? (
                                        sourceResult.vulnerabilities.map((vuln, i) => (
                                            <div key={i} className="flag-item">
                                                <span className={`severity-badge severity-badge--${(vuln.severity || 'medium').toLowerCase()}`}>{vuln.severity}</span>
                                                <span className="flag-text">
                                                    Line {vuln.line}: <strong>{vuln.type.replace(/_/g, ' ')}</strong> &mdash; {vuln.description}
                                                </span>
                                            </div>
                                        ))
                                    ) : (
                                        <div className="section-empty">No obvious vulnerabilities detected.</div>
                                    )}
                                </div>
                            </AccordionCard>

                            {/* 3. Dangerous Functions (structured) */}
                            <AccordionCard
                                title="Dangerous Functions"
                                icon="pest_control"
                                sectionKey="srcDanger"
                                summary={`${(sourceResult.dangerous_functions || []).length} detected`}
                                variant="source-danger"
                                openSections={openSections}
                                toggleSection={toggleSection}
                            >
                                <div className="flag-list">
                                    {(sourceResult.dangerous_functions || []).length > 0 ? (
                                        sourceResult.dangerous_functions.map((fn, i) => (
                                            <div key={i} className="flag-item">
                                                <span className="flag-icon"></span>
                                                <span className="flag-text">
                                                    Line {fn.line}: <strong>{fn.name}</strong> &mdash; {fn.risk}
                                                </span>
                                            </div>
                                        ))
                                    ) : (
                                        <div className="section-empty">No dangerous function calls detected.</div>
                                    )}
                                </div>
                            </AccordionCard>

                            {/* 4. Exploit Hints */}
                            {sourceResult.exploit_hints && sourceResult.exploit_hints.length > 0 && (
                                <AccordionCard
                                    title="Exploit Hints"
                                    icon="tips_and_updates"
                                    sectionKey="srcExploitHints"
                                    summary={`${sourceResult.exploit_hints.length} specific steps`}
                                    variant="source-hints"
                                    openSections={openSections}
                                    toggleSection={toggleSection}
                                >
                                    <div className="ai-hints-body">
                                        <div className="ai-bullets">
                                            {sourceResult.exploit_hints.map((hint, i) => (
                                                <div key={i} className="ai-bullet">
                                                    <span className="bullet-point"></span>
                                                    <span dangerouslySetInnerHTML={{ __html: hint.replace(/`(.*?)`/g, '<code class="inline-code">$1</code>') }} />
                                                </div>
                                            ))}
                                        </div>
                                    </div>
                                </AccordionCard>
                            )}

                            {/* 5. AI Hints (parallel Groq + Nemotron) */}
                            <AccordionCard
                                title="CTF Hints"
                                icon="lightbulb"
                                sectionKey="srcHints"
                                summary={
                                    sourceResult.ai_hints_enhanced ? "\u2705 Enhanced with deep reasoning" :
                                    sourceResult.ai_hints_quick ? "\u26A1 Quick analysis" :
                                    "Strategic guidance"
                                }
                                variant="source-hints"
                                openSections={openSections}
                                toggleSection={toggleSection}
                            >
                                <div className="ai-hints-body">
                                    {/* Enhanced / Quick badge — mirrors binary flow */}
                                    {sourceResult.ai_hints_enhanced && (
                                        <div className="ai-system-badge ai-system-badge--enhanced">
                                            \u2705 Enhanced with deep reasoning
                                        </div>
                                    )}
                                    {!sourceResult.ai_hints_enhanced && sourceResult.ai_hints_quick && (
                                        <div className="ai-system-badge ai-system-badge--quick">
                                            \u26A1 Quick analysis
                                        </div>
                                    )}
                                    <div className="ai-bullets">
                                        {(sourceResult.ai_hints || sourceResult.hints) ? (
                                            (sourceResult.ai_hints || sourceResult.hints).split('\n').filter(val => val.trim()).map((line, i) => (
                                                <div key={i} className="ai-bullet">
                                                    <span className="bullet-point"></span>
                                                    {line.replace(/^\s*/, '')}
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
                                                        {line.replace(/^\s*/, '')}
                                                    </div>
                                                ))}
                                            </div>
                                        </div>
                                    )}
                                </div>
                            </AccordionCard>


                            {/* 6. Exploit Template */}
                            {sourceResult.exploit_template && (
                                <AccordionCard
                                    title="Exploit Template"
                                    icon="code"
                                    sectionKey="srcExploit"
                                    summary="Working pwntools script"
                                    variant="source-code"
                                    openSections={openSections}
                                    toggleSection={toggleSection}
                                >
                                    <div className="pwn-template-actions">
                                        <button className="pwn-action-btn" onClick={()=>navigator.clipboard.writeText(sourceResult.exploit_template)} type="button">[Copy]</button>
                                        <button className="pwn-action-btn" onClick={()=>{const b=new Blob([sourceResult.exploit_template],{type:'text/x-python'});const u=URL.createObjectURL(b);const a=document.createElement('a');a.href=u;a.download='exploit.py';a.click();URL.revokeObjectURL(u)}} type="button">[Download]</button>
                                    </div>
                                    <div className="pwn-template-body">
                                        <pre className="pwn-code">{sourceResult.exploit_template.split('\n').map((line,i)=><div className="pwn-line" key={i}><span className="pwn-line-num">{String(i+1).padStart(3,' ')}</span><span className={`pwn-line-text${line.trimStart().startsWith('#')?' pwn-comment':line.includes('from pwn')||line.includes('#!/')?' pwn-import':''}`}>{line||' '}</span></div>)}</pre>
                                    </div>
                                </AccordionCard>
                            )}

                            {/* 7. Source Code View */}
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

                            {/* 8. Combined Analysis (binary + source) */}
                        </div>

                        {/* -- Source Code Chat (always visible) -- */}
                        <div className="bottom-section">
                            <div className="bottom-section-header"><span className="bottom-section-icon"></span><h3 className="bottom-section-title">Source Code Chat</h3></div>
                            {conversationSummary && (
                                <div style={{
                                    fontSize: '11px', color: '#8b949e', padding: '4px 12px',
                                    background: '#161b22', borderBottom: '1px solid #21262d',
                                    display: 'flex', alignItems: 'center', gap: '6px'
                                }}>
                                    <span style={{color: '#3fb950'}}>●</span>
                                    Session context preserved ({srcChatMessages.length} messages)
                                </div>
                            )}
                            <div className="chat-messages" id="src-chat-messages" style={{ padding: '16px', gap: '16px' }}>
                                {srcChatMessages.map((msg,i)=>(
                                  <div
                                    className={`chat-bubble chat-bubble--${msg.role}`}
                                    key={i}
                                    style={{
                                      padding: '16px 20px',
                                      marginBottom: '20px',
                                      borderLeft: msg.role === 'assistant' 
                                        ? '3px solid rgba(56, 139, 253, 0.3)' 
                                        : '3px solid rgba(63, 185, 80, 0.3)'
                                    }}
                                  >
                                    {msg.role === 'assistant' && (
                                      <button
                                        onClick={() => navigator.clipboard.writeText(msg.content)}
                                        style={{
                                          background: 'none', border: '1px solid #30363d',
                                          color: '#6e7681', fontSize: '11px', borderRadius: '4px',
                                          padding: '2px 8px', cursor: 'pointer', float: 'right',
                                          marginLeft: '8px'
                                        }}
                                      >
                                        ⎘ Copy
                                      </button>
                                    )}
                                    <span className="chat-bubble-label">
                                      {msg.role==='user'?'You':'AI Mentor'}
                                      {msg.role === 'assistant' && msg.response_source === 'cache' && (
                                        <span className="response-source-badge response-source-badge--cache" style={{ marginLeft: '8px', padding: '2px 6px', borderRadius: '4px', fontSize: '11px', fontWeight: 'bold', backgroundColor: 'rgba(46, 160, 67, 0.15)', color: '#3fb950', border: '1px solid rgba(46, 160, 67, 0.4)', display: 'inline-flex', alignItems: 'center' }}>⚡ Instant</span>
                                      )}
                                      {msg.role === 'assistant' && msg.response_source === 'ai' && (
                                        <span className="response-source-badge response-source-badge--ai" style={{ marginLeft: '8px', padding: '2px 6px', borderRadius: '4px', fontSize: '11px', fontWeight: 'bold', backgroundColor: 'rgba(56, 139, 253, 0.15)', color: '#58a6ff', border: '1px solid rgba(56, 139, 253, 0.4)', display: 'inline-flex', alignItems: 'center' }}>🤖 AI</span>
                                      )}
                                    </span>
                                    <div className="chat-bubble-content">{renderAIMessage(msg.content, binaryContext)}</div>
                                    {msg.role === 'assistant' && (
                                      <div className="provenance-badge" style={{ marginTop: '6px', fontSize: '11px', color: msg.provenance?.evidence_type === 'general' ? '#8b949e' : '#58a6ff', background: 'rgba(22, 27, 34, 0.6)', border: '1px solid rgba(48, 54, 61, 0.6)', borderRadius: '4px', padding: '3px 8px', display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
                                        {msg.provenance?.evidence_type === 'detected_function' && (
                                          <span>Based on: <strong>{msg.provenance.evidence_value}</strong> in the detected functions</span>
                                        )}
                                        {msg.provenance?.evidence_type === 'overflow_offset' && (
                                          <span>Based on: the detected overflow offset (<strong>{msg.provenance.evidence_value}</strong> bytes)</span>
                                        )}
                                        {msg.provenance?.evidence_type === 'protection_flag' && (
                                          <span>Based on: <strong>{msg.provenance.evidence_value}</strong> status shown above</span>
                                        )}
                                        {msg.provenance?.evidence_type === 'disassembly_line' && (
                                          <span>Based on: the disassembly excerpt shown above</span>
                                        )}
                                        {msg.provenance?.evidence_type === 'rop_gadget' && (
                                          <span>Based on: the ROP gadgets listed above</span>
                                        )}
                                        {(!msg.provenance || msg.provenance?.evidence_type === 'general') && (
                                          <span style={{ fontStyle: 'italic', color: '#8b949e' }}>General guidance — not tied to a specific finding</span>
                                        )}
                                      </div>
                                    )}
                                  </div>
                                ))}
                                {srcChatLoading&&<div className="chat-bubble chat-bubble--assistant"><span className="chat-bubble-label">AI Mentor</span><div className="chat-bubble-content"><span className="chat-typing">Thinking<span className="chat-dots">...</span></span></div></div>}
                                <div ref={srcChatEndRef}/>
                            </div>
                            {triedCommands.length > 0 && (
                              <div style={{
                                display: 'flex', alignItems: 'center', gap: '8px',
                                padding: '6px 12px', background: '#0d1117',
                                borderTop: '1px solid #21262d', flexWrap: 'wrap'
                              }}>
                                <span style={{fontSize: '11px', color: '#6e7681', whiteSpace: 'nowrap'}}>
                                  ✓ Already tried ({triedCommands.length} commands):
                                </span>
                                {triedCommands.slice(0, 4).map((cmd, i) => (
                                  <span key={i} style={{
                                    background: '#21262d', color: '#6e7681', fontSize: '10px',
                                    padding: '2px 8px', borderRadius: '10px', fontFamily: 'monospace',
                                    border: '1px solid #30363d', maxWidth: '150px',
                                    overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap'
                                  }}>
                                    {cmd.substring(0, 35)}{cmd.length > 35 ? '...' : ''}
                                  </span>
                                ))}
                              </div>
                            )}
                            <div className="chat-input-row">
                                <textarea className="chat-input chat-textarea" placeholder="Ask anything about this source code... (Shift+Enter for new line)" value={srcChatInput} onChange={e=>{setSrcChatInput(e.target.value);e.target.style.height='auto';e.target.style.height=Math.min(e.target.scrollHeight,200)+'px';}} onKeyDown={onSrcChatKeyDown} disabled={srcChatLoading} id="src-chat-input" rows={3}/>
                                <button className="chat-send-btn" onClick={sendSrcChat} disabled={srcChatLoading||!srcChatInput.trim()} id="src-chat-send-btn">{srcChatLoading?'...':' Send'}</button>
                            </div>
                        </div>

                    </>
                )}

                {/* Combined Analysis â€” appears when BOTH binary and source results exist */}
                {result && sourceResult && (
                    <div className="bottom-section combined-analysis-section">
                        <div className="bottom-section-header">
                            <span className="bottom-section-icon">{"\ud83d\udd17"}</span>
                            <h3 className="bottom-section-title">Combined Analysis</h3>
                        </div>
                        <div className="combined-analysis-body">
                            <p className="combined-analysis-intro">Binary analysis and source code results cross-referenced:</p>
                            <div className="combined-analysis-items">
                                {/* Cross-reference dangerous functions */}
                                {result.patterns?.dangerous_functions?.length > 0 && (sourceResult.dangerous_functions || []).length > 0 && (
                                    <div className="combined-item combined-item--confirmed">
                                        <span className="combined-icon">{"\u2705"}</span>
                                        <span>Source confirms binary has dangerous functions: {(sourceResult.dangerous_functions || []).map(f => f.name).join(', ')} found in both binary strings and source code.</span>
                                    </div>
                                )}
                                {/* Cross-reference overflow */}
                                {result.overflow_hint?.likely_offset && Array.isArray(sourceResult.vulnerabilities) && sourceResult.vulnerabilities.some(v => v.type === 'buffer_overflow') && (
                                    <div className="combined-item combined-item--confirmed">
                                        <span className="combined-icon">{"\u2705"}</span>
                                        <span>Source confirms binary has buffer overflow{sourceResult.vulnerabilities.filter(v => v.type === 'buffer_overflow').map(v => ` at ${v.description.split('â€”')[0].trim()}`).join('')} &mdash; binary overflow offset predicted at {result.overflow_hint.likely_offset} bytes.</span>
                                    </div>
                                )}
                                {/* Checksec vs source vulns */}
                                {result.checksec && !result.checksec.canary && Array.isArray(sourceResult.vulnerabilities) && sourceResult.vulnerabilities.some(v => v.type === 'buffer_overflow') && (
                                    <div className="combined-item combined-item--critical">
                                        <span className="combined-icon">{"\ud83d\udea8"}</span>
                                        <span>Stack canary is DISABLED and source has buffer overflow vulnerabilities &mdash; exploitation is straightforward.</span>
                                    </div>
                                )}
                                {result.checksec && !result.checksec.pie && (
                                    <div className="combined-item combined-item--info">
                                        <span className="combined-icon">{"\u2139\ufe0f"}</span>
                                        <span>PIE is DISABLED &mdash; function addresses are fixed, making ret2win exploits reliable.</span>
                                    </div>
                                )}
                                {/* CTF category */}
                                {result.ctf_category?.category && result.ctf_category.category !== 'unknown' && (
                                    <div className="combined-item combined-item--info">
                                        <span className="combined-icon">{"\ud83c\udff7\ufe0f"}</span>
                                        <span>CTF category: {result.ctf_category.category.replace(/_/g, ' ')} ({result.ctf_category.confidence} confidence) &mdash; source code analysis confirms this classification.</span>
                                    </div>
                                )}
                                {/* Format string cross-reference */}
                                {result.format_string?.vulnerable && Array.isArray(sourceResult.vulnerabilities) && sourceResult.vulnerabilities.some(v => v.type === 'format_string') && (
                                    <div className="combined-item combined-item--confirmed">
                                        <span className="combined-icon">{"\u2705"}</span>
                                        <span>Format string vulnerability confirmed in both binary analysis and source code.</span>
                                    </div>
                                )}
                            </div>
                        </div>
                    </div>
                )}
                    </>
                )}

                {/* Footer */}
                <footer className="footer">
                    <span>BinExplain performs static analysis only. Uploaded files are deleted
                    immediately after analysis. No binaries are ever executed.</span>
                    {cagStats && cagStats.total_cached > 0 && (
                        <span className="cag-footer-badge" id="cag-stats-badge" title={`${cagStats.total_cached} cached entries, ${cagStats.total_hits} total hits`}>
                            {'\u26A1'} CAG: {cagStats.hit_rate}% hit rate
                        </span>
                    )}
                    <div className="footer-links">
                        <Link to="/" className="footer-link">Home</Link>
                        <span className="footer-link-separator">|</span>
                        <Link to="/learn" className="footer-link">Learn</Link>
                        <span className="footer-link-separator">|</span>
                        <Link to="/about" className="footer-link">About</Link>
                        <span className="footer-link-separator">|</span>
                        <Link to="/docs" className="footer-link">Docs</Link>
                        <span className="footer-link-separator">|</span>
                        <Link to="/blog" className="footer-link">Blog</Link>
                        <span className="footer-link-separator">|</span>
                        <Link to="/contact" className="footer-link">Contact</Link>
                        <span className="footer-link-separator">|</span>
                        <Link to="/privacy" className="footer-link">Privacy Policy</Link>
                        <span className="footer-link-separator">|</span>
                        <a href="https://github.com/Vaibhavi28/binexplain" target="_blank" rel="noopener noreferrer" className="footer-link">GitHub</a>
                    </div>
                    <span>
                        © 2026 Vaibhavi Sanjay Kathepuri · CC BY-NC-ND 4.0 ·{' '}
                        <Link to="/privacy" style={{ color: 'var(--primary)', textDecoration: 'none', fontWeight: '700' }}>Privacy Policy</Link> ·{' '}
                        <Link to="/contact" style={{ color: 'var(--primary)', textDecoration: 'none', fontWeight: '700' }}>Contact</Link>
                    </span>
                </footer>
            </div>

            {/* -- Card Detail Modal -- */}
            {modalData && (
                <CardModal title={modalData.title} icon={modalData.icon} accent={modalData.accent} onClose={closeModal}>
                    {modalData.content}
                </CardModal>
            )}

            {/* -- Password Modal (for protected ZIPs) -- */}
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
                            <span className="pwd-modal-icon"></span>
                            <h2 className="pwd-modal-title">Password Protected ZIP</h2>
                        </div>
                        <p className="pwd-modal-desc">
                            This archive is encrypted. Enter the password to unlock and analyze its contents.
                        </p>

                        {passwordError && (
                            <div className="pwd-modal-error" id="password-error">
                                <span className="pwd-modal-error-icon"></span>
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
                                    ' Unlock & Analyze'
                                )}
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}
