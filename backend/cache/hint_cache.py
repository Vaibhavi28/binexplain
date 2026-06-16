"""
Cache Augmented Generation (CAG) — SQLite-backed hint cache for BinExplain.

When a binary is analyzed, a deterministic cache key is built from:
    ctf_category + checksec combination + top 3 dangerous functions

If the same key has been seen before the cached hints are returned
instantly — zero LLM calls, zero tokens burned.

Security:
• The cache stores only AI-generated text hints, never binary content.
• The SQLite DB lives in backend/cache/hints.db.
• All access is serialised through a threading lock.
"""

import hashlib
import json
import os
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path


_DB_PATH = Path(__file__).resolve().parent / "hints.db"

_lock = threading.Lock()


def _get_db_path() -> str:
    """Return the path to the SQLite DB.  Allows override via env var for testing."""
    return os.environ.get("CAG_DB_PATH", str(_DB_PATH))


def _connect() -> sqlite3.Connection:
    """Return a connection to the hint-cache database, creating the table if needed."""
    db_path = _get_db_path()
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS hint_cache (
            cache_key   TEXT PRIMARY KEY,
            hints       TEXT NOT NULL,
            kill_chain  TEXT NOT NULL DEFAULT '',
            category    TEXT NOT NULL DEFAULT '',
            created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            hit_count   INTEGER NOT NULL DEFAULT 0
        )
        """
    )
    conn.commit()
    return conn


# Module-level singleton connection (lazily initialised)
_conn: sqlite3.Connection | None = None


def _get_conn() -> sqlite3.Connection:
    global _conn
    if _conn is None:
        _conn = _connect()
    return _conn


# Save builtin `set` before our module-level `set()` function shadows it
_builtin_set = set

# ── Public API ────────────────────────────────────────────────────────────


def generate_key(
    ctf_category: str,
    checksec: dict,
    dangerous_functions: list[str],
) -> str:
    """
    Build a deterministic cache key from the analysis fingerprint.

    Format: ``{category}_NX{0|1}_PIE{0|1}_Canary{0|1}_{func1}_{func2}_{func3}``

    Only the top 3 dangerous functions (sorted) are included so that
    minor variations in extracted strings don't bust the cache.
    """
    cat = (ctf_category or "unknown").strip().lower()

    nx = 1 if checksec.get("nx") else 0
    pie = 1 if checksec.get("pie") else 0
    canary = 1 if checksec.get("canary") else 0

    # Normalise: lowercase, strip whitespace, deduplicate, sort, take top 3
    seen = _builtin_set()
    clean_funcs: list[str] = []
    for f in dangerous_functions:
        norm = f.strip().lower()
        if norm and norm not in seen:
            seen.add(norm)
            clean_funcs.append(norm)
    clean_funcs.sort()
    top3 = clean_funcs[:3]

    parts = [cat, f"NX{nx}", f"PIE{pie}", f"Canary{canary}"] + top3
    return "_".join(parts)


def get(cache_key: str) -> dict | None:
    """
    Look up *cache_key* in the database.

    Returns ``{"hints": str, "kill_chain": str, "category": str}`` on a
    hit, or ``None`` on a miss.  Each hit increments ``hit_count``.
    """
    with _lock:
        conn = _get_conn()
        row = conn.execute(
            "SELECT hints, kill_chain, category FROM hint_cache WHERE cache_key = ?",
            (cache_key,),
        ).fetchone()
        if row is None:
            return None
        # Increment hit counter
        conn.execute(
            "UPDATE hint_cache SET hit_count = hit_count + 1 WHERE cache_key = ?",
            (cache_key,),
        )
        conn.commit()
        return {"hints": row[0], "kill_chain": row[1], "category": row[2]}


def set(cache_key: str, hints: str, kill_chain: str = "", category: str = "") -> None:
    """
    Store a new cache entry (or replace an existing one).
    """
    with _lock:
        conn = _get_conn()
        conn.execute(
            """
            INSERT OR REPLACE INTO hint_cache
                (cache_key, hints, kill_chain, category, created_at, hit_count)
            VALUES (?, ?, ?, ?, ?, 0)
            """,
            (cache_key, hints, kill_chain, category, datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()


def get_stats() -> dict:
    """
    Return aggregate cache statistics.

    Returns::

        {
            "total_cached": int,
            "total_hits": int,
            "hit_rate": float,          # percentage (0-100)
            "most_common_categories": [str, ...],
        }
    """
    with _lock:
        conn = _get_conn()
        row = conn.execute(
            "SELECT COUNT(*), COALESCE(SUM(hit_count), 0) FROM hint_cache"
        ).fetchone()
        total_cached = row[0]
        total_hits = row[1]

        # hit_rate = hits / (hits + total_cached_entries)
        # Each cached entry was generated from exactly one LLM call (a miss).
        # So total_misses ≈ total_cached.
        total_requests = total_hits + total_cached
        hit_rate = round((total_hits / total_requests * 100) if total_requests > 0 else 0.0, 1)

        cats = conn.execute(
            """
            SELECT category, COUNT(*) as cnt
            FROM hint_cache
            WHERE category != ''
            GROUP BY category
            ORDER BY cnt DESC
            LIMIT 5
            """
        ).fetchall()
        most_common = [c[0] for c in cats]

        return {
            "total_cached": total_cached,
            "total_hits": total_hits,
            "hit_rate": hit_rate,
            "most_common_categories": most_common,
        }


def clear() -> None:
    """Delete all cache entries.  Useful for testing."""
    with _lock:
        conn = _get_conn()
        conn.execute("DELETE FROM hint_cache")
        conn.commit()


def reset_connection() -> None:
    """Close and reset the module-level DB connection.  Useful for testing."""
    global _conn
    with _lock:
        if _conn is not None:
            try:
                _conn.close()
            except Exception:
                pass
            _conn = None
