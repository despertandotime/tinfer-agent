import hashlib

def init_findings_hash_table(conn):
    conn.execute("""
    CREATE TABLE IF NOT EXISTS findings_hash (
        hash TEXT PRIMARY KEY,
        target TEXT,
        vuln_type TEXT,
        endpoint TEXT,
        program TEXT,
        reported_at TEXT,
        status TEXT DEFAULT 'pending'
    )
    """)
    conn.commit()

def finding_hash(target, vuln_type, endpoint):
    raw = f"{target.lower()}|{vuln_type.lower()}|{endpoint.lower().rstrip('/')}"
    return hashlib.sha256(raw.encode()).hexdigest()

def is_duplicate(conn, target, vuln_type, endpoint):
    h = finding_hash(target, vuln_type, endpoint)
    row = conn.execute("SELECT 1 FROM findings_hash WHERE hash=?", (h,)).fetchone()
    return row is not None

def register_finding(conn, target, vuln_type, endpoint, program):
    h = finding_hash(target, vuln_type, endpoint)
    conn.execute("INSERT OR IGNORE INTO findings_hash (hash, target, vuln_type, endpoint, program, reported_at) VALUES (?, ?, ?, ?, ?, datetime('now'))", (h, target, vuln_type, endpoint, program))
    conn.commit()
