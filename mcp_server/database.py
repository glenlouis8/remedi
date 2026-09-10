import os
import sys
import datetime
from dotenv import load_dotenv

# Load environment variables early
load_dotenv()

# PostgreSQL logic is now mandatory
import psycopg2
import psycopg2.extras
import psycopg2.extensions

def get_connection(db_override=None):
    """Establishes a connection to PostgreSQL using a standard Connection URI."""
    # Priority 1: Use the standard DATABASE_URL (Supported by Supabase, Heroku, etc.)
    db_url = os.environ.get("DATABASE_URL")
    
    if db_url:
        return psycopg2.connect(db_url)
    
    # Fallback/Legacy: Build from individual components
    db_user = os.environ.get("DB_USER", "postgres")
    db_pass = os.environ.get("DB_PASS", "password")
    db_name = db_override if db_override else os.environ.get("DB_NAME", "postgres")
    host = os.environ.get("DB_HOST", "localhost")
    port = os.environ.get("DB_PORT", "5432")
    
    return psycopg2.connect(
        user=db_user, 
        password=db_pass, 
        dbname=db_name, 
        host=host,
        port=port,
        connect_timeout=10
    )

def create_postgres_db():
    """Connects to default 'postgres' DB to create the target DB if missing."""
    print("[DB] Attempting to create missing database...", file=sys.stderr)
    try:
        # Connect to default 'postgres' database
        conn = get_connection(db_override="postgres")
        conn.set_isolation_level(psycopg2.extensions.ISOLATION_LEVEL_AUTOCOMMIT)
        c = conn.cursor()
        target_db = os.environ.get("DB_NAME", "aegis_db")
        
        c.execute("SELECT 1 FROM pg_database WHERE datname = %s", (target_db,))
        if not c.fetchone():
            # CREATE DATABASE doesn't support parameterized queries — validate name first
            if not target_db.replace("_", "").replace("-", "").isalnum():
                raise ValueError(f"Invalid database name: {target_db}")
            c.execute(f"CREATE DATABASE {target_db}")
            print(f"[DB] Successfully created database: {target_db}", file=sys.stderr)
        else:
            print(f"[DB] Database {target_db} already exists.", file=sys.stderr)
        conn.close()
    except Exception as e:
        print(f"[DB] Failed to create database: {e}", file=sys.stderr)

def init_db():
    print("[DB] Initializing PostgreSQL database...", file=sys.stderr)
    try:
        conn = get_connection()
    except Exception as e:
        if 'database "' in str(e) and 'does not exist' in str(e):
            create_postgres_db()
            conn = get_connection() # Retry
        else:
            print(f"[DB] ERROR: Could not connect to Cloud SQL. {e}", file=sys.stderr)
            raise e

    try:
        c = conn.cursor()

        # Serialize concurrent init_db() calls — up to MAX_CONCURRENT_SCANS MCP
        # subprocesses can start at once, and the conditional CREATE / ALTER /
        # DROP CONSTRAINT DDL below races otherwise. Released on commit.
        c.execute("SELECT pg_advisory_xact_lock(%s)", (854792301,))

        # Create tables
        c.execute('''
            CREATE TABLE IF NOT EXISTS aws_accounts (
                user_id TEXT NOT NULL,
                account_name TEXT NOT NULL DEFAULT 'Default',
                access_key_enc TEXT NOT NULL,
                secret_key_enc TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_used_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (user_id, account_name)
            )
        ''')
        # Migration: add columns for existing DBs
        c.execute("ALTER TABLE aws_accounts ADD COLUMN IF NOT EXISTS last_used_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP")
        c.execute("ALTER TABLE aws_accounts ADD COLUMN IF NOT EXISTS account_name TEXT NOT NULL DEFAULT 'Default'")
        c.execute("ALTER TABLE aws_accounts ADD COLUMN IF NOT EXISTS protected_users TEXT DEFAULT ''")
        # Migration: make the credential timestamps tz-aware so the 30-min purge
        # (NOW() - INTERVAL) is correct regardless of a connection's TimeZone.
        c.execute("""
            SELECT data_type FROM information_schema.columns
            WHERE table_name = 'aws_accounts' AND column_name = 'last_used_at' AND table_schema = 'public'
        """)
        _lu = c.fetchone()
        if _lu and _lu[0] == 'timestamp without time zone':
            c.execute("ALTER TABLE aws_accounts ALTER COLUMN last_used_at TYPE timestamptz USING last_used_at AT TIME ZONE 'UTC'")
            c.execute("ALTER TABLE aws_accounts ALTER COLUMN created_at TYPE timestamptz USING created_at AT TIME ZONE 'UTC'")
        # Migration: promote PK from user_id-only to (user_id, account_name) if needed
        c.execute("""
            SELECT COUNT(kcu.column_name)
            FROM information_schema.table_constraints tc
            JOIN information_schema.key_column_usage kcu
              ON tc.constraint_name = kcu.constraint_name AND tc.table_schema = kcu.table_schema
            WHERE tc.table_name = 'aws_accounts' AND tc.constraint_type = 'PRIMARY KEY'
              AND tc.table_schema = 'public'
        """)
        row = c.fetchone()
        if row and row[0] == 1:
            c.execute("""
                SELECT constraint_name FROM information_schema.table_constraints
                WHERE table_name = 'aws_accounts' AND constraint_type = 'PRIMARY KEY' AND table_schema = 'public'
            """)
            pk_name = c.fetchone()[0]
            c.execute(f"ALTER TABLE aws_accounts DROP CONSTRAINT {pk_name}")
            c.execute("ALTER TABLE aws_accounts ADD PRIMARY KEY (user_id, account_name)")

        c.execute('''
            CREATE TABLE IF NOT EXISTS compliance_checks (
                id TEXT NOT NULL,
                user_id TEXT NOT NULL DEFAULT '',
                name TEXT,
                description TEXT,
                status TEXT
            )
        ''')
        # Migration: backfill legacy global rows, then promote PK to (id, user_id)
        c.execute("ALTER TABLE compliance_checks ALTER COLUMN user_id SET DEFAULT ''")
        c.execute("UPDATE compliance_checks SET user_id = '' WHERE user_id IS NULL")
        c.execute("ALTER TABLE compliance_checks ALTER COLUMN user_id SET NOT NULL")
        c.execute("""
            SELECT constraint_name FROM information_schema.table_constraints
            WHERE table_name = 'compliance_checks' AND constraint_type = 'PRIMARY KEY' AND table_schema = 'public'
        """)
        pk_row = c.fetchone()
        if pk_row and pk_row[0] != 'compliance_checks_pkey_composite':
            c.execute(f"ALTER TABLE compliance_checks DROP CONSTRAINT {pk_row[0]}")
            c.execute("ALTER TABLE compliance_checks ADD CONSTRAINT compliance_checks_pkey_composite PRIMARY KEY (id, user_id)")
        elif not pk_row:
            c.execute("ALTER TABLE compliance_checks ADD CONSTRAINT compliance_checks_pkey_composite PRIMARY KEY (id, user_id)")

        c.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                user_id TEXT,
                start_time TIMESTAMP,
                end_time TIMESTAMP,
                findings_count INTEGER DEFAULT 0,
                remediations_count INTEGER DEFAULT 0,
                status TEXT
            )
        ''')

        # Add new columns if they don't exist (safe to run multiple times)
        c.execute("ALTER TABLE scans ADD COLUMN IF NOT EXISTS gate_time TIMESTAMP")
        c.execute("ALTER TABLE scans ADD COLUMN IF NOT EXISTS verified BOOLEAN DEFAULT FALSE")
        c.execute("ALTER TABLE scans ADD COLUMN IF NOT EXISTS audit_summary TEXT")
        c.execute("ALTER TABLE scans ADD COLUMN IF NOT EXISTS account_name TEXT NOT NULL DEFAULT 'Default'")

        c.execute('''
            CREATE TABLE IF NOT EXISTS feedback (
                id SERIAL PRIMARY KEY,
                user_id TEXT,
                scan_id TEXT,
                rating INTEGER,
                message TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        c.execute('''
            CREATE TABLE IF NOT EXISTS remediation_logs (
                id SERIAL PRIMARY KEY,
                scan_id TEXT,
                user_id TEXT,
                resource_name TEXT,
                action TEXT,
                status TEXT,
                duration REAL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Per-user compliance rows are created on demand by update_status() as each
        # user's scans run — no global seed data (compliance_checks is now scoped
        # per (id, user_id), so there's no single "default" row to pre-populate).

        conn.commit()
    finally:
        conn.close()

def purge_expired_credentials():
    """Delete AWS credentials not used in the last 30 minutes."""
    conn = get_connection()
    try:
        c = conn.cursor()
        c.execute("DELETE FROM aws_accounts WHERE last_used_at < NOW() - INTERVAL '30 minutes'")
        deleted = c.rowcount
        conn.commit()
        if deleted:
            print(f"[DB] Purged credentials for {deleted} inactive user(s).", file=sys.stderr)
    finally:
        conn.close()


def start_scan(scan_id: str, user_id: str | None = None, account_name: str = "Default"):
    conn = get_connection()
    try:
        c = conn.cursor()
        now = datetime.datetime.now().isoformat()
        c.execute(
            "INSERT INTO scans (id, user_id, account_name, start_time, status) VALUES (%s, %s, %s, %s, %s) ON CONFLICT (id) DO NOTHING",
            (scan_id, user_id, account_name, now, "RUNNING")
        )
        conn.commit()
    finally:
        conn.close()

_SCAN_UPDATE_COLUMNS = {
    "user_id", "start_time", "end_time", "findings_count", "remediations_count",
    "status", "gate_time", "verified", "audit_summary", "account_name",
}


def update_scan(scan_id: str, **kwargs):
    if not kwargs:
        return
    bad = set(kwargs) - _SCAN_UPDATE_COLUMNS
    if bad:
        raise ValueError(f"update_scan: refusing unknown column(s): {sorted(bad)}")
    conn = get_connection()
    try:
        c = conn.cursor()
        fields = []
        values = []
        for k, v in kwargs.items():
            fields.append(f"{k} = %s")
            values.append(v)
        values.append(scan_id)
        query = f"UPDATE scans SET {', '.join(fields)} WHERE id = %s"
        c.execute(query, tuple(values))
        conn.commit()
    finally:
        conn.close()

def _env_user_id() -> str:
    """User the current process is scanning on behalf of (set by server.py per scan)."""
    return os.environ.get("REMEDI_USER_ID", "")

def log_remediation(scan_id: str, resource_name: str, action: str, status: str, duration: float, user_id: str = None):
    if user_id is None:
        user_id = _env_user_id()
    conn = get_connection()
    try:
        c = conn.cursor()
        c.execute("INSERT INTO remediation_logs (scan_id, user_id, resource_name, action, status, duration) VALUES (%s, %s, %s, %s, %s, %s)",
                  (scan_id, user_id, resource_name, action, status, duration))
        conn.commit()
    finally:
        conn.close()

def update_status(check_id: str, status: str, user_id: str = None):
    if user_id is None:
        user_id = _env_user_id()
    conn = get_connection()
    try:
        c = conn.cursor()
        print(f"[DB] Updating {check_id} -> {status} (user={user_id})", file=sys.stderr)
        c.execute("""
            INSERT INTO compliance_checks (id, user_id, status)
            VALUES (%s, %s, %s)
            ON CONFLICT (id, user_id) DO UPDATE SET status = EXCLUDED.status
        """, (check_id, user_id, status))
        conn.commit()
    finally:
        conn.close()

def get_all_status(user_id: str):
    conn = get_connection()
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("SELECT * FROM compliance_checks WHERE user_id = %s", (user_id,))
        rows = [dict(row) for row in cur.fetchall()]
    finally:
        conn.close()
    return rows

def reset_to_vulnerable(user_id: str):
    conn = get_connection()
    try:
        c = conn.cursor()
        c.execute("UPDATE compliance_checks SET status = 'VULNERABLE' WHERE user_id = %s", (user_id,))
        conn.commit()
    finally:
        conn.close()

def count_scans_today(user_id: str, account_name: str) -> int:
    """Returns number of scans started today for this user+account combo."""
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT COUNT(*) FROM scans
            WHERE user_id = %s
              AND account_name = %s
              AND start_time >= CURRENT_DATE
        """, (user_id, account_name))
        return cur.fetchone()[0]
    finally:
        conn.close()


def get_scan_history(user_id: str | None = None):
    """Returns last 10 completed scans for the history timeline."""
    conn = get_connection()
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        if user_id:
            cur.execute("""
                SELECT id, account_name, start_time, end_time, findings_count, remediations_count, status, verified
                FROM scans
                WHERE status IN ('COMPLETED', 'ABORTED', 'SECURE') AND user_id = %s
                ORDER BY start_time DESC
                LIMIT 10
            """, (user_id,))
        else:
            cur.execute("""
                SELECT id, account_name, start_time, end_time, findings_count, remediations_count, status, verified
                FROM scans
                WHERE status IN ('COMPLETED', 'ABORTED', 'SECURE')
                ORDER BY start_time DESC
                LIMIT 10
            """)
        rows = [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()
    return rows

def get_remediation_breakdown(user_id: str):
    """Returns count of remediations grouped by category, for one user."""
    conn = get_connection()
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("""
            SELECT action, COUNT(*) as count
            FROM remediation_logs
            WHERE status = 'SUCCESS' AND user_id = %s
            GROUP BY action
        """, (user_id,))
        rows = [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()

    category_map = {
        "restrict_iam_user": "IAM",
        "remediate_s3": "S3",
        "remediate_vpc_flow_logs": "VPC",
        "revoke_security_group_ingress": "Network",
        "enforce_imdsv2": "EC2",
        "stop_instance": "EC2",
    }

    totals = {}
    for row in rows:
        cat = category_map.get(row["action"], "Other")
        totals[cat] = totals.get(cat, 0) + row["count"]

    return [{"category": k, "count": v} for k, v in totals.items()]


def get_scan_detail(scan_id: str, user_id: str):
    """Returns the full detail for one scan: audit summary + remediation log entries.
    Scoped to user_id so one user can't pull another user's scan by guessing the ID."""
    conn = get_connection()
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("""
            SELECT id, start_time, end_time, findings_count, remediations_count,
                   status, verified, audit_summary
            FROM scans WHERE id = %s AND user_id = %s
        """, (scan_id, user_id))
        scan = dict(cur.fetchone() or {})
        if not scan:
            return scan

        cur.execute("""
            SELECT resource_name, action, status, duration, timestamp
            FROM remediation_logs WHERE scan_id = %s ORDER BY timestamp ASC
        """, (scan_id,))
        scan["remediations"] = [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()
    return scan


def save_feedback(user_id: str, scan_id: str, rating: int, message: str):
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO feedback (user_id, scan_id, rating, message) VALUES (%s, %s, %s, %s)",
            (user_id, scan_id, rating, message)
        )
        conn.commit()
    finally:
        conn.close()