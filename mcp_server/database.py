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
            
    c = conn.cursor()
    
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
            id TEXT PRIMARY KEY,
            user_id TEXT,
            name TEXT,
            description TEXT,
            status TEXT
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id TEXT PRIMARY KEY,
            user_id TEXT,
            start_time TIMESTAMP,
            end_time TIMESTAMP,
            findings_count INTEGER DEFAULT 0,
            remediations_count INTEGER DEFAULT 0,
            total_tokens INTEGER DEFAULT 0,
            estimated_cost REAL DEFAULT 0.0,
            status TEXT
        )
    ''')

    # Add new columns if they don't exist (safe to run multiple times)
    c.execute("ALTER TABLE scans ADD COLUMN IF NOT EXISTS gate_time TIMESTAMP")
    c.execute("ALTER TABLE scans ADD COLUMN IF NOT EXISTS verified BOOLEAN DEFAULT FALSE")
    c.execute("ALTER TABLE scans ADD COLUMN IF NOT EXISTS audit_summary TEXT")

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
    
    initial_data = [
        ("check_iam", "IAM Privilege Escalation", "Ensures no unauthorized Admin users", "SAFE"),
        ("check_s3", "S3 Data Leakage", "Prevents Public Access to Buckets", "SAFE"),
        ("check_ssh", "Network Exposure", "Restricts Port 22 (SSH) Access", "SAFE"),
        ("check_ec2", "Compute Hardening", "Enforces IMDSv2 & Encryption", "SAFE"),
        ("check_vpc", "Network Logging", "Ensures VPC Flow Logs are Active", "SAFE"),
        ("check_rds", "RDS Public Access", "Ensures no RDS databases are publicly accessible", "SAFE"),
        ("check_lambda", "Lambda Over-Permission", "Ensures Lambda execution roles follow least privilege", "SAFE"),
        ("check_cloudtrail", "CloudTrail Logging", "Ensures CloudTrail is enabled and actively logging", "SAFE"),
    ]
    
    for row in initial_data:
        c.execute("INSERT INTO compliance_checks (id, name, description, status) VALUES (%s, %s, %s, %s) ON CONFLICT (id) DO NOTHING", row)
    
    conn.commit()
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


def start_scan(scan_id: str, user_id: str | None = None):
    conn = get_connection()
    try:
        c = conn.cursor()
        now = datetime.datetime.now().isoformat()
        c.execute(
            "INSERT INTO scans (id, user_id, start_time, status) VALUES (%s, %s, %s, %s) ON CONFLICT (id) DO NOTHING",
            (scan_id, user_id, now, "RUNNING")
        )
        conn.commit()
    finally:
        conn.close()

def update_scan(scan_id: str, **kwargs):
    if not kwargs:
        return
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

def log_remediation(scan_id: str, resource_name: str, action: str, status: str, duration: float):
    conn = get_connection()
    try:
        c = conn.cursor()
        c.execute("INSERT INTO remediation_logs (scan_id, resource_name, action, status, duration) VALUES (%s, %s, %s, %s, %s)",
                  (scan_id, resource_name, action, status, duration))
        conn.commit()
    finally:
        conn.close()

def update_status(check_id: str, status: str):
    conn = get_connection()
    try:
        c = conn.cursor()
        print(f"[DB] Updating {check_id} -> {status}", file=sys.stderr)
        c.execute("UPDATE compliance_checks SET status = %s WHERE id = %s", (status, check_id))
        if c.rowcount == 0:
            print(f"[DB] WARNING: Update failed. Check ID '{check_id}' not found in DB.", file=sys.stderr)
        conn.commit()
    finally:
        conn.close()

def get_all_status():
    conn = get_connection()
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("SELECT * FROM compliance_checks")
        rows = [dict(row) for row in cur.fetchall()]
    finally:
        conn.close()
    return rows

def reset_to_vulnerable():
    conn = get_connection()
    try:
        c = conn.cursor()
        c.execute("UPDATE compliance_checks SET status = 'VULNERABLE'")
        conn.commit()
    finally:
        conn.close()

def get_scan_history(user_id: str | None = None):
    """Returns last 10 completed scans for the history timeline."""
    conn = get_connection()
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        if user_id:
            cur.execute("""
                SELECT id, start_time, end_time, findings_count, remediations_count, status, verified
                FROM scans
                WHERE status IN ('COMPLETED', 'ABORTED', 'SECURE') AND user_id = %s
                ORDER BY start_time DESC
                LIMIT 10
            """, (user_id,))
        else:
            cur.execute("""
                SELECT id, start_time, end_time, findings_count, remediations_count, status, verified
                FROM scans
                WHERE status IN ('COMPLETED', 'ABORTED', 'SECURE')
                ORDER BY start_time DESC
                LIMIT 10
            """)
        rows = [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()
    return rows

def get_remediation_breakdown():
    """Returns count of remediations grouped by category."""
    conn = get_connection()
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("""
            SELECT action, COUNT(*) as count
            FROM remediation_logs
            WHERE status = 'SUCCESS'
            GROUP BY action
        """)
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


def get_scan_detail(scan_id: str):
    """Returns the full detail for one scan: audit summary + remediation log entries."""
    conn = get_connection()
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("""
            SELECT id, start_time, end_time, findings_count, remediations_count,
                   status, verified, estimated_cost, total_tokens, audit_summary
            FROM scans WHERE id = %s
        """, (scan_id,))
        scan = dict(cur.fetchone() or {})

        cur.execute("""
            SELECT resource_name, action, status, duration, timestamp
            FROM remediation_logs WHERE scan_id = %s ORDER BY timestamp ASC
        """, (scan_id,))
        scan["remediations"] = [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()
    return scan