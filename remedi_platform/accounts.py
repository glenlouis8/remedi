import os
from cryptography.fernet import Fernet
from mcp_server.database import get_connection


def _fernet() -> Fernet:
    key = os.environ.get("ENCRYPTION_KEY")
    if not key:
        raise RuntimeError("ENCRYPTION_KEY is not set in environment")
    return Fernet(key.encode())


def save_aws_credentials(user_id: str, account_name: str, access_key: str, secret_key: str) -> None:
    f = _fernet()
    access_key_enc = f.encrypt(access_key.encode()).decode()
    secret_key_enc = f.encrypt(secret_key.encode()).decode()

    conn = get_connection()
    try:
        c = conn.cursor()
        c.execute(
            """
            INSERT INTO aws_accounts (user_id, account_name, access_key_enc, secret_key_enc, last_used_at)
            VALUES (%s, %s, %s, %s, NOW())
            ON CONFLICT (user_id, account_name) DO UPDATE
              SET access_key_enc = EXCLUDED.access_key_enc,
                  secret_key_enc = EXCLUDED.secret_key_enc,
                  last_used_at   = NOW()
            """,
            (user_id, account_name, access_key_enc, secret_key_enc),
        )
        conn.commit()
    finally:
        conn.close()


def get_aws_credentials(user_id: str, account_name: str) -> dict | None:
    conn = get_connection()
    try:
        c = conn.cursor()
        c.execute(
            """
            UPDATE aws_accounts SET last_used_at = NOW()
            WHERE user_id = %s AND account_name = %s
            RETURNING access_key_enc, secret_key_enc
            """,
            (user_id, account_name),
        )
        row = c.fetchone()
        conn.commit()
    finally:
        conn.close()

    if row is None:
        return None

    f = _fernet()
    return {
        "AWS_ACCESS_KEY_ID":     f.decrypt(row[0].encode()).decode(),
        "AWS_SECRET_ACCESS_KEY": f.decrypt(row[1].encode()).decode(),
    }


def list_aws_accounts(user_id: str) -> list[dict]:
    conn = get_connection()
    try:
        c = conn.cursor()
        c.execute(
            "SELECT account_name, created_at FROM aws_accounts WHERE user_id = %s ORDER BY created_at ASC",
            (user_id,),
        )
        rows = c.fetchall()
    finally:
        conn.close()
    return [{"account_name": r[0], "created_at": r[1].isoformat() if r[1] else None} for r in rows]


def count_aws_accounts(user_id: str) -> int:
    conn = get_connection()
    try:
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM aws_accounts WHERE user_id = %s", (user_id,))
        return c.fetchone()[0]
    finally:
        conn.close()


def delete_aws_credentials(user_id: str, account_name: str | None = None) -> None:
    conn = get_connection()
    try:
        c = conn.cursor()
        if account_name is None:
            c.execute("DELETE FROM aws_accounts WHERE user_id = %s", (user_id,))
        else:
            c.execute(
                "DELETE FROM aws_accounts WHERE user_id = %s AND account_name = %s",
                (user_id, account_name),
            )
        conn.commit()
    finally:
        conn.close()


def has_aws_account(user_id: str) -> bool:
    conn = get_connection()
    try:
        c = conn.cursor()
        c.execute("SELECT 1 FROM aws_accounts WHERE user_id = %s LIMIT 1", (user_id,))
        return c.fetchone() is not None
    finally:
        conn.close()
