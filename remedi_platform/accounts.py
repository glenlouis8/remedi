import os
from cryptography.fernet import Fernet
from mcp_server.database import get_connection


def _fernet() -> Fernet:
    key = os.environ.get("ENCRYPTION_KEY")
    if not key:
        raise RuntimeError("ENCRYPTION_KEY is not set in environment")
    return Fernet(key.encode())


def save_aws_credentials(user_id: str, access_key: str, secret_key: str) -> None:
    f = _fernet()
    access_key_enc = f.encrypt(access_key.encode()).decode()
    secret_key_enc = f.encrypt(secret_key.encode()).decode()

    conn = get_connection()
    try:
        c = conn.cursor()
        c.execute(
            """
            INSERT INTO aws_accounts (user_id, access_key_enc, secret_key_enc)
            VALUES (%s, %s, %s)
            ON CONFLICT (user_id) DO UPDATE
              SET access_key_enc = EXCLUDED.access_key_enc,
                  secret_key_enc = EXCLUDED.secret_key_enc
            """,
            (user_id, access_key_enc, secret_key_enc),
        )
        conn.commit()
    finally:
        conn.close()


def get_aws_credentials(user_id: str) -> dict | None:
    conn = get_connection()
    try:
        c = conn.cursor()
        c.execute(
            "SELECT access_key_enc, secret_key_enc FROM aws_accounts WHERE user_id = %s",
            (user_id,),
        )
        row = c.fetchone()
    finally:
        conn.close()

    if row is None:
        return None

    f = _fernet()
    return {
        "AWS_ACCESS_KEY_ID": f.decrypt(row[0].encode()).decode(),
        "AWS_SECRET_ACCESS_KEY": f.decrypt(row[1].encode()).decode(),
    }


def has_aws_account(user_id: str) -> bool:
    conn = get_connection()
    try:
        c = conn.cursor()
        c.execute("SELECT 1 FROM aws_accounts WHERE user_id = %s", (user_id,))
        return c.fetchone() is not None
    finally:
        conn.close()
