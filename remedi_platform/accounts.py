import json
import os
from cryptography.fernet import Fernet
from mcp_server.database import get_connection


MAX_ACCOUNTS_PER_USER = 3


class CredentialDecryptError(Exception):
    """Stored ciphertext could not be decrypted — usually ENCRYPTION_KEY rotated."""


class AccountLimitError(Exception):
    """User is already at MAX_ACCOUNTS_PER_USER connected accounts."""


def _fernet() -> Fernet:
    key = os.environ.get("ENCRYPTION_KEY")
    if not key:
        raise RuntimeError("ENCRYPTION_KEY is not set in environment")
    return Fernet(key.encode())


def seal_json(data: dict) -> str:
    """Fernet-encrypt a dict for short-lived transport (e.g. handing scan
    credentials to the Celery worker without putting them on the broker)."""
    return _fernet().encrypt(json.dumps(data).encode()).decode()


def unseal_json(token: str) -> dict:
    return json.loads(_fernet().decrypt(token.encode()).decode())


def save_aws_credentials(user_id: str, account_name: str, access_key: str, secret_key: str) -> None:
    f = _fernet()
    access_key_enc = f.encrypt(access_key.encode()).decode()
    secret_key_enc = f.encrypt(secret_key.encode()).decode()

    conn = get_connection()
    try:
        c = conn.cursor()
        # Serialize per-user so two concurrent "add account" calls with different
        # names can't both pass the COUNT(*) check below (READ COMMITTED lets
        # both see the pre-insert snapshot). Released on commit.
        c.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", (user_id,))
        # Atomic cap enforcement: the row is inserted only if the user is under
        # the limit OR this account_name already exists (an update).
        c.execute(
            """
            INSERT INTO aws_accounts (user_id, account_name, access_key_enc, secret_key_enc, last_used_at)
            SELECT %(uid)s, %(name)s, %(ak)s, %(sk)s, NOW()
            WHERE (SELECT COUNT(*) FROM aws_accounts WHERE user_id = %(uid)s) < %(cap)s
               OR EXISTS (SELECT 1 FROM aws_accounts WHERE user_id = %(uid)s AND account_name = %(name)s)
            ON CONFLICT (user_id, account_name) DO UPDATE
              SET access_key_enc = EXCLUDED.access_key_enc,
                  secret_key_enc = EXCLUDED.secret_key_enc,
                  last_used_at   = NOW()
            """,
            {"uid": user_id, "name": account_name, "ak": access_key_enc,
             "sk": secret_key_enc, "cap": MAX_ACCOUNTS_PER_USER},
        )
        inserted = c.rowcount
        conn.commit()
    finally:
        conn.close()

    if inserted == 0:
        raise AccountLimitError(
            f"Maximum of {MAX_ACCOUNTS_PER_USER} AWS accounts allowed per user"
        )


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

    try:
        f = _fernet()
        return {
            "AWS_ACCESS_KEY_ID":     f.decrypt(row[0].encode()).decode(),
            "AWS_SECRET_ACCESS_KEY": f.decrypt(row[1].encode()).decode(),
        }
    except Exception as exc:
        raise CredentialDecryptError(
            f"Could not decrypt stored AWS credentials for '{account_name}': {exc}"
        )


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


def save_protected_users(user_id: str, account_name: str, users: list[str]) -> None:
    conn = get_connection()
    try:
        c = conn.cursor()
        c.execute(
            "UPDATE aws_accounts SET protected_users = %s WHERE user_id = %s AND account_name = %s",
            (",".join(u.strip() for u in users if u.strip()), user_id, account_name),
        )
        conn.commit()
    finally:
        conn.close()


def get_protected_users(user_id: str, account_name: str) -> list[str]:
    conn = get_connection()
    try:
        c = conn.cursor()
        c.execute(
            "SELECT protected_users FROM aws_accounts WHERE user_id = %s AND account_name = %s",
            (user_id, account_name),
        )
        row = c.fetchone()
    finally:
        conn.close()
    if not row or not row[0]:
        return []
    return [u.strip() for u in row[0].split(",") if u.strip()]


def has_aws_account(user_id: str) -> bool:
    conn = get_connection()
    try:
        c = conn.cursor()
        c.execute("SELECT 1 FROM aws_accounts WHERE user_id = %s LIMIT 1", (user_id,))
        return c.fetchone() is not None
    finally:
        conn.close()
