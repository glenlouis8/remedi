import os
import sys
import signal
import threading
import time
import uuid
import redis as redis_lib
from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel

from mcp_server.database import (
    reset_to_vulnerable, get_all_status, init_db,
    get_scan_history, get_remediation_breakdown, get_scan_detail, get_connection,
    purge_expired_credentials, count_scans_today, save_feedback,
)
from remedi_platform.auth import get_current_user
from remedi_platform.accounts import (
    save_aws_credentials, get_aws_credentials, has_aws_account,
    delete_aws_credentials, list_aws_accounts, count_aws_accounts,
    save_protected_users, get_protected_users,
)
from remedi_platform.compliance import get_cis_score
from worker import celery_app, run_scan_task

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=[os.environ.get("FRONTEND_URL", "http://localhost:3000")],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- REDIS ---
REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
r = redis_lib.Redis.from_url(REDIS_URL, decode_responses=True)
# Separate connection for pubsub streaming — no socket timeout so it can block during long scans
r_pubsub = redis_lib.Redis.from_url(
    REDIS_URL,
    decode_responses=True,
    socket_timeout=None,
    socket_connect_timeout=5,
    socket_keepalive=True,
    health_check_interval=30,
)

# --- DB INIT ---
max_retries = 30
for i in range(max_retries):
    try:
        init_db()
        print("✅ Database initialized.")
        break
    except Exception as e:
        if i == max_retries - 1:
            print(f"❌ Database connection failed after {max_retries} attempts: {e}")
            raise
        print(f"⚠️  DB attempt {i+1}/{max_retries}: {e}")
        time.sleep(2)


# --- CREDENTIAL EXPIRY (30 min inactivity) ---
def _credential_purge_loop():
    while True:
        time.sleep(300)
        try:
            purge_expired_credentials()
        except Exception as e:
            print(f"⚠️  Credential purge error: {e}")

threading.Thread(target=_credential_purge_loop, daemon=True).start()


# --- SIGNAL HANDLING ---
def handle_sigterm(*args):
    sys.exit(0)

signal.signal(signal.SIGTERM, handle_sigterm)


# --- SCHEMAS ---
class AWSCredentials(BaseModel):
    account_name: str = 'Default'
    access_key: str
    secret_key: str

class RunAgentRequest(BaseModel):
    account_name: str = 'Default'

class ApproveRequest(BaseModel):
    scan_id: str
    approved_resources: list[str] | None = None


# --- ROUTES ---

@app.post("/api/accounts")
def connect_aws(creds: AWSCredentials, user: dict = Depends(get_current_user)):
    if not creds.access_key.startswith("AKIA") or len(creds.access_key) != 20:
        raise HTTPException(status_code=400, detail="Invalid AWS Access Key format")
    if not creds.account_name.strip():
        raise HTTPException(status_code=400, detail="Account name cannot be empty")
    user_id = user["sub"]
    existing = count_aws_accounts(user_id)
    accounts = list_aws_accounts(user_id)
    is_new = not any(a["account_name"] == creds.account_name for a in accounts)
    if is_new and existing >= 3:
        raise HTTPException(status_code=400, detail="Maximum of 3 AWS accounts allowed per user")
    save_aws_credentials(user_id, creds.account_name.strip(), creds.access_key, creds.secret_key)
    return {"status": "connected", "account_name": creds.account_name.strip()}


@app.get("/api/accounts")
def list_accounts(user: dict = Depends(get_current_user)):
    return list_aws_accounts(user["sub"])


@app.get("/api/accounts/status")
def account_status(user: dict = Depends(get_current_user)):
    return {"connected": has_aws_account(user["sub"])}


@app.delete("/api/accounts")
def disconnect_all(user: dict = Depends(get_current_user)):
    delete_aws_credentials(user["sub"])
    return {"status": "disconnected"}


@app.delete("/api/accounts/{account_name}")
def disconnect_one(account_name: str, user: dict = Depends(get_current_user)):
    delete_aws_credentials(user["sub"], account_name)
    return {"status": "disconnected", "account_name": account_name}


@app.get("/api/scans/remaining")
def scans_remaining(account_name: str = "Default", user: dict = Depends(get_current_user)):
    used = count_scans_today(user["sub"], account_name)
    return {"remaining": max(0, 3 - used), "limit": 3, "used": used}


class FeedbackRequest(BaseModel):
    scan_id: str
    account_name: str = "Default"
    rating: int
    message: str = ""

@app.post("/api/feedback")
def submit_feedback(body: FeedbackRequest, user: dict = Depends(get_current_user)):
    if not 1 <= body.rating <= 5:
        raise HTTPException(status_code=400, detail="Rating must be 1-5")
    save_feedback(user["sub"], body.scan_id, body.rating, body.message)
    webhook_url = os.environ.get("DISCORD_FEEDBACK_WEBHOOK")
    if webhook_url:
        stars = "★" * body.rating + "☆" * (5 - body.rating)
        content = (
            f"⭐ **New Feedback — Remedi**\n"
            f"Rating: {stars} ({body.rating}/5)\n"
            f"Scan: `{body.scan_id}` · Account: `{body.account_name}`"
        )
        if body.message:
            content += f"\nMessage: \"{body.message}\""
        try:
            import requests as req
            req.post(webhook_url, json={"content": content}, timeout=5)
        except Exception:
            pass
    return {"status": "received"}


@app.delete("/api/user")
def delete_user(user: dict = Depends(get_current_user)):
    import requests as req
    user_id = user["sub"]
    clerk_secret = os.environ.get("CLERK_SECRET_KEY", "")
    if not clerk_secret:
        raise HTTPException(status_code=500, detail="Server misconfiguration")
    delete_aws_credentials(user_id)
    resp = req.delete(
        f"https://api.clerk.com/v1/users/{user_id}",
        headers={"Authorization": f"Bearer {clerk_secret}"},
    )
    if resp.status_code not in (200, 204):
        raise HTTPException(status_code=502, detail="Failed to delete account")
    return {"status": "deleted"}


@app.get("/api/iam/users")
def list_iam_users(account_name: str = "Default", user: dict = Depends(get_current_user)):
    import boto3, botocore.exceptions
    creds = get_aws_credentials(user["sub"], account_name)
    if not creds:
        raise HTTPException(status_code=400, detail="No AWS account connected.")
    try:
        session = boto3.Session(
            aws_access_key_id=creds["AWS_ACCESS_KEY_ID"],
            aws_secret_access_key=creds["AWS_SECRET_ACCESS_KEY"],
        )
        sts = session.client("sts")
        identity = sts.get_caller_identity()
        credential_user = identity["Arn"].split("/")[-1]

        iam = session.client("iam")
        paginator = iam.get_paginator("list_users")
        users = []
        for page in paginator.paginate():
            users.extend(u["UserName"] for u in page["Users"])

        return {"users": sorted(users), "credential_user": credential_user}
    except botocore.exceptions.ClientError as e:
        raise HTTPException(status_code=400, detail=str(e))


class ProtectedUsersRequest(BaseModel):
    account_name: str = "Default"
    protected_users: list[str]

@app.post("/api/accounts/protected-users")
def set_protected_users(body: ProtectedUsersRequest, user: dict = Depends(get_current_user)):
    save_protected_users(user["sub"], body.account_name, body.protected_users)
    return {"ok": True}

@app.get("/api/accounts/protected-users")
def get_protected_users_route(account_name: str = "Default", user: dict = Depends(get_current_user)):
    users = get_protected_users(user["sub"], account_name)
    return {"protected_users": users}


@app.get("/api/compliance")
def compliance_score(user: dict = Depends(get_current_user)):
    return get_cis_score()


@app.get("/api/status")
def get_status(user: dict = Depends(get_current_user)):
    return JSONResponse(content=get_all_status())


@app.get("/api/metrics")
def get_metrics(user: dict = Depends(get_current_user)):
    import datetime
    import psycopg2.extras

    user_id = user["sub"]
    conn = get_connection()
    try:
        c = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        c.execute(
            "SELECT * FROM scans WHERE status IN ('COMPLETED', 'ABORTED', 'SECURE', 'VERIFIED', 'FAILED') AND user_id = %s",
            (user_id,),
        )
        scans = c.fetchall()
    finally:
        conn.close()

    if not scans:
        return {
            "avg_mttr": "0s", "avg_ttd": "0s", "success_rate": "100%",
            "verification_pass_rate": "N/A",
            "total_scans": 0,
        }

    durations, ttd_list = [], []
    verified_count = completed_count = aborted_count = 0

    for s in scans:
        status = s["status"]

        if status in ("COMPLETED", "SECURE", "VERIFIED"):
            completed_count += 1
            try:
                start = s["start_time"] if isinstance(s["start_time"], datetime.datetime) else datetime.datetime.fromisoformat(s["start_time"])
                end = s["end_time"] if isinstance(s["end_time"], datetime.datetime) else datetime.datetime.fromisoformat(s["end_time"])
                durations.append((end - start).total_seconds())
            except Exception:
                pass
            if s.get("verified"):
                verified_count += 1
        elif status in ("ABORTED", "FAILED"):
            aborted_count += 1

        try:
            if s.get("gate_time"):
                start = s["start_time"] if isinstance(s["start_time"], datetime.datetime) else datetime.datetime.fromisoformat(s["start_time"])
                gate = s["gate_time"] if isinstance(s["gate_time"], datetime.datetime) else datetime.datetime.fromisoformat(s["gate_time"])
                ttd_list.append((gate - start).total_seconds())
        except Exception:
            pass

    total = len(scans)
    success_pct = int(completed_count / total * 100) if total else 100

    return {
        "avg_mttr": f"{int(sum(durations) / len(durations) if durations else 0)}s",
        "avg_ttd": f"{int(sum(ttd_list) / len(ttd_list) if ttd_list else 0)}s",
        "success_rate": f"{success_pct}%",
        "verification_pass_rate": f"{int(verified_count / completed_count * 100)}%" if completed_count else "N/A",
        "total_scans": total,
    }


@app.get("/api/metrics/history")
def get_history(user: dict = Depends(get_current_user)):
    return get_scan_history(user_id=user["sub"])


@app.get("/api/metrics/history/{scan_id}")
def get_scan_detail_endpoint(scan_id: str, user: dict = Depends(get_current_user)):
    detail = get_scan_detail(scan_id)
    if not detail:
        raise HTTPException(status_code=404, detail="Scan not found")
    return detail


@app.get("/api/metrics/breakdown")
def get_breakdown(user: dict = Depends(get_current_user)):
    return get_remediation_breakdown()


MAX_CONCURRENT_SCANS = 3

@app.post("/api/run-agent")
def run_agent(body: RunAgentRequest, user: dict = Depends(get_current_user)):
    user_id = user["sub"]
    creds = get_aws_credentials(user_id, body.account_name)
    if not creds:
        raise HTTPException(status_code=400, detail="No AWS account connected. Please complete onboarding first.")

    # Count active scans via Redis
    active = int(r.get("active_scans") or 0)
    if active >= MAX_CONCURRENT_SCANS:
        raise HTTPException(status_code=503, detail="Server is busy with other scans. Try again in a few minutes.")

    used = count_scans_today(user_id, body.account_name or "Default")
    if used >= 3:
        raise HTTPException(status_code=429, detail="Scan limit reached: 3 scans per account per day. Resets at midnight.")

    env = dict(creds)

    import boto3
    try:
        sts = boto3.Session(
            aws_access_key_id=creds["AWS_ACCESS_KEY_ID"],
            aws_secret_access_key=creds["AWS_SECRET_ACCESS_KEY"],
        ).client("sts")
        credential_user = sts.get_caller_identity()["Arn"].split("/")[-1]
    except Exception:
        credential_user = None

    protected = get_protected_users(user_id, body.account_name or "Default")
    if credential_user and credential_user not in protected:
        protected.append(credential_user)

    if protected:
        env["PROTECTED_IAM_USERS"] = ",".join(u.strip() for u in protected if u.strip())

    env["REMEDI_USER_ID"] = user_id
    env["REMEDI_ACCOUNT_NAME"] = body.account_name or "Default"

    scan_id = f"SCAN-{uuid.uuid4().hex[:8].upper()}"

    # Hand off to Celery worker — FastAPI is now free
    run_scan_task.delay(scan_id, user_id, env)

    def stream():
        while True:
            pubsub = r_pubsub.pubsub()
            pubsub.subscribe(f"scan:{scan_id}:output")
            try:
                for message in pubsub.listen():
                    if message["type"] == "message":
                        data = message["data"]
                        if data == "__DONE__":
                            return
                        yield data if data.endswith("\n") else data + "\n"
                return
            except Exception:
                # reconnect on timeout/disconnect and keep streaming
                try:
                    pubsub.unsubscribe(f"scan:{scan_id}:output")
                except Exception:
                    pass
                status = r.get(f"scan:{scan_id}:status")
                if status in ("done", "aborted", None):
                    return

    return StreamingResponse(
        stream(),
        media_type="text/plain",
        headers={
            "X-Accel-Buffering": "no",
            "Cache-Control": "no-cache",
            "Transfer-Encoding": "chunked",
        },
    )


@app.post("/api/approve")
def approve_remediation(body: ApproveRequest, user: dict = Depends(get_current_user)):
    owner = r.get(f"scan:{body.scan_id}:owner")
    if owner != user["sub"]:
        raise HTTPException(status_code=403, detail="Not your scan")

    payload = "approve"
    if body.approved_resources:
        payload = "approve:" + ",".join(body.approved_resources)

    # lpush unblocks the worker's blpop immediately
    r.lpush(f"scan:{body.scan_id}:decision", payload)
    return {"status": "approved"}


@app.post("/api/stop")
def stop_process(scan_id: str, user: dict = Depends(get_current_user)):
    owner = r.get(f"scan:{scan_id}:owner")
    if owner != user["sub"]:
        raise HTTPException(status_code=403, detail="Not your scan")
    # Push abort signal — worker's blpop picks it up if waiting, otherwise scan ends naturally
    r.lpush(f"scan:{scan_id}:decision", "abort")
    r.set(f"scan:{scan_id}:status", "aborted", ex=7200)
    return {"status": "stopped"}


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8080))
    uvicorn.run(app, host="0.0.0.0", port=port)
