import subprocess
import os
import sys
import signal
import threading
import time
from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from mcp_server.database import (
    reset_to_vulnerable, get_all_status, init_db,
    get_scan_history, get_remediation_breakdown, get_scan_detail, get_connection,
    purge_expired_credentials,
)
from remedi_platform.auth import get_current_user
from remedi_platform.accounts import (
    save_aws_credentials, get_aws_credentials, has_aws_account,
    delete_aws_credentials, list_aws_accounts, count_aws_accounts,
)
from remedi_platform.compliance import get_cis_score

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=[os.environ.get("FRONTEND_URL", "http://localhost:3000")],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
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
        time.sleep(300)  # check every 5 minutes
        try:
            purge_expired_credentials()
        except Exception as e:
            print(f"⚠️  Credential purge error: {e}")

threading.Thread(target=_credential_purge_loop, daemon=True).start()


# --- AGENT PROCESS MANAGER ---
class ProcessManager:
    def __init__(self):
        self.process = None
        self.is_running = False
        self.waiting_for_approval = False

    def start_agent(self, env: dict):
        if self.is_running and self.process and self.process.poll() is None:
            return

        proc_env = os.environ.copy()
        proc_env.update(env)
        proc_env["PYTHONUNBUFFERED"] = "1"

        self.process = subprocess.Popen(
            ["python", "-u", "main.py"],
            cwd=os.getcwd(),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=proc_env,
            text=True,
            bufsize=1,
            universal_newlines=True,
        )
        self.is_running = True
        self.waiting_for_approval = False

    def stream_output(self):
        """Generator: yields stdout lines from the agent subprocess to the HTTP response."""
        try:
            for line in iter(self.process.stdout.readline, ""):
                if line:
                    sys.stdout.write(line)
                    sys.stdout.flush()
                    if "PAUSING FOR HUMAN REVIEW" in line:
                        self.waiting_for_approval = True
                    yield line
        finally:
            self.process.stdout.close()
            self.is_running = False

    def send_approval(self, approved_resources: list[str] | None = None):
        if self.process and self.waiting_for_approval:
            try:
                if approved_resources:
                    payload = "approve:" + ",".join(approved_resources) + "\n"
                else:
                    payload = "approve\n"
                self.process.stdin.write(payload)
                self.process.stdin.flush()
                self.waiting_for_approval = False
                return True
            except (OSError, BrokenPipeError):
                self.waiting_for_approval = False
        return False


# One manager per user session (keyed by user_id)
_managers: dict[str, ProcessManager] = {}


def _get_manager(user_id: str) -> ProcessManager:
    if user_id not in _managers:
        _managers[user_id] = ProcessManager()
    return _managers[user_id]


# --- SIGNAL HANDLING ---
def handle_sigterm(*args):
    for m in _managers.values():
        if m.process and m.process.poll() is None:
            m.process.terminate()
    sys.exit(0)

signal.signal(signal.SIGTERM, handle_sigterm)


# --- SCHEMAS ---
class AWSCredentials(BaseModel):
    account_name: str = 'Default'
    access_key: str
    secret_key: str

class RunAgentRequest(BaseModel):
    account_name: str = 'Default'
    protected_users: list[str] = []


# --- ROUTES ---

@app.post("/api/accounts")
def connect_aws(creds: AWSCredentials, user: dict = Depends(get_current_user)):
    if not creds.access_key.startswith("AKIA") or len(creds.access_key) != 20:
        raise HTTPException(status_code=400, detail="Invalid AWS Access Key format")
    if not creds.account_name.strip():
        raise HTTPException(status_code=400, detail="Account name cannot be empty")
    user_id = user["sub"]
    existing = count_aws_accounts(user_id)
    # Allow upsert on existing account name; only block if it's a brand-new name and already at 3
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
        # Who owns these credentials — always auto-protect this user
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
            "SELECT * FROM scans WHERE status IN ('COMPLETED', 'ABORTED') AND user_id = %s",
            (user_id,),
        )
        scans = c.fetchall()
        c.execute(
            "SELECT SUM(estimated_cost) as total_cost, SUM(total_tokens) as total_tokens FROM scans WHERE user_id = %s",
            (user_id,),
        )
        totals = c.fetchone()
    finally:
        conn.close()

    if not scans:
        return {
            "avg_mttr": "0s", "avg_ttd": "0s", "success_rate": "100%",
            "verification_pass_rate": "N/A",
            "total_cost": f"${totals.get('total_cost', 0.0) or 0:.4f}",
            "total_tokens": totals.get("total_tokens", 0) or 0,
            "total_scans": 0,
        }

    durations, ttd_list, success_rates = [], [], []
    verified_count = completed_count = 0

    for s in scans:
        if s["status"] == "COMPLETED":
            try:
                start = s["start_time"] if isinstance(s["start_time"], datetime.datetime) else datetime.datetime.fromisoformat(s["start_time"])
                end = s["end_time"] if isinstance(s["end_time"], datetime.datetime) else datetime.datetime.fromisoformat(s["end_time"])
                durations.append((end - start).total_seconds())
            except Exception:
                pass

        try:
            if s.get("gate_time"):
                start = s["start_time"] if isinstance(s["start_time"], datetime.datetime) else datetime.datetime.fromisoformat(s["start_time"])
                gate = s["gate_time"] if isinstance(s["gate_time"], datetime.datetime) else datetime.datetime.fromisoformat(s["gate_time"])
                ttd_list.append((gate - start).total_seconds())
        except Exception:
            pass

        if s["status"] == "COMPLETED" and s["findings_count"]:
            success_rates.append(min(1.0, s["remediations_count"] / s["findings_count"]))
            completed_count += 1
            if s.get("verified"):
                verified_count += 1

    return {
        "avg_mttr": f"{int(sum(durations) / len(durations) if durations else 0)}s",
        "avg_ttd": f"{int(sum(ttd_list) / len(ttd_list) if ttd_list else 0)}s",
        "success_rate": f"{int((sum(success_rates) / len(success_rates) * 100) if success_rates else 100)}%",
        "verification_pass_rate": f"{int(verified_count / completed_count * 100)}%" if completed_count else "N/A",
        "total_cost": f"${totals.get('total_cost', 0.0) or 0:.4f}",
        "total_tokens": totals.get("total_tokens", 0) or 0,
        "total_scans": len(scans),
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


@app.post("/api/run-agent")
def run_agent(body: RunAgentRequest, user: dict = Depends(get_current_user)):
    user_id = user["sub"]
    creds = get_aws_credentials(user_id, body.account_name)
    if not creds:
        raise HTTPException(status_code=400, detail="No AWS account connected. Please complete onboarding first.")

    env = dict(creds)

    # Always auto-protect the IAM user whose credentials we're using
    import boto3
    try:
        sts = boto3.Session(
            aws_access_key_id=creds["AWS_ACCESS_KEY_ID"],
            aws_secret_access_key=creds["AWS_SECRET_ACCESS_KEY"],
        ).client("sts")
        credential_user = sts.get_caller_identity()["Arn"].split("/")[-1]
    except Exception:
        credential_user = None

    protected = list(body.protected_users)
    if credential_user and credential_user not in protected:
        protected.append(credential_user)

    if protected:
        env["PROTECTED_IAM_USERS"] = ",".join(u.strip() for u in protected if u.strip())

    env["REMEDI_USER_ID"] = user_id

    manager = _get_manager(user_id)
    manager.start_agent(env)
    from fastapi.responses import StreamingResponse
    return StreamingResponse(manager.stream_output(), media_type="text/plain")


class ApproveRequest(BaseModel):
    approved_resources: list[str] | None = None

@app.post("/api/approve")
def approve_remediation(body: ApproveRequest = ApproveRequest(), user: dict = Depends(get_current_user)):
    manager = _get_manager(user["sub"])
    if manager.send_approval(body.approved_resources):
        return {"status": "approved"}
    raise HTTPException(status_code=400, detail="No agent waiting for approval")


@app.post("/api/stop")
def stop_process(user: dict = Depends(get_current_user)):
    manager = _get_manager(user["sub"])
    if manager.is_running and manager.process:
        manager.process.terminate()
    return {"status": "stopped"}


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8080))
    uvicorn.run(app, host="0.0.0.0", port=port)
