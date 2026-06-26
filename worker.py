import os
import sys
import subprocess
import redis
from celery import Celery
from dotenv import load_dotenv

load_dotenv()

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")

# Celery/kombu rejects a rediss:// broker URL unless ssl_cert_reqs is set.
# Upstash gives a rediss:// URL without it — append a default so the worker can start.
# (redis-py clients below handle TLS on their own and don't need this.)
BROKER_URL = REDIS_URL
if BROKER_URL.startswith("rediss://") and "ssl_cert_reqs" not in BROKER_URL:
    BROKER_URL += ("&" if "?" in BROKER_URL else "?") + "ssl_cert_reqs=CERT_NONE"

celery_app = Celery("remedi", broker=BROKER_URL)
r = redis.Redis.from_url(REDIS_URL, decode_responses=True)
# Separate connection for blpop — no socket timeout so it can block up to 1800s
r_blocking = redis.Redis.from_url(REDIS_URL, decode_responses=True, socket_timeout=None)


@celery_app.task(bind=True)
def run_scan_task(self, scan_id: str, user_id: str, env: dict):
    proc_env = os.environ.copy()
    proc_env.update(env)
    proc_env["PYTHONUNBUFFERED"] = "1"
    proc_env["REMEDI_SCAN_ID"] = scan_id

    print(f"[worker] spawning main.py for {scan_id} with python={sys.executable}", flush=True)
    try:
        process = subprocess.Popen(
            [sys.executable, "-u", "main.py"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=proc_env,
            text=True,
            bufsize=1,
        )
    except Exception as exc:
        print(f"[worker] failed to spawn main.py: {exc}", flush=True)
        r.publish(f"scan:{scan_id}:output", f"[ERROR] Could not start scan process: {exc}\n")
        r.publish(f"scan:{scan_id}:output", "__DONE__")
        r.set(f"scan:{scan_id}:status", "done", ex=7200)
        return

    # Store owner so /api/approve can verify the caller owns this scan
    r.set(f"scan:{scan_id}:owner", user_id, ex=7200)
    r.set(f"scan:{scan_id}:status", "running", ex=7200)

    for line in iter(process.stdout.readline, ""):
        if not line:
            continue

        print(line, end="", flush=True)
        r.xadd(f"scan:{scan_id}:stream", {"line": line}, maxlen=2000)

        if "[ACTION_REQUIRED] WAITING_FOR_APPROVAL" in line:
            r.set(f"scan:{scan_id}:status", "waiting_approval", ex=7200)

            # Block with zero CPU burn until /api/approve pushes a decision.
            # timeout=1800 → auto-abort if user never approves within 30 min.
            result = r_blocking.blpop(f"scan:{scan_id}:decision", timeout=1800)
            if result is None:
                process.terminate()
                r.set(f"scan:{scan_id}:status", "aborted", ex=7200)
                return

            _, decision = result
            if not decision.startswith("approve"):
                process.terminate()
                r.set(f"scan:{scan_id}:status", "aborted", ex=7200)
                return
            process.stdin.write(decision + "\n")
            process.stdin.flush()
            r.set(f"scan:{scan_id}:status", "running", ex=7200)

    process.wait()
    r.set(f"scan:{scan_id}:status", "done", ex=7200)

    # Bust cached metrics/history so dashboard shows fresh data after scan
    r.delete(f"cache:{user_id}:metrics", f"cache:{user_id}:history")
    r.delete("cache:status", "cache:compliance", "cache:breakdown")

    # Signal stream consumers that output is finished; expire stream after 2 hours
    r.xadd(f"scan:{scan_id}:stream", {"line": "__DONE__"})
    r.expire(f"scan:{scan_id}:stream", 7200)
