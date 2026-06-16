import os
import subprocess
import redis
from celery import Celery
from dotenv import load_dotenv

load_dotenv()

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")

celery_app = Celery("remedi", broker=REDIS_URL)
r = redis.Redis.from_url(REDIS_URL, decode_responses=True)
# Separate connection for blpop — no socket timeout so it can block up to 1800s
r_blocking = redis.Redis.from_url(REDIS_URL, decode_responses=True, socket_timeout=None)


@celery_app.task(bind=True)
def run_scan_task(self, scan_id: str, user_id: str, env: dict):
    proc_env = os.environ.copy()
    proc_env.update(env)
    proc_env["PYTHONUNBUFFERED"] = "1"
    proc_env["REMEDI_SCAN_ID"] = scan_id

    process = subprocess.Popen(
        ["python", "-u", "main.py"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env=proc_env,
        text=True,
        bufsize=1,
    )

    # Store owner so /api/approve can verify the caller owns this scan
    r.set(f"scan:{scan_id}:owner", user_id, ex=7200)
    r.set(f"scan:{scan_id}:status", "running", ex=7200)

    for line in iter(process.stdout.readline, ""):
        if not line:
            continue

        print(line, end="", flush=True)
        r.publish(f"scan:{scan_id}:output", line)

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
            process.stdin.write(decision + "\n")
            process.stdin.flush()
            r.set(f"scan:{scan_id}:status", "running", ex=7200)

    process.wait()
    r.set(f"scan:{scan_id}:status", "done", ex=7200)

    # Bust cached metrics/history so dashboard shows fresh data after scan
    r.delete(f"cache:{user_id}:metrics", f"cache:{user_id}:history")
    r.delete("cache:status", "cache:compliance", "cache:breakdown")

    # Signal stream consumers that output is finished
    r.publish(f"scan:{scan_id}:output", "__DONE__")
