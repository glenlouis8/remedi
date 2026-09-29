"""Record one real demo-mode scan as a replayable JSON file.

Mirrors what worker.py does: spawns main.py with stderr merged into stdout, reads
it line by line, and writes "approve" to stdin at the approval gate. Instead of
pushing lines to a Redis stream it saves them with timestamps, split at the gate,
so the frontend can replay the run with no backend.

    DATABASE_URL=postgresql://localhost/remedi_demo GOOGLE_API_KEY=... \\
        python scripts/record_demo.py

Uses real Gemini calls (about $0.02) and a local Postgres; the AWS side is the
fake account in mcp_server/demo_fixtures.py, so no AWS credentials are involved.
"""
import argparse
import datetime
import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent.parent
GATE_LINE = "[ACTION_REQUIRED] WAITING_FOR_APPROVAL"
SCAN_ID = "SCAN-DEMO0001"
TIME_LIMIT_S = 600


def _require_local_db() -> str:
    url = os.environ.get("DATABASE_URL", "")
    host = urlparse(url).hostname
    if host not in ("localhost", "127.0.0.1", "::1"):
        sys.exit(
            "refusing to record: DATABASE_URL must be set in the environment and point at a "
            "local Postgres (a scan writes rows). Got: " + (host or "nothing")
        )
    return url


def record() -> dict:
    env = os.environ.copy()
    env.update({
        "DATABASE_URL": _require_local_db(),
        "REMEDI_DEMO": "1",
        "REMEDI_SCAN_ID": SCAN_ID,
        "REMEDI_USER_ID": "demo-user",
        "AWS_ACCESS_KEY_ID": "demo",
        "AWS_SECRET_ACCESS_KEY": "demo",
        "PYTHONUNBUFFERED": "1",
    })
    proc = subprocess.Popen(
        [sys.executable, "-u", "main.py"],
        cwd=ROOT, env=env, text=True, bufsize=1,
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    timer = threading.Timer(TIME_LIMIT_S, proc.kill)
    timer.start()

    pre_gate, post_gate = [], []
    target = pre_gate
    t0 = time.perf_counter()
    gate_seen = 0
    try:
        for raw in iter(proc.stdout.readline, ""):
            line = raw.rstrip("\n")
            if not line.strip():
                continue  # the frontend drops blank lines anyway
            target.append({"t_ms": round((time.perf_counter() - t0) * 1000), "line": line})
            print(line, flush=True)
            if GATE_LINE in line:
                gate_seen += 1
                # The visitor's click is the approval on replay, so time restarts here.
                proc.stdin.write("approve\n")
                proc.stdin.flush()
                target = post_gate
                t0 = time.perf_counter()
        code = proc.wait()
    finally:
        timer.cancel()
        if proc.poll() is None:
            proc.kill()

    return {
        "version": 1,
        "recorded_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "scan_id": SCAN_ID,
        "exit_code": code,
        "gate_count": gate_seen,
        "pre_gate": pre_gate,
        "post_gate": post_gate,
    }


def validate(rec: dict) -> list[str]:
    """Reasons this recording is not worth keeping (empty list = good)."""
    problems = []
    pre = [e["line"] for e in rec["pre_gate"]]
    post = [e["line"] for e in rec["post_gate"]]
    lines = pre + post
    if rec["exit_code"] != 0:
        problems.append(f"main.py exited {rec['exit_code']}")
    if rec["gate_count"] != 1:
        problems.append(f"expected exactly 1 approval gate, saw {rec['gate_count']}")
    if not any(l.startswith("[SCAN] ") for l in pre):
        problems.append("no [SCAN] events before the gate")
    if not any("[EXEC] Calling" in l for l in post):
        problems.append("no [EXEC] lines after the gate")
    if not any("MISSION ACCOMPLISHED" in l for l in post):
        problems.append("verifier did not report MISSION ACCOMPLISHED")
    if any(l.startswith("❌") or "[ERROR]" in l or "Traceback" in l for l in lines):
        problems.append("run contains an error line")
    return problems


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(ROOT / "frontend" / "public" / "demo_run.json"))
    args = ap.parse_args()

    rec = record()
    problems = validate(rec)
    if problems:
        sys.exit("\nnot saving, bad recording:\n  - " + "\n  - ".join(problems))

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(rec, ensure_ascii=False, indent=1) + "\n")
    print(
        f"\nsaved {out} ({out.stat().st_size // 1024} KB): "
        f"{len(rec['pre_gate'])} lines before the gate, {len(rec['post_gate'])} after",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
