#!/usr/bin/env bash
# Run the Celery worker and the uvicorn API together in one dyno, supervised.
# - forward SIGTERM/SIGINT to both children so a deploy drains cleanly instead
#   of letting Render SIGKILL in-flight scans
# - if EITHER child exits, stop the other and exit non-zero so Render restarts
#   the whole dyno, rather than serving a half-dead app (healthy HTTP, no worker)
set -uo pipefail

PORT="${PORT:-8080}"

echo "[start] launching celery worker"
python -m celery -A worker worker --loglevel=info --concurrency=1 &
CELERY_PID=$!

echo "[start] launching uvicorn on :${PORT}"
python -m uvicorn server:app --host 0.0.0.0 --port "${PORT}" &
UVICORN_PID=$!

echo "[start] celery=${CELERY_PID} uvicorn=${UVICORN_PID}"

shutdown() {
  echo "[start] signal received — forwarding TERM to children"
  kill -TERM "$CELERY_PID" "$UVICORN_PID" 2>/dev/null || true
  wait "$CELERY_PID" "$UVICORN_PID" 2>/dev/null || true
  exit 0
}
trap shutdown SIGTERM SIGINT

# Poll rather than `wait -n` (needs bash >= 4.3). `sleep` is interruptible, so a
# trapped SIGTERM still fires promptly.
while kill -0 "$CELERY_PID" 2>/dev/null && kill -0 "$UVICORN_PID" 2>/dev/null; do
  sleep 2
done

echo "[start] a child exited — tearing down the other"
kill -TERM "$CELERY_PID" "$UVICORN_PID" 2>/dev/null || true
wait "$CELERY_PID" "$UVICORN_PID" 2>/dev/null || true
exit 1
