#!/usr/bin/env bash
set -e

echo "[start] launching celery worker"
python -m celery -A worker worker --loglevel=info --concurrency=1 &
CELERY_PID=$!

echo "[start] celery pid=$CELERY_PID"
echo "[start] launching uvicorn"

python -m uvicorn server:app --host 0.0.0.0 --port "${PORT:-8080}"

wait $CELERY_PID
