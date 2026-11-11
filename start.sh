#!/usr/bin/env bash
set -euo pipefail

# Render starts from the repository root. Apply safe, idempotent Django
# migrations before serving requests, including the new GmailConnection table.
cd "$(dirname "$0")/backend"
python manage.py migrate --noinput

exec gunicorn cybershield_ai.wsgi:application --bind "0.0.0.0:${PORT:-10000}"
