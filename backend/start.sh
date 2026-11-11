#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"
python manage.py migrate --noinput

exec gunicorn cybershield_ai.wsgi:application --bind "0.0.0.0:${PORT:-10000}"
