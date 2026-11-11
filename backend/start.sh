#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"
python manage.py migrate --noinput

# This opt-in account bootstrap is intended only for the isolated preview
# service. It does nothing unless all preview-specific variables are set.
if [[ "${PREVIEW_DEMO_USER_ENABLED:-false}" == "true" ]]; then
    python manage.py create_preview_demo_user
fi

exec gunicorn cybershield_ai.wsgi:application --bind "0.0.0.0:${PORT:-10000}"
