#!/usr/bin/env bash
set -euo pipefail
exec bash "$(dirname "$0")/backend/start.sh"
