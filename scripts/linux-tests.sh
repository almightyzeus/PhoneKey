#!/usr/bin/env bash
# Runs the Linux verifier and protocol tests (stdlib unittest; no extra dependencies).
set -euo pipefail
cd "$(dirname "$0")/.."
PYTHONPATH="linux/daemon${PYTHONPATH:+:$PYTHONPATH}" exec python3 -m unittest discover -s tests -t . "$@"
