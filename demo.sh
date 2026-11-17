#!/bin/sh
# Thirty-second offline demo. No install, no network.
set -eu
cd "$(dirname "$0")"
PYTHONPATH="${PYTHONPATH:-}:$(pwd)/src"
export PYTHONPATH
exec python3 -m cordon demo
