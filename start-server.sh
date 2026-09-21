#!/bin/sh
set -eu
cd "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
if [ ! -x .venv/bin/python ]; then
    echo 'Install dependencies first: see README.md (Linux / macOS).'
    exit 1
fi
exec .venv/bin/python -m src.pairing "$@"
