#!/usr/bin/env bash
set -euo pipefail

python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .

if ! command -v suricata >/dev/null 2>&1; then
  echo "Suricata is not installed or is not on PATH." >&2
  echo "Install Suricata with your operating system's package manager." >&2
  exit 1
fi

echo "Setup complete. Run: atlas-suricata-lab"
