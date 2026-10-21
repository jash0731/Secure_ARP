#!/usr/bin/env sh
cd "$(dirname "$0")" || exit 1
if [ -x .venv/bin/python ]; then
    exec .venv/bin/python -m secure_arp --demo
fi
exec python3 -m secure_arp --demo
