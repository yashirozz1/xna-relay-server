#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "$(readlink -f -- "$0")")"
if [[ ${1:-} == --non-interactive && $# -eq 1 ]]; then
    exec bash ./install-common.sh relay
fi
exec python3 ./menu.py --role relay "$@"
