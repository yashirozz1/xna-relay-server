#!/usr/bin/env bash
# Repository entry point. Opening the menu never installs anything by itself.
set -euo pipefail
project_dir="$(cd -- "$(dirname -- "$0")" && pwd)"
command -v python3 >/dev/null || { printf 'Instale Python 3.10+ para abrir o menu.\n' >&2; exit 1; }
exec python3 "$project_dir/fleet/menu.py" "$@"
