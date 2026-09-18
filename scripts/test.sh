#!/usr/bin/env bash
# Local Linux harness. Does not install packages or contact the pool.
set -euo pipefail
cd -- "$(dirname -- "$(readlink -f -- "$0")")/.."
python=${PRL_TEST_PYTHON:-python3}
if [[ -z ${PRL_TEST_PYTHON:-} && -x .tools/monitor-venv/bin/python ]]; then
    python="$PWD/.tools/monitor-venv/bin/python"
fi
"$python" -m unittest discover -s tests -p 'test_*.py' -v
"$python" tests/integration.py
"$python" tests/integration_fleet.py
"$python" tests/validate_linux.py
