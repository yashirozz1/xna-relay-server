#!/usr/bin/env python3
"""Forced SSH command: only register one mining VM, never provide a shell."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def request_for_claim(body, account, reserve_cpu_percent):
    if not isinstance(body, dict) or set(body) != {'claim'}:
        raise ValueError('only a per-VM enrollment claim is accepted')
    claim = body['claim']
    if not isinstance(claim, str) or not re.fullmatch('[a-f0-9]{64}', claim):
        raise ValueError('invalid enrollment claim')
    spec = {'account': account, 'reserve_cpu_percent': reserve_cpu_percent}
    return dict(action='prepare', operation_id=hashlib.sha256(
        ('xna-mining-enrollment-v1:' + claim).encode()).hexdigest(),
        spec_hash=hashlib.sha256(json.dumps(spec, sort_keys=True).encode()).hexdigest(), **spec)


def main():
    from fleet.azure_provision import Provisioner
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base-dir', type=Path, required=True)
    parser.add_argument('--account', required=True)
    parser.add_argument('--reserve-cpu-percent', type=int, default=10)
    args = parser.parse_args()
    try:
        raw = sys.stdin.buffer.read(4097)
        if len(raw) > 4096:
            raise ValueError('request too large')
        request = request_for_claim(json.loads(raw), args.account, args.reserve_cpu_percent)
        response = Provisioner(args.base_dir).handle(request)
        print(json.dumps(response))
        return 0
    except Exception as error:
        # Never print raw input, claims, PEMs or a provisioning response.
        print('Enrollment failed: ' + str(error)[:800], file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
