#!/usr/bin/env python3
"""Validate shell and systemd files without installing or starting services."""
from pathlib import Path
import subprocess
import tempfile
import sys

from integration import ROOT, binary


def main():
    for source in [ROOT / 'install.sh', ROOT / 'bootstrap.sh', *sorted((ROOT / 'scripts').glob('*.sh')),
                   *sorted((ROOT / 'fleet').glob('*.sh'))]:
        subprocess.run(['bash', '-n', str(source)], check=True)
    substitutions = {
        '/usr/sbin/haproxy': binary('haproxy', 'usr/sbin/haproxy'),
        '/usr/bin/stunnel4': binary('stunnel4', 'usr/bin/stunnel4'),
        '/opt/prl-monitor/venv/bin/uvicorn': str(Path(sys.executable).parent / 'uvicorn'),
    }
    with tempfile.TemporaryDirectory(prefix='prl-unit-check-') as temporary:
        units = []
        for source in [*sorted((ROOT / 'templates').glob('*.service')),
                       *sorted((ROOT / 'fleet/templates').glob('*.service'))]:
            text = source.read_text()
            for installed, actual in substitutions.items():
                text = text.replace(installed, actual)
            target = Path(temporary) / source.name
            target.write_text(text)
            target.chmod(0o644)
            units.append(str(target))
        subprocess.run(['systemd-analyze', 'verify', *units], check=True)
    print('OK: bash -n e systemd-analyze verify (executaveis locais; sem instalar servicos).')


if __name__ == '__main__':
    main()
