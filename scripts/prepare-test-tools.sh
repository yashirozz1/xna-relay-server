#!/usr/bin/env bash
# Download verified distro packages and extract locally. No apt install/services.
set -euo pipefail
cd -- "$(dirname -- "$(readlink -f -- "$0")")/.."
source /etc/os-release
if [[ ${ID:-} != ubuntu || ${VERSION_ID:-} != 24.04 || $(dpkg --print-architecture) != amd64 ]]; then
    printf 'Este bootstrap local foi preparado para Ubuntu 24.04 amd64.\n' >&2
    exit 1
fi
mkdir -p .tools/debs .tools/root
cd .tools/debs
apt-get download haproxy stunnel4 libwrap0 liblua5.4-0
for package in *.deb; do
    dpkg-deb -x "$package" ../root
done
printf 'Componentes extraidos em .tools/root. Nenhum servico instalado ou iniciado.\n'
