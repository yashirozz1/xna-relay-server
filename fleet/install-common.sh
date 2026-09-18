#!/usr/bin/env bash
# Sourced by the generated installer. Fixed targets; never changes SSH/firewall.
set -euo pipefail
umask 077
fail() { printf '%s\n' "$*" >&2; exit 1; }
[[ $EUID -eq 0 ]] || fail 'Execute com sudo bash install.sh.'
source /etc/os-release
[[ ${ID:-} == ubuntu && ${VERSION_ID:-} == 24.04 ]] || fail 'Alvo suportado: Ubuntu 24.04 LTS.'
[[ -d /run/systemd/system ]] || fail 'Este instalador precisa de systemd ativo.'
role=${1:-}
if [[ $role == relay ]]; then
    services=(prl-fleet prl-monitor)
    accounts=(prl-fleet prl-monitor)
    groups=(prl-fleet prl-monitor prl-metrics)
    targets=(/etc/prl-fleet /etc/prl-monitor /opt/prl-monitor /var/lib/prl-monitor)
    stocks=(haproxy.service)
    packages=(haproxy ca-certificates openssl python3-venv)
    required=(haproxy.cfg server.pem ca.crt crl.pem registry.json api-token requirements-monitor.txt monitor/app.py)
    mapfile -t ports < <(awk '/^[[:space:]]*bind / { sub(/^.*:/,"",$2); print $2 }' haproxy.cfg)
    ports+=(18080)
elif [[ $role == client ]]; then
    services=(prl-fleet-client)
    accounts=(prl-fleet-client)
    groups=(prl-fleet-client)
    targets=(/etc/prl-fleet-client)
    stocks=(stunnel.target stunnel4.service)
    packages=(stunnel4 ca-certificates openssl)
    required=(stunnel.conf client.pem ca.crt)
    mapfile -t ports < <(awk '/^accept = / { sub(/^.*:/,"",$3); print $3 }' stunnel.conf)
else
    fail 'Tipo de pacote invalido.'
fi
for file in "${required[@]}"; do
    [[ -f $file && ! -L $file ]] || fail "Arquivo ausente ou link: $file"
done
for target in "${targets[@]}"; do
    [[ ! -e $target && ! -L $target ]] || fail "Destino ja existe: $target. Instalacao preservada."
done
for service in "${services[@]}"; do
    [[ -f $service.service ]] || fail "Unidade ausente: $service.service"
    [[ ! -e /etc/systemd/system/$service.service && ! -L /etc/systemd/system/$service.service ]] || fail "Unidade existente: $service"
    [[ $(systemctl show "$service.service" -p LoadState --value) == not-found ]] || fail "Unidade existente: $service"
done
for account in "${accounts[@]}"; do
    ! getent passwd "$account" >/dev/null || fail "Conta ja existe: $account. Revise a instalacao anterior."
done
for group in "${groups[@]}"; do
    ! getent group "$group" >/dev/null || fail "Grupo ja existe: $group. Revise a instalacao anterior."
done
[[ ${#ports[@]} -ge 2 ]] || fail 'Portas ausentes no pacote.'
for port in "${ports[@]}"; do
    [[ $port =~ ^[0-9]+$ && $port -ge 1024 && $port -le 65535 ]] || fail 'Porta invalida no pacote.'
    [[ -z $(ss -H -ltn "sport = :$port") ]] || fail "Porta $port ja esta ocupada."
done

masked=() created_dirs=() created_units=() created_users=() created_groups=()
success=0
cleanup() {
    code=$?
    trap - EXIT
    set +e
    if (( ! success )); then
        for service in "${created_units[@]}"; do
            systemctl disable --now "$service.service" >/dev/null 2>&1
            rm -f -- "/etc/systemd/system/$service.service"
        done
        for target in "${created_dirs[@]}"; do rm -rf -- "$target"; done
        for account in "${created_users[@]}"; do userdel "$account"; done
        for group in "${created_groups[@]}"; do groupdel "$group"; done
        systemctl daemon-reload
    fi
    for stock in "${masked[@]}"; do systemctl unmask --runtime "$stock" >/dev/null; done
    exit "$code"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
for stock in "${stocks[@]}"; do
    if ! systemctl is-active --quiet "$stock"; then
        state=$(systemctl is-enabled "$stock" 2>/dev/null || true)
        if [[ $state != masked && $state != masked-runtime ]]; then
            systemctl mask --runtime "$stock"
            masked+=("$stock")
        fi
    fi
done
apt-get update
apt-get install -y --no-install-recommends "${packages[@]}"
for group in "${groups[@]}"; do
    groupadd --system "$group"
    created_groups+=("$group")
done
for account in "${accounts[@]}"; do
    useradd --system --gid "$account" --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin "$account"
    created_users+=("$account")
done
for target in "${targets[@]}"; do
    mkdir -- "$target"
    created_dirs+=("$target")
done

if [[ $role == relay ]]; then
    chmod 0750 /etc/prl-fleet /etc/prl-monitor
    chown root:prl-fleet /etc/prl-fleet
    chown root:prl-monitor /etc/prl-monitor
    install -o root -g prl-fleet -m 0640 haproxy.cfg server.pem ca.crt crl.pem /etc/prl-fleet/
    install -o root -g prl-monitor -m 0640 registry.json api-token /etc/prl-monitor/
    chmod 0755 /opt/prl-monitor
    install -d -m 0755 /opt/prl-monitor/monitor
    install -m 0644 monitor/*.py /opt/prl-monitor/monitor/
    install -m 0644 requirements-monitor.txt /opt/prl-monitor/
    # The venv is executable by the unprivileged service, but writable only by root.
    (umask 022; python3 -m venv /opt/prl-monitor/venv
     /opt/prl-monitor/venv/bin/pip install --disable-pip-version-check --requirement /opt/prl-monitor/requirements-monitor.txt)
    chown prl-monitor:prl-monitor /var/lib/prl-monitor
    chmod 0700 /var/lib/prl-monitor
    openssl verify -CAfile ca.crt -purpose sslserver server.pem
    openssl crl -in crl.pem -CAfile ca.crt -noout -verify
    runuser -u prl-fleet -- /usr/sbin/haproxy -c -f /etc/prl-fleet/haproxy.cfg
    (cd /opt/prl-monitor; runuser -u prl-monitor -- /opt/prl-monitor/venv/bin/python -c \
        'from pathlib import Path; from monitor.config import load_registry; from monitor.app import _read_token; load_registry(Path("/etc/prl-monitor/registry.json")); _read_token(Path("/etc/prl-monitor/api-token"))')
else
    chmod 0750 /etc/prl-fleet-client
    chown root:prl-fleet-client /etc/prl-fleet-client
    install -o root -g prl-fleet-client -m 0640 stunnel.conf client.pem ca.crt /etc/prl-fleet-client/
    openssl verify -CAfile ca.crt -purpose sslclient client.pem
fi
for service in "${services[@]}"; do
    created_units+=("$service")
    install -m 0644 "$service.service" "/etc/systemd/system/$service.service"
done
systemctl daemon-reload
for service in "${services[@]}"; do systemctl enable --now "$service.service"; done
sleep 2
for service in "${services[@]}"; do
    systemctl is-active --quiet "$service.service" || fail "Servico falhou: $service; consulte journalctl."
done
if [[ $role == relay ]]; then
    # Health must prove the sampler can read the real stats socket as its service user.
    /opt/prl-monitor/venv/bin/python - <<'PY'
import json, time, urllib.error, urllib.request
from pathlib import Path
token = Path('/etc/prl-monitor/api-token').read_text().strip()
request = urllib.request.Request('http://127.0.0.1:18080/v1/health', headers={'Authorization': 'Bearer ' + token})
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
for attempt in range(20):
    try:
        with opener.open(request, timeout=2) as response:
            if json.load(response)['status'] == 'ok':
                break
    except (OSError, ValueError):
        pass
    time.sleep(1)
else:
    raise SystemExit('Monitor sem coleta valida; consulte journalctl -u prl-monitor.')
PY
fi
success=1
printf 'Instalado (%s). SSH, rotas e firewall preservados.\n' "$role"
printf 'Valide conectividade e certificados antes de usar o relay; consulte README.md.\n'
