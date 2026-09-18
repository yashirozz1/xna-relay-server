#!/usr/bin/env bash
# Run from the generated relay/ OR client/ directory. No firewall or SSH changes.
set -euo pipefail
cd -- "$(dirname -- "$(readlink -f -- "$0")")"
fail() { printf '%s\n' "$*" >&2; exit 1; }
[[ $EUID -eq 0 ]] || fail 'Execute com sudo bash install.sh.'
source /etc/os-release
[[ ${ID:-} == ubuntu && ${VERSION_ID:-} == 24.04 ]] || fail 'Alvo suportado: Ubuntu 24.04 LTS.'
[[ -d /run/systemd/system ]] || fail 'Este instalador precisa de systemd ativo.'

if [[ -f haproxy.cfg && -f prl-relay.service && ! -f stunnel.conf ]]; then
    service=prl-relay
    config=haproxy.cfg
    packages=(haproxy ca-certificates)
elif [[ -f stunnel.conf && -f prl-client.service && ! -f haproxy.cfg ]]; then
    service=prl-client
    config=stunnel.conf
    packages=(stunnel4 ca-certificates)
else
    fail 'Pasta invalida: use relay/ ou client/ do pacote gerado.'
fi

target="/etc/$service"
unit="/etc/systemd/system/$service.service"
[[ ! -e $target && ! -L $target && ! -e $unit && ! -L $unit ]] || fail 'Instalacao existente: revise e remova explicitamente antes de reinstalar.'
[[ $(systemctl show "$service.service" -p LoadState --value) == not-found ]] || fail 'Ja existe uma unidade com esse nome.'

if [[ $service == prl-relay ]]; then
    port=$(awk '/^[[:space:]]*bind / { sub(/^.*:/,"",$2); print $2 }' "$config")
else
    port=$(awk '/^accept = / { sub(/^.*:/,"",$3); print $3 }' "$config")
fi
[[ $port =~ ^[0-9]+$ && $port -ge 1024 && $port -le 65535 ]] || fail 'Porta invalida no pacote.'
[[ -z $(ss -H -ltn "sport = :$port") ]] || fail "Porta $port ja esta ocupada."

# Prevent distro post-install hooks from starting default units. Runtime masks
# created here are removed at exit; pre-existing masks are never changed.
masked=()
created=0
success=0
cleanup() {
    code=$?
    trap - EXIT
    if (( ! success && created )); then
        systemctl disable --now "$service.service" >/dev/null 2>&1 || true
        rm -f -- "$unit" "$target/$config"
        rmdir -- "$target" 2>/dev/null || true
        systemctl daemon-reload || true
    fi
    for stock in "${masked[@]}"; do
        systemctl unmask --runtime "$stock" >/dev/null || true
    done
    exit "$code"
}
trap cleanup EXIT
if [[ $service == prl-relay ]]; then
    stocks=(haproxy.service)
else
    # Ubuntu 24.04 has a native target and a legacy SysV service. Guard both.
    stocks=(stunnel.target stunnel4.service)
fi
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
if [[ $service == prl-relay ]]; then
    /usr/sbin/haproxy -c -f "$PWD/$config"
fi

install -d -m 755 "$target"
created=1
install -m 644 "$config" "$target/$config"
install -m 644 "$service.service" "$unit"
systemctl daemon-reload
systemctl enable --now "$service.service"
sleep 1
systemctl is-active --quiet "$service.service" || fail 'Servico falhou; consulte journalctl.'
success=1
printf 'Instalado: %s. SSH, rotas e firewall nao foram alterados.\n' "$service"
printf 'Servico ativo nao confirma conectividade com a pool. Execute check_tls.py e o teste do cliente.\n'
