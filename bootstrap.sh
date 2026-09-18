#!/usr/bin/env bash
# Download the public source and open the menu. Does not install system services.
set -euo pipefail

main() {
    local destination=${XNA_INSTALL_DIR:-${HOME:?HOME is required}/.local/share/xna-relay}
    local launch=1 argument tmpdir
    local -a menu_args=()
    for argument in "$@"; do
        case "$argument" in
            --no-launch) launch=0 ;;
            --no-animation|--no-color|--status) menu_args+=("$argument") ;;
            --help|-h)
                printf '%s\n' 'XNA Relay — instalador Linux' \
                    'Uso: bash bootstrap.sh [--no-launch] [--no-color] [--no-animation] [--status]' \
                    'XNA_INSTALL_DIR: pasta nova para o codigo (padrao: ~/.local/share/xna-relay).' \
                    'Baixa o projeto e abre o menu. Servicos sao instalados pelo menu do pacote.'
                return 0 ;;
            *) printf 'Opcao desconhecida: %s\n' "$argument" >&2; return 2 ;;
        esac
    done
    [[ $(uname -s) == Linux ]] || { printf 'Execute este instalador no Linux.\n' >&2; return 1; }
    local dependency
    for dependency in python3 openssl tar; do
        command -v "$dependency" >/dev/null || {
            printf 'Dependencia ausente: %s\nUse: sudo apt-get update && sudo apt-get install -y python3 openssl curl tar\n' "$dependency" >&2
            return 1
        }
    done
    python3 -c 'import sys; sys.exit(sys.version_info < (3, 10))' || {
        printf 'Python 3.10+ necessario. Alvo recomendado: Ubuntu 24.04.\n' >&2; return 1;
    }
    if [[ -e "$destination" || -L "$destination" ]]; then
        printf 'A pasta ja existe; nenhum arquivo foi alterado.\n' >&2
        if [[ -f "$destination/install.sh" && -f "$destination/fleet/menu.py" ]]; then
            printf 'Abra o menu existente: bash %q\n' "$destination/install.sh" >&2
        else
            printf 'Use XNA_INSTALL_DIR com uma pasta nova para concluir o download.\n' >&2
        fi
        return 1
    fi
    umask 077
    tmpdir=$(mktemp -d -t xna-relay-download.XXXXXXXX)
    # The trap owns only the unique directory just allocated by mktemp.
    trap 'rm -rf -- "$tmpdir"' EXIT
    printf '\n    XNA RELAY SERVER\n    Baixando o projeto pelo GitHub...\n\n'
    local archive_url=https://codeload.github.com/yashirozz1/xna-relay-server/tar.gz/refs/heads/main
    if command -v curl >/dev/null; then
        curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
            --connect-timeout 15 --max-time 180 --retry 2 \
            "$archive_url" --output "$tmpdir/source.tar.gz"
    elif command -v wget >/dev/null; then
        wget --https-only --timeout=30 --tries=3 --quiet \
            --output-document="$tmpdir/source.tar.gz" "$archive_url"
    else
        printf 'Instale curl ou wget para continuar.\n' >&2
        exit 1
    fi
    mkdir -- "$tmpdir/source"
    tar -xzf "$tmpdir/source.tar.gz" --strip-components=1 --no-same-owner -C "$tmpdir/source"
    for dependency in install.sh fleet/menu.py fleet_bundle.py; do
        [[ -f "$tmpdir/source/$dependency" && ! -L "$tmpdir/source/$dependency" ]] || {
            printf 'Download incompleto: %s ausente.\n' "$dependency" >&2; exit 1;
        }
    done
    mkdir -p -- "$(dirname -- "$destination")"
    # mkdir reserves a new destination, including when two bootstraps run together.
    mkdir -- "$destination"
    if ! cp -R -- "$tmpdir/source/." "$destination/"; then
        printf 'Falha na copia. Pasta parcial preservada: %s\n' "$destination" >&2
        printf 'Corrija o erro e repita com XNA_INSTALL_DIR apontando para uma pasta nova.\n' >&2
        exit 1
    fi
    printf '    Projeto instalado em: %s\n    Para reabrir: bash ' "$destination"
    printf '%q\n\n' "$destination/install.sh"
    rm -rf -- "$tmpdir"
    trap - EXIT
    if ((launch)); then
        # curl | bash consumes stdin; reconnect the menu to the actual terminal.
        if [[ -t 1 && -r /dev/tty ]]; then
            exec bash "$destination/install.sh" "${menu_args[@]}" </dev/tty
        fi
        exec bash "$destination/install.sh" "${menu_args[@]}"
    fi
}

main "$@"
