#!/usr/bin/env python3
"""XNA Relay interactive installer. Standard library only; safe on redirected input."""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime
import getpass
import os
from pathlib import Path
import shutil
import subprocess
import sys
import threading
import time


SOURCE_ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = 'https://github.com/yashirozz1/xna-relay-server'
REQUIRED = {
    'relay': ('install-common.sh', 'haproxy.cfg', 'server.pem', 'ca.crt', 'crl.pem',
              'registry.json', 'api-token', 'prl-fleet.service', 'prl-monitor.service'),
    'client': ('install-common.sh', 'stunnel.conf', 'client.pem', 'ca.crt', 'prl-fleet-client.service'),
}


class Terminal:
    COLORS = {'cyan': '\033[96m', 'green': '\033[92m', 'muted': '\033[90m',
              'white': '\033[97;1m', 'yellow': '\033[93m'}

    def __init__(self, stream=None, *, interactive=None, animation=True, color=None):
        self.stream = stream or sys.stdout
        self.interactive = (sys.stdin.isatty() and self.stream.isatty()) if interactive is None else interactive
        capable = self.interactive and os.environ.get('TERM') != 'dumb'
        self.color = capable and ('NO_COLOR' not in os.environ) if color is None else color
        self.animation = animation and capable and self.color and not os.environ.get('XNA_NO_ANIMATION')
        self.status = ''

    def paint(self, value, color):
        return self.COLORS[color] + str(value) + '\033[0m' if self.color else str(value)

    def line(self, value='', color=None):
        print(self.paint(value, color) if color else value, file=self.stream, flush=True)

    def banner(self, role=None):
        if self.color:
            print('\033[2J\033[H', end='', file=self.stream)
        self.line()
        for line in ('    __  __  _   _    _', '    \\ \\/ / | \\ | |  / \\',
                     '     >  <  |  \\| | / _ \\', '    /_/\\_\\ |_|\\__|/_/ \\_\\'):
            self.line(line, 'cyan')
            if self.animation:
                time.sleep(.035)
        self.line('    XNA RELAY SERVER', 'white')
        self.line('    Transporte autenticado. Frota conectada.', 'muted')
        self.line('    ' + '-' * 50, 'muted')
        mode = {'relay': 'Relay + API / Contabo', 'client': 'Cliente / VM de origem'}.get(role, 'Central de instalacao')
        self.line('    ' + mode, 'cyan')
        self.line()

    def choice(self, key, title, description):
        self.line(f'    {self.paint(key, "cyan")}  {title}')
        self.line(f'       {description}', 'muted')
        self.line()

    def ask(self, label, default=None):
        suffix = f' [{default}]' if default is not None else ''
        return input(f'    {label}{suffix}: ').strip() or default or ''

    def confirm(self, label):
        return self.ask(label + ' [s/N]').lower() in ('s', 'sim', 'y', 'yes')

    @contextmanager
    def activity(self, label):
        self.status = label
        stopped = threading.Event()

        def animate():
            frames = ('   ', '.  ', '.. ', '...')
            index = 0
            while not stopped.wait(.12):
                print('\r\033[2K    ' + self.paint(frames[index % 4], 'cyan') + ' ' + self.status,
                      end='', file=self.stream, flush=True)
                index += 1

        worker = threading.Thread(target=animate, daemon=True) if self.animation else None
        if worker:
            worker.start()
        else:
            self.line('    ... ' + label)
        ok = False
        try:
            yield
            ok = True
        finally:
            stopped.set()
            if worker:
                worker.join()
                print('\r\033[2K', end='', file=self.stream)
            self.line('    ' + ('[OK] ' if ok else '[ERRO] ') + label, 'green' if ok else 'yellow')


def is_linux():
    return sys.platform.startswith('linux')


def is_root():
    return hasattr(os, 'geteuid') and os.geteuid() == 0


def prepare_fleet(relay_ip, count, pki, output, password, progress=None):
    """Create a new authority and complete bundles; never reuse or overwrite keys."""
    if not (SOURCE_ROOT / 'fleet_bundle.py').is_file():
        raise ValueError('Prepare a frota a partir do repositorio, na maquina de administracao.')
    if str(SOURCE_ROOT) not in sys.path:
        sys.path.insert(0, str(SOURCE_ROOT))
    from fleet_bundle import generate, validate_manifest
    from fleet.pki import init_pki, issue_client

    if type(count) is not int or not 1 <= count <= 1024:
        raise ValueError('Informe entre 1 e 1024 clientes.')
    if len(password) < 12 or '\n' in password or '\r' in password:
        raise ValueError('Use uma senha de pelo menos 12 caracteres, em uma linha.')
    pki, output = Path(pki).expanduser().resolve(), Path(output).expanduser().resolve()
    if pki.exists() or output.exists():
        raise ValueError('A pasta da CA e a pasta de saida precisam ser novas.')
    if pki == output or pki.is_relative_to(output) or output.is_relative_to(pki):
        raise ValueError('Mantenha a CA em uma pasta separada dos pacotes de implantacao.')
    manifest = validate_manifest({'relay_ip': relay_ip, 'instances': [
        {'id': f'gpu{i:04}', 'label': f'Minerador {i:04}'} for i in range(1, count + 1)]})
    init_pki(pki, password, relay_ip=manifest['relay_ip'])
    identities = [i['id'] for i in manifest['instances']] + ['monitor-panel']
    for index, identity in enumerate(identities, 1):
        if progress:
            progress(f'Certificados: {index}/{len(identities)}')
        issue_client(pki, identity, password)
    if progress:
        progress('Montando pacotes individuais...')
    return generate(manifest, pki, output)


def prepare_wizard(terminal, root):
    terminal.line('    PREPARAR UMA NOVA FROTA', 'white')
    terminal.line('    Execute na maquina de administracao; mantenha a CA privada nela.', 'muted')
    terminal.line('    Use a CLI documentada para ampliar uma frota existente.', 'muted')
    relay_ip = terminal.ask('IPv4 da Contabo')
    count = int(terminal.ask('Quantidade de clientes', '300'))
    stamp = datetime.now().strftime('%Y%m%d-%H%M%S')
    pki = Path(terminal.ask('Nova pasta privada da CA', str(Path.home() / '.xna-relay' / ('pki-' + stamp)))).expanduser()
    output = Path(terminal.ask('Nova pasta dos pacotes', str(root / 'build' / ('fleet-' + stamp)))).expanduser()
    terminal.line()
    terminal.line(f'    Relay: {relay_ip}:18443   |   API HTTPS: 18444')
    terminal.line(f'    Clientes: {count}   |   Limite global: 2048 conexoes')
    terminal.line(f'    CA privada: {pki}')
    terminal.line(f'    Pacotes:    {output}')
    if not terminal.confirm('Gerar esta frota'):
        terminal.line('    Preparacao cancelada.', 'muted')
        return
    password = getpass.getpass('    Senha da CA (minimo 12 caracteres): ')
    if password != getpass.getpass('    Repita a senha da CA: '):
        raise ValueError('As senhas nao conferem.')
    with terminal.activity('Preparando certificados e pacotes'):
        result = prepare_fleet(relay_ip, count, pki, output, password,
                               progress=lambda status: setattr(terminal, 'status', status))
    terminal.line()
    terminal.line(f'    Pacotes prontos: {result}', 'green')
    terminal.line('    relay/       -> Contabo')
    terminal.line('    clients/ID/  -> somente a VM daquele ID')
    terminal.line('    panel/       -> backend do painel')
    terminal.line('    Na maquina de destino: sudo bash install.sh', 'cyan')
    terminal.line('    Guarde a CA e a senha. A CRL precisa ser renovada antes de 30 dias.', 'muted')


def install_bundle(terminal, directory, role):
    directory = Path(directory).expanduser().resolve()
    if role not in REQUIRED:
        raise ValueError('Papel de instalacao invalido.')
    missing = [name for name in REQUIRED[role]
               if not (directory / name).is_file() or (directory / name).is_symlink()]
    if missing:
        raise ValueError('Pacote incompleto: ' + ', '.join(missing))
    terminal.line(f'    Pacote: {directory}', 'white')
    terminal.line('    Destino: Ubuntu 24.04 LTS com systemd')
    terminal.line('    Componentes: ' + ('HAProxy + API de metricas' if role == 'relay' else 'stunnel + TLS da pool'))
    terminal.line('    Instala dependencias e servicos. SSH e firewall permanecem como estao.', 'muted')
    terminal.line('    Instalacoes existentes nao serao sobrescritas.', 'muted')
    if not terminal.confirm('Instalar neste computador'):
        terminal.line('    Instalacao cancelada.', 'muted')
        return 0
    if not is_linux():
        raise ValueError('Instale o pacote na VM Ubuntu de destino.')
    command = ['bash', str(directory / 'install-common.sh'), role]
    if not is_root():
        if not shutil.which('sudo'):
            raise ValueError('Execute o menu com sudo na VM de destino.')
        command.insert(0, 'sudo')
    terminal.line('    Iniciando instalacao; o progresso sera exibido abaixo.', 'cyan')
    result = subprocess.run(command, cwd=directory)
    terminal.line('    Instalacao concluida.' if result.returncode == 0 else
                  f'    Instalacao falhou (codigo {result.returncode}). Consulte a saida acima.',
                  'green' if result.returncode == 0 else 'yellow')
    return result.returncode


def show_status(terminal, role=None):
    if not is_linux() or not shutil.which('systemctl'):
        terminal.line('    Status disponivel na VM Linux com systemd.', 'yellow')
        return
    services = ['prl-fleet', 'prl-monitor'] if role == 'relay' else ['prl-fleet-client'] if role == 'client' else [
        'prl-fleet', 'prl-monitor', 'prl-fleet-client']
    for service in services:
        result = subprocess.run(['systemctl', 'is-active', service], capture_output=True, text=True)
        status = result.stdout.strip() or 'indisponivel'
        terminal.line(f'    {service:<20} {status}', 'green' if status == 'active' else 'muted')
    terminal.line('    Servico ativo nao confirma conectividade com a pool.', 'muted')


def show_guide(terminal):
    terminal.line('    1. Prepare os pacotes na maquina de administracao.')
    terminal.line('    2. Transfira cada pasta via SCP para seu destinatario.')
    terminal.line('    3. Execute sudo bash install.sh no pacote de destino.')
    terminal.line('    4. Valide o relay e consulte a API pelo backend do painel.')
    terminal.line('    Minerador: stratum+tcp://127.0.0.1:17048', 'cyan')
    terminal.line('    API: HTTPS 18444, certificado monitor-panel e Bearer.', 'cyan')
    terminal.line('    Documentacao: ' + REPOSITORY + '/blob/main/docs/FLEET.md')


def run_menu(terminal, root, role=None):
    while True:
        terminal.banner(role)
        if role:
            terminal.choice('1', 'Instalar neste servidor', 'Revisar o pacote e iniciar a instalacao')
            terminal.choice('2', 'Status dos servicos', 'Consultar a instalacao nesta maquina')
            terminal.choice('3', 'Guia rapido', 'Portas, credenciais e proximos passos')
        else:
            terminal.choice('1', 'Preparar uma nova frota', 'IP, quantidade de clientes e certificados individuais')
            terminal.choice('2', 'Instalar relay + API', 'Selecionar o pacote relay/ para esta Contabo')
            terminal.choice('3', 'Instalar cliente', 'Selecionar o pacote clients/ID/ para esta VM')
            terminal.choice('4', 'Status dos servicos', 'Consultar relay, monitor e cliente locais')
            terminal.choice('5', 'Guia rapido', 'Entender o fluxo e abrir a documentacao')
        terminal.choice('0', 'Sair', 'Nenhuma alteracao adicional')
        choice = terminal.ask('Escolha')
        if choice == '0':
            terminal.line('    Ate a proxima.', 'muted')
            return 0
        try:
            if role and choice == '1':
                install_bundle(terminal, root, role)
            elif role and choice == '2' or not role and choice == '4':
                show_status(terminal, role)
            elif role and choice == '3' or not role and choice == '5':
                show_guide(terminal)
            elif not role and choice == '1':
                prepare_wizard(terminal, root)
            elif not role and choice in ('2', '3'):
                target = terminal.ask('Caminho da pasta do pacote')
                if target:
                    install_bundle(terminal, Path(target), 'relay' if choice == '2' else 'client')
            else:
                terminal.line('    Opcao invalida. Escolha um numero do menu.', 'yellow')
        except (ValueError, OSError, RuntimeError) as exc:
            terminal.line('    ' + str(exc), 'yellow')
        terminal.ask('Enter para voltar')


def main(argv=None):
    parser = argparse.ArgumentParser(description='XNA Relay: menu de preparacao e instalacao.')
    parser.add_argument('--role', choices=('relay', 'client'), help='papel do pacote gerado')
    parser.add_argument('--no-animation', action='store_true', help='desativar animacoes do terminal')
    parser.add_argument('--no-color', action='store_true', help='saida sem cores ou sequencias ANSI')
    parser.add_argument('--status', action='store_true', help='consultar servicos sem abrir o menu')
    args = parser.parse_args(argv)
    terminal = Terminal(animation=not args.no_animation, color=False if args.no_color else None)
    root = Path(__file__).resolve().parent if args.role else SOURCE_ROOT
    if args.status:
        show_status(terminal, args.role)
        return 0
    if not terminal.interactive:
        terminal.banner(args.role)
        terminal.line('    Abra em um terminal interativo para escolher uma opcao.')
        terminal.line('    Use --help para consultar as opcoes.')
        if args.role:
            terminal.line('    Automacao: sudo bash install.sh --non-interactive')
        return 0
    try:
        return run_menu(terminal, root, args.role)
    except (EOFError, KeyboardInterrupt):
        terminal.line('\n    Operacao interrompida. Arquivos ja gerados foram preservados.', 'yellow')
        return 130


if __name__ == '__main__':
    raise SystemExit(main())
