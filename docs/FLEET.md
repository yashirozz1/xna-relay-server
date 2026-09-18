# Relay Fleet na Contabo

O backend do painel consulta a API do relay por HTTPS, com certificado de cliente
`monitor-panel` e token Bearer. O monitor coleta os contadores do HAProxy a cada
15 segundos e mantém 72 horas de histórico em SQLite. O relay não envia webhooks.

```text
Cliente: minerador → stunnel TLS da pool → stunnel mTLS do relay
                                              ↓ TCP 18443
Contabo:                                HAProxy → pool TLS
                                           ↓ socket local (somente leitura)
Painel backend → HTTPS mTLS :18444 → API 127.0.0.1:18080 → SQLite
```

O TLS da pool continua sendo validado no cliente. O relay identifica cada
instância pelo certificado e registra bytes, conexões e erros por ID.
Esses bytes são do transporte TLS interno, não uma medição de banda faturável.

O túnel de mineração usa TLS sobre TCP, não navegação HTTP. Na rede da VM, as
conexões encaminhadas usam o endereço do relay. Isso não torna a mineração
indetectável: IP, porta, SNI do TLS externo, volume e horários continuam
observáveis. O administrador da VM também pode inspecionar processos. A Contabo
observa suas próprias conexões de saída para a pool. TLS protege conteúdo; não
garante anonimato nem ausência de classificação por análise de tráfego
([RFC 8446, E.3](https://www.rfc-editor.org/rfc/rfc8446.html#appendix-E.3)).

O cliente gerado falha quando o relay cai, sem fallback direto para a pool, como
verificado em integração. Isso vale para conexões enviadas ao endpoint local:
não controla fallbacks, dev-fee ou outros destinos internos de um minerador.

Capacidade medida para o cenário inicial de 300 mineradores: consulte
`docs/CAPACITY.md` no código-fonte. O teste é local; valide também na Contabo.

## Gerar os pacotes

No Linux, baixe o código e abra o menu diretamente:

```sh
curl -fsSL https://raw.githubusercontent.com/yashirozz1/xna-relay-server/main/bootstrap.sh | bash
```

O bootstrap precisa de Python 3.10+, OpenSSL, tar e curl ou wget. Instala o código
em `~/.local/share/xna-relay`, sem modificar serviços. Para reabrir, execute
`bash ~/.local/share/xna-relay/install.sh`. Os pacotes com certificados são
gerados em seguida, pelo assistente, e instalados nas respectivas VMs.

Para uma nova frota, abra `bash install.sh` na raiz do repositório e escolha
**Preparar uma nova frota**. O assistente solicita o IP da Contabo, a quantidade
de clientes, pastas novas para CA/pacotes e a senha da CA. Ele gera certificados
individuais e pacotes prontos para distribuição. Não instala nada ao abrir o menu.
Para trabalhar com uma PKI existente ou alterar pool/portas, use a CLI abaixo.

Use Python 3.10+ e OpenSSL. Para produção, mantenha a PKI em Linux, em diretório
privado fora do projeto. Os IPs abaixo são exemplos reservados; substitua pelos
reais. Execute na raiz do código-fonte:

```sh
umask 077
python3 -m fleet.pki init /secure/prl-pki --relay-ip 203.0.113.10
python3 -m fleet.pki issue /secure/prl-pki gpu001
python3 -m fleet.pki issue /secure/prl-pki gpu002
python3 -m fleet.pki issue /secure/prl-pki monitor-panel
python3 fleet_bundle.py --manifest examples/fleet.json \
  --pki-dir /secure/prl-pki --output build/contabo-fleet
```

A CLI solicita a senha da CA sem exibi-la. Ajuste os IDs do manifesto e emita um
certificado para cada um. `monitor-panel` é reservado ao painel. `allowed_ip`
opcional limita também o IP de saída de uma instância. Gere em uma pasta nova;
o gerador recusa sobrescrever uma saída existente.

O pacote contém segredos e deve ser distribuído por destinatário via SCP/SSH:

| Pasta | Destino | Conteúdo privado |
|---|---|---|
| `relay/` | VPS Contabo | chave do relay e token da API |
| `clients/ID/` | somente a VM desse ID | chave desse cliente |
| `panel/` | backend do painel | certificado/chave monitor-panel e token |

A CA privada nunca é incluída. Não coloque `panel/` no frontend, repositório ou
diretório público. Os modos de arquivo gerados no Windows não substituem ACLs;
os instaladores reaplicam permissões no Linux.

## Instalar

Alvo: Ubuntu 24.04 LTS com systemd, acesso administrativo por chave SSH e saída
para os repositórios Ubuntu/PyPI, DNS e pool. Na Contabo, copie apenas `relay/` e
execute dentro dela:

```sh
sudo bash install.sh
sudo systemctl status prl-fleet prl-monitor --no-pager
```

Na VM de cada cliente, copie sua pasta `clients/ID/` e execute:

```sh
sudo bash install.sh
sudo systemctl status prl-fleet-client --no-pager
```

O pacote também inclui um menu: escolha **Instalar neste servidor** e confirme
o resumo. Para automação sem menu, use `sudo bash install.sh --non-interactive`.
`--no-animation` desliga as animações e `--no-color` oferece saída simples.
Em entrada redirecionada, o menu apenas mostra instruções e não instala.

Configure o minerador para `stratum+tcp://127.0.0.1:17048`. As portas 17048 e 17443
ficam em loopback. O instalador recusa destinos, contas de serviço e portas já
ocupados, instala dependências, cria serviços sem root e verifica a coleta local
no relay. Uma falha remove somente os novos arquivos/contas; pacotes apt permanecem.
Não modifica firewall, SSH ou rotas. O instalador é para primeira instalação;
não substitui uma instalação existente.

Configure no firewall da VPS e/ou provedor:

- TCP 18443: origens dos clientes quando os IPs de saída forem conhecidos.
- TCP 18444: somente o IP de saída do backend do painel.
- SSH: preserve seu acesso administrativo atual.

Não publique 18080, 17048 ou 17443. Se alterar portas no manifesto, ajuste o
firewall correspondente. O acesso HTTPS exige o certificado `monitor-panel`;
certificados dos clientes não dão acesso à API.

## Consultar pelo backend do painel

O certificado do relay contém `relay.prl.internal`. Use esse nome com resolução
privada para o IP da Contabo, ou o IP se ele foi incluído no SAN durante `init`.
Um teste com curl, a partir da pasta `panel/`, sem mudar DNS:

```sh
curl --fail-with-body --noproxy '*' \
  --resolve relay.prl.internal:18444:203.0.113.10 \
  --cacert ca.crt --cert client.pem \
  --header @<(printf 'Authorization: Bearer %s\n' "$(cat api-token)") \
  https://relay.prl.internal:18444/v1/instances
```

Exemplo Python para o backend, usando a biblioteca padrão e um IP incluído no SAN:

```python
import json
import ssl
import urllib.request
from pathlib import Path

credentials = Path('/run/secrets/prl-panel')
tls = ssl.create_default_context(cafile=str(credentials / 'ca.crt'))
tls.load_cert_chain(str(credentials / 'client.pem'))
opener = urllib.request.build_opener(
    urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=tls))
request = urllib.request.Request(
    'https://203.0.113.10:18444/v1/instances',
    headers={'Authorization': 'Bearer ' + (credentials / 'api-token').read_text().strip()},
)
with opener.open(request, timeout=10) as response:
    data = json.load(response)
```

Consulte `/v1/instances` a cada 15–30 segundos para atualizar todos os clientes em
uma chamada. `/v1/instances/ID` detalha um cliente; `/v1/traffic` aceita
`instance_id`, `since` e `until` em segundos Unix UTC, e `limit` até 2000.
`/openapi.json` entrega o contrato autenticado. `/v1/health` retorna 503 quando a
coleta falha ou fica antiga; dados históricos continuam disponíveis com `stale`.
Campos de taxa nulos e `discontinuity: true` indicam que não há delta confiável.
Não trate ausência de tráfego como prova de máquina desligada.

O token é lido a cada chamada, permitindo rotação por substituição atômica de
`/etc/prl-monitor/api-token` (root:prl-monitor, modo 0640). Distribua o novo token
ao backend do painel. Há limite global efetivo de 120 chamadas/minuto no monitor,
pois as requisições remotas chegam pelo proxy local. Receber 429 exige reduzir
consultas; 401 indica token incorreto; 403 indica certificado sem permissão ou
método diferente de GET. Falhas TLS acontecem antes de uma resposta HTTP.

## Operação e certificados

```sh
sudo journalctl -u prl-fleet -u prl-monitor -n 100 --no-pager
sudo journalctl -u prl-fleet-client -n 100 --no-pager
```

Os serviços reiniciam após falha e iniciam no boot. A API usa um único worker.
O banco fica em `/var/lib/prl-monitor/metrics.sqlite3`; faça backup pela API de
backup SQLite, ou pare o monitor antes de copiar o banco e seus arquivos WAL.

A CRL expira após 30 dias. Renove-a antes do vencimento com a PKI offline
(`python3 -m fleet.pki refresh-crl /secure/prl-pki`), mesmo sem revogações. Para
revogar: `python3 -m fleet.pki revoke /secure/prl-pki gpu001`. Transfira apenas a
nova `crl.pem`, valide sua assinatura e substitua
`/etc/prl-fleet/crl.pem` como root:prl-fleet, modo 0640. Execute
`sudo /usr/sbin/haproxy -c -f /etc/prl-fleet/haproxy.cfg` e
`sudo systemctl restart prl-fleet`. O restart encerra conexões antigas e aplica a
revogação; há uma breve interrupção. Não use apenas reload para expulsar sessões
já autenticadas. Certificados de relay/cliente duram 825 dias; planeje sua
substituição antes do vencimento, em uma nova PKI/pacote com migração coordenada.

Para alterar intervalo/retenção, use `sudo systemctl edit prl-monitor` com:

```ini
[Service]
Environment=PRL_SAMPLE_SECONDS=15
Environment=PRL_RETENTION_HOURS=72
```

Reinicie o monitor. Intervalo permitido: 5–300 segundos; retenção: 1–168 horas.
O manifesto aceita até 1024 IDs; isso é um limite de configuração, não garantia
de capacidade da VPS. Meça CPU, memória, tamanho do banco e volume real.

## Validação e limites da entrega

Na raiz do código-fonte: `bash scripts/test.sh` no Linux, ou
`powershell -NoProfile -File scripts/test.ps1` no Windows com WSL Ubuntu.
Instale `requirements-monitor.txt` em um venv antes; detalhes no README do projeto.
Os testes usam HAProxy, stunnel, OpenSSL e uma pool TLS local, sem mineração.

O deploy remoto, execução apt/systemd em VPS limpa, firewall, reboot e carga
prolongada na Contabo precisam ser validados no ambiente de destino.

Referências: [HAProxy 2.8](https://docs.haproxy.org/2.8/configuration.html),
[stunnel](https://www.stunnel.org/manual.html).
