# Verificação — 17/09/2026

## Testes locais

Comando: `powershell -NoProfile -File scripts/test.ps1`, com Python no Windows e
WSL Ubuntu 24.04. A suíte usa certificados temporários e uma pool TLS local;
não inicia mineração nem instala serviços no computador.

- 41 testes Python no Windows: geradores, PKI, API e menu.
- No Linux, os mesmos testes mais 8 testes do bootstrap por download.
- 5 testes de transporte V1 e 13 testes Fleet, com HAProxy, stunnel, OpenSSL,
  Uvicorn e SQLite reais.
- Sintaxe dos scripts com `bash -n` e unidades com `systemd-analyze verify`,
  substituindo apenas os caminhos dos executáveis pelos disponíveis localmente.

O bootstrap foi validado com um arquivo de download local na fronteira de rede:
abertura do menu, modo sem interface, preservação de destino existente, falha de
download, arquivo inválido/incompleto e falha de cópia. O menu foi aberto também
em terminal interativo. Os testes não executam apt ou instalação de serviços.

Os casos de transporte incluem rejeição de certificado ausente, CA incorreta,
revogação, ID desconhecido, origem fora da ACL e pool com identidade incorreta.
O painel exige seu certificado e Bearer; clientes não acessam a API. Relay ou
pool indisponível causa falha, sem fallback direto pelo cliente gerado.

Os testes da API cobrem retenção, resets de contadores, coleta antiga/falha e
timestamps inválidos. Os pacotes não incluem a chave da CA; cada cliente recebe
sua própria chave. Emissão, revogação e renovação da CRL compartilham um bloqueio.

Starlette emite um aviso de depreciação de `httpx` no cliente de testes; isso não
causou falha. O workflow [Tests](https://github.com/yashirozz1/xna-relay-server/actions/workflows/tests.yml)
executa a suíte Linux em cada push e pull request.

## Carga e histórico

Ensaios locais em WSL/loopback, com quatro CPUs lógicas disponíveis ao teste:

| Medição | Resultado |
|---|---|
| Conexões ativas | 300, em duas ondas |
| Trocas verificadas | 10.200 |
| RSS máximo amostrado do HAProxy | 35,28 MiB |
| RSS máximo amostrado do monitor | 47,84 MiB |
| p95 da API HTTPS | 110,10 ms |
| Histórico sintético | 5.184.000 registros |
| Tamanho do banco sintético | 990,50 MiB |
| Leitura das últimas amostras | Cerca de 0,4 s |

Configuração de 1.024 IDs aceita pelo HAProxy real. São medições de laboratório,
não capacidade comprovada da Contabo. Metodologia, uso de WAL e relatórios JSON
estão em [Capacidade](docs/CAPACITY.md) e [benchmarks](docs/benchmarks/).

## Limites da verificação

Continuam pendentes a instalação apt/systemd e rollback em Ubuntu limpo, deploy
na Contabo, firewall real, reboot, carga prolongada e integração no código do
painel. O projeto fornece a API e exemplos; o código do painel é separado.

Nenhuma VPS foi acessada nesta verificação. Os testes não garantem comportamento
de fallbacks internos de mineradores externos nem ocultação da atividade na rede.
