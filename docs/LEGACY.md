# Relay V1 - cliente por IP

Documentacao da primeira versao; para novas frotas use [Fleet](FLEET.md).

Pacote para **proteger o transporte e evitar confiar no software de um proxy de
mineração desconhecido**. O relay encaminha bytes; não implementa PearlHash,
reescrita de carteira, taxa de mineração ou recebimento de pagamentos.

**Não oferece ocultação da mineração ao provedor, camuflagem como navegação nem
desativação de monitoramento.** SNI, IPs, horários e volume continuam observáveis.
O provedor da VM continua controlando a infraestrutura de execução.

## Fluxo e confiança

```text
VM Ubuntu com minerador                    VPS Contabo              Kryptex
minerador -> 127.0.0.1:17048 -> stunnel ===> HAProxy TCP ===========> pool TLS
                                  TLS autenticado até a pool
```

O stunnel no cliente valida a cadeia de CAs e o nome `prl.kryptex.network`, mesmo
conectando ao IP da Contabo. O relay não termina TLS e não recebe a chave TLS da pool.
Assim, um relay comprometido pode bloquear/atrasar a conexão e observar metadados,
mas não alterar conteúdo aceito pelo cliente/pool sem violar a autenticação TLS.
Isso depende da integridade do cliente/pool, relógio e CAs confiáveis.

Não protege contra um minerador malicioso, conta comprometida, CA comprometida,
pool desonesta ou invasão administrativa da VM. Nunca informe seed, chave privada
ou senha da conta ao relay. Compare workers, shares aceitas e pagamentos no painel
original da Kryptex. Taxas da pool e do minerador continuam existindo.

## Estado da entrega

Este é um pacote local para preparar a implantação. Ainda não existe VPS configurada
por este projeto. Nenhuma compra, mineração ou mudança de SSH/firewall foi feita.
Os testes locais e seus resultados ficam descritos em `TEST-RESULTS.md` no projeto.

## Requisitos futuros

- Contabo: VPS dedicada a este relay, Ubuntu 24.04 LTS, IPv4 acessível e SSH por chave.
  Como ponto de partida para poucas conexões: 1 vCPU e 1 GB RAM; dimensionamento
  deve ser confirmado com carga real. Não precisa de GPU nem domínio para o relay.
- Cliente: Ubuntu 24.04 LTS com systemd e acesso sudo.
- Endereço IPv4 de **saída** do cliente. Pode diferir do IP usado no SSH se houver NAT.
  Esse endereço precisa permanecer estável ou a ACL precisará ser atualizada.
- Firewall externo permitindo TCP 18443 na Contabo somente a partir desse IPv4;
  preservar a regra administrativa de SSH 22. O instalador não cria essas regras.
- Minerador compatível com PRL e com conexão TCP à pool local. Minerador e carteira
  não são fornecidos neste pacote; não instale binários de origem desconhecida.

## Preparar os pacotes (neste projeto, Windows ou Linux)

Python 3.10+ é suficiente. Não é necessário instalar bibliotecas Python.

```bash
python3 relay_bundle.py --relay-ip 203.0.113.10 --client-ip 198.51.100.20 --output build/contabo
```

**Os IPs acima são reservados para documentação. Troque pelos reais ao implantar.**
No Windows, use `python` em vez de `python3`. O gerador não conecta a nenhum servidor.
Saída: `relay/` vai à Contabo; `client/` vai à VM com GPUs; `settings.json` registra
os parâmetros. Não há senhas no pacote. Uma saída existente nunca é sobrescrita.
Para atualizar, gere outro diretório e revise as diferenças.

Opções: `--pool-host`, `--pool-port`, `--relay-port`, `--local-port`.
O padrão da pool é o endpoint TLS documentado `prl.kryptex.network:8048`.
Não aponte para 7048, que é TCP sem TLS. Não desabilite verificação de certificado
para contornar erro: interrompa e confira a identidade/CA com a pool.

## Instalar quando as VMs existirem

Revise `settings.json`, configs e `install.sh`. Transfira cada pasta por SCP usando
seu acesso SSH existente. Não substitua senhas nem regras do SSH.

Na Contabo, dentro da pasta `relay/`:

```bash
sudo bash install.sh
sudo systemctl status prl-relay --no-pager
```

Na VM com GPUs, dentro da pasta `client/`:

```bash
sudo bash install.sh
sudo systemctl status prl-client --no-pager
```

O instalador obtém componentes dos repositórios Ubuntu, cria unidades próprias
com execução sem root, e recusa sobrescrever instalação anterior deste pacote.
Impede que serviços padrão inativos sejam iniciados durante a instalação dos
pacotes. Não altera rotas, UFW, NSG, nftables, iptables nem configuração SSH.
Pacotes existentes podem ser atualizados pelo apt; use VMs sem serviços conflitantes.
Falha de inicialização remove os arquivos novos do pacote; dependências apt ficam.

**Uma unidade ativa não significa que a pool está autenticada/alcançável.**

## Verificar antes de iniciar mineração

1. Na VM cliente, teste o TLS através da Contabo (script na raiz do pacote):

```bash
python3 check_tls.py --connect IP_REAL_CONTABO --port 18443
```

O resultado precisa confirmar cadeia e identidade da pool. O script não envia
wallet, login nem shares. Uma origem não permitida pela ACL não deve conectar.

2. Confira o listener local e os logs:

```bash
ss -ltn 'sport = :17048'
sudo journalctl -u prl-client -n 30 --no-pager
```

O listener precisa ser **127.0.0.1:17048**, não `0.0.0.0`. O minerador deve usar
`stratum+tcp://127.0.0.1:17048` (ou sintaxe TCP equivalente do minerador de PRL).
Não use SSL nesse endpoint local: stunnel faz TLS a partir dele. Mantenha o formato
de usuário/wallet/worker exigido pela Kryptex, sem alterar o destino de pagamento.
O TCP local não sai da VM. Processos locais ainda podem acessar esse listener.

3. Após selecionar o minerador, faça um teste curto e confirme shares/worker na
Kryptex, depois interrompa o relay e verifique que esse worker desconecta. Este teste
operacional ainda depende das VMs e do minerador escolhidos.

**Limite:** apenas conexões ao endpoint local passam pelo relay. Não há kill switch
da VM. Fallbacks e conexões de dev-fee do minerador podem usar outros destinos;
precisam ser avaliados separadamente. Não configure fallback direto como solução
para falhas de certificado ou indisponibilidade.

## Parar e remover

Na Contabo:

```bash
sudo systemctl disable --now prl-relay
sudo rm /etc/systemd/system/prl-relay.service /etc/prl-relay/haproxy.cfg
sudo rmdir /etc/prl-relay
sudo systemctl daemon-reload
```

No cliente:

```bash
sudo systemctl disable --now prl-client
sudo rm /etc/systemd/system/prl-client.service /etc/prl-client/stunnel.conf
sudo rmdir /etc/prl-client
sudo systemctl daemon-reload
```

Pare o minerador antes. Essas instruções removem somente os arquivos deste pacote,
sem desinstalar dependências nem tocar SSH. Para atualização, pare/remova o pacote
antigo, mantendo uma cópia, e instale o novo; há uma breve interrupção de serviço.

## Testes locais

Em Ubuntu 24.04 amd64, pode preparar as ferramentas sem instalá-las no sistema:

```bash
bash scripts/prepare-test-tools.sh
bash scripts/test.sh
```

O bootstrap baixa pacotes dos repositórios Ubuntu configurados e os extrai em
`.tools/`. Se os índices apt estiverem antigos e o download falhar, atualize os
índices e tente novamente. Não adiciona repositórios, instala pacotes ou inicia
serviços. O harness também funciona com os executáveis já instalados no PATH.

No Windows com uma distribuição WSL chamada Ubuntu, depois do bootstrap no WSL:

```powershell
powershell -NoProfile -File scripts/test.ps1
```

Comandos individuais:

```bash
python3 -m unittest discover -s tests -p test_bundle.py -v
python3 tests/integration.py
python3 tests/validate_linux.py
```

Integração exige Linux, HAProxy, stunnel4 e OpenSSL. Não usa carteira, conta Kryptex
ou mineração. Cria CA/certificados temporários, um servidor TLS falso e processos
locais, encerrados ao final. Não altera serviços do sistema.

## Fontes

- [Pool PRL e endpoint SSL da Kryptex](https://pool.kryptex.com/prl)
- [HAProxy TCP](https://www.haproxy.com/documentation/haproxy-configuration-tutorials/protocol-support/tcp/)
- [Autenticação stunnel](https://www.stunnel.org/auth.html)
- [Manual stunnel](https://www.stunnel.org/manual.html)
