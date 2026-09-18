# Um instalador para todas as VMs

O mesmo **arquivo privado `install-miners.sh`** pode ser executado em todas as
VMs Ubuntu 24.04 x86_64 com driver NVIDIA funcional. Não informe ID, senha,
certificados, endereço de pool ou worker em cada máquina:

```bash
sudo bash install-miners.sh
```

O script já contém uma credencial de cadastro restrita ao relay e sua chave de
host SSH fixada. Ele solicita automaticamente o próximo ID disponível, recebe
somente o certificado daquela VM e instala o túnel, PRL nas GPUs e XMR na CPU.
O nome do Linux passa a ser `gpu0017`, `gpu0018` etc.; os workers são
`CONTA/gpu0017-gpu` e `CONTA/gpu0017-cpu`. O nome do recurso no portal Azure é
definido quando a VM é criada e não é alterado por este instalador.

Para primeiro boot, use o **mesmo `cloud-init.yaml` privado em todas as VMs**:

```bash
az vm create [seus parâmetros de imagem, tamanho e rede] --custom-data cloud-init.yaml
```

Isso substitui a necessidade de gerar ou copiar um cloud-init por ID. Os dois
arquivos são gerados juntos; não é necessário executar o `.sh` se o cloud-init
foi usado. Eles automatizam a mineração em uma VM; não criam recursos Azure.

## O que ocorre automaticamente

1. A VM cria uma credencial aleatória de retomada e a associa ao UUID do hardware.
2. O relay reserva o próximo ID livre sob trava, inclusive em criações simultâneas.
3. A CA emite o certificado individual; o relay libera o ID e atualiza a API do painel.
4. A VM verifica o pacote, configura seu hostname e instala os dois mineradores.
5. O script espera **shares aceitas de PRL e de XMR** antes de registrar sucesso.
6. Falhas de rede ou instalação são repetidas automaticamente pelo systemd.

Uma repetição na mesma VM reutiliza a identidade. Reservas de operações
interrompidas são mantidas, portanto podem existir lacunas na numeração.
No reboot, os mineradores e o túnel voltam automaticamente. VMs substituídas
com disco novo recebem uma identidade nova. Use uma imagem capturada **antes**
do cadastro/mineração; não clone uma imagem contendo certificados de outra VM.

O relay prepara espaço para novos clientes em lotes de 128. O primeiro cadastro
e uma futura expansão de capacidade podem provocar uma breve reconexão dos
mineradores. Dentro do lote, os novos cadastros não reiniciam o transporte.
A API continua mostrando apenas identidades cadastradas e seus dados de tráfego.

## Preparação única no relay

Esta etapa instala o cadastro automático no servidor e gera os arquivos privados.
Depois dela, nenhuma preparação individual por VM é necessária:

```bash
sudo python3 -m fleet.enroll_setup \
  --base-dir /root/.local/share/xna-relay-secrets \
  --account krxYZDM8VP \
  --output /root/.local/share/xna-relay-secrets/automatic-mining
```

O diretório precisa conter a PKI, `ca-passphrase` com permissão 0600 e o pacote
`fleet` correspondente ao relay instalado. A instalação existente é verificada
antes de cadastrar clientes; alterações externas incompatíveis são recusadas.

O preparador preserva as chaves administrativas e adiciona uma autorização SSH
`restrict,command=...`: a chave do instalador só cadastra VMs. Não permite shell,
PTY, encaminhamento de portas ou alteração da conta de mineração pelo cliente.
A senha administrativa e a chave privada da CA permanecem no relay. A conta e
a reserva de CPU são fixadas pelo administrador no comando acima.

Cada versão usa uma cópia privada imutável do código de cadastro. Atualizar o
checkout do repositório não muda o instalador entregue a scripts antigos.
Um timer diário renova a CRL quando necessário, preservando revogações. Seu
estado aparece em `systemctl status xna-relay-maintenance.timer`.

**Os arquivos gerados contêm uma credencial privada de cadastro.** Distribua-os
somente à sua automação/às suas VMs; não publique no Git, imagem pública ou URL
pública. Administradores da VM e do recurso Azure podem acessar o custom data.
Remover a linha de cadastro correspondente de `/root/.ssh/authorized_keys`
impede novos cadastros com aquela versão; os certificados já emitidos precisam
ser revogados separadamente, conforme [PKI.md](PKI.md).

## Acompanhamento opcional

O acompanhamento não é necessário para a instalação continuar:

```bash
sudo journalctl -u xna-dual-bootstrap -f
sudo systemctl status xna-dual-tunnel xna-dual-prl xna-dual-xmr --no-pager
hostname
```

O registro `/var/lib/xna-dual-enroll/ready` confirma que ambos os mineradores
aceitaram shares. Os serviços mantêm nomes explícitos de mineração.
A autenticação e o TLS protegem o transporte; não tornam a atividade indetectável.

Requisitos de GPU, limites de CPU, huge pages e APIs locais estão em
[AZURE-DUAL.md](AZURE-DUAL.md). A API consultada pelo backend do painel está em
[MONITOR-API.md](MONITOR-API.md).
