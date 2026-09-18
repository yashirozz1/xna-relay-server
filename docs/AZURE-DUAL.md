# Azure: PRL nas GPUs e XMR na CPU no primeiro boot

**Para usar um único arquivo em todas as VMs, sem preparar IDs ou certificados
individualmente, veja [Mineração automática](AUTOMATIC-MINING.md).** O fluxo
abaixo é a alternativa de provisionamento individual.

O gerador `dual_bundle.py` cria um **cloud-init privado por identidade**. Passe o
arquivo a `az vm create --custom-data`: o primeiro boot instala o túnel mTLS e os
serviços de mineração. Não precisa de SSH, senha da Contabo ou chave da CA na VM.

Requisitos: imagem limpa Ubuntu 24.04 x86_64, systemd, Python 3, OpenSSL e driver
NVIDIA funcional **580.65.06 ou superior**. O instalador não instala drivers.
Use uma imagem anterior à instalação dos mineradores; capturar a VM que já está
minerando também copia serviços e credenciais que não devem ser reutilizados.
É necessário acesso HTTPS aos repositórios Ubuntu/GitHub, DNS e TCP à porta do
relay. Não é aberta nenhuma porta pública na VM.

## 1. Preparar o relay e as identidades

O relay precisa de uma identidade por VM, conforme [FLEET.md](FLEET.md), com o
manifesto dual do [exemplo](../examples/fleet-dual.json). Estes campos habilitam
XMR, mantendo PRL como destino padrão:

```json
"xmr_pool_host": "xmr.kryptex.network",
"xmr_pool_port": 8029
```

Gere e aplique a configuração do relay antes de provisionar os clientes. Apenas
editar o manifesto não altera o HAProxy em execução. O gerador de clientes exige
PRL `prl.kryptex.network:8048` e XMR `xmr.kryptex.network:8029`.

Em cada backend autenticado, o SNI externo `xmr.relay.prl.internal` seleciona
XMR. O certificado do relay continua validado como `relay.prl.internal`. Cada
pool é autenticada em uma segunda conexão TLS. A API existente soma o tráfego
PRL e XMR **por identidade**; não informa hashrate, saldo ou shares.

## 2. Gerar o cloud-init privado

No administrador que armazena os pacotes da frota:

```bash
umask 077
python3 dual_bundle.py \
  --fleet-dir "$HOME/.local/share/xna-relay-secrets/fleet" \
  --instance-id gpu0002 \
  --account krxYZDM8VP \
  --output "$HOME/.local/share/xna-relay-secrets/azure-dual/gpu0002"
```

Para todos os IDs, troque `--instance-id gpu0002` por `--all` e use uma pasta de
saída nova, como `.../azure-dual-20260918`. Um erro interrompe o lote; as pastas
já geradas são preservadas. Para repetir, escolha outra pasta de saída.

O gerador verifica a CA, o CN, a validade e a correspondência da chave privada.
Não sobrescreve saídas existentes. Cada pasta tem `cloud-init.yaml`, instalador,
configuração, certificado da CA e **somente a chave/certificado daquele ID**.
O arquivo cloud-init inclui essa chave: não publique, não coloque no Git e não
registre seu conteúdo nos logs da automação. Quem controla o recurso Azure ou
o sistema operacional pode acessar o custom data. Para um modelo que exija
segredos fora do custom data, use provisionamento separado com Key Vault.

## 3. Usar na criação via Azure CLI

Copie o arquivo privado para a máquina que executa sua automação. Exemplo quando
ele foi gerado na Contabo:

```bash
umask 077
scp root@169.58.109.245:/root/.local/share/xna-relay-secrets/azure-dual/gpu0002/cloud-init.yaml \
  ./gpu0002-cloud-init.yaml
chmod 600 ./gpu0002-cloud-init.yaml
```

Acrescente esta opção ao seu comando de criação existente:

```bash
--custom-data ./gpu0002-cloud-init.yaml
```

Exemplo completo; defina as variáveis conforme sua assinatura, imagem e rede:

```bash
az vm create \
  --resource-group "$RESOURCE_GROUP" \
  --name gpu0002 \
  --image "$NVIDIA_IMAGE_ID" \
  --size "$GPU_VM_SIZE" \
  --admin-username ubuntu \
  --ssh-key-values "$SSH_PUBLIC_KEY_FILE" \
  --subnet "$SUBNET_ID" \
  --custom-data ./gpu0002-cloud-init.yaml
```

Mantenha as opções Spot/rede/disco da sua automação. Para uma VM simultânea nova,
use o próximo ID e o arquivo correspondente. **Nunca clone o mesmo cloud-init
para várias VMs ativas.** O ID `gpu0001` já pode estar reservado à VM atual.
Quando substituir uma VM Spot definitivamente removida, seu ID pode ser
reutilizado depois de confirmar que a anterior não voltará a conectar.

A resposta de `az vm create` não significa que os mineradores já inicializaram.
O limite de custom data do Azure é 64 KiB; o gerador comprime os arquivos e
recusa um resultado acima do limite. Referências oficiais:
[cloud-init](https://learn.microsoft.com/en-us/azure/virtual-machines/linux/using-cloud-init)
e [custom data](https://learn.microsoft.com/en-us/azure/virtual-machines/custom-data).

## 4. Acompanhar e operar

```bash
sudo journalctl -u xna-dual-bootstrap -f
sudo systemctl status xna-dual-tunnel xna-dual-prl xna-dual-xmr --no-pager -l
sudo journalctl -u xna-dual-prl -u xna-dual-xmr -n 80 --no-pager
```

O bootstrap repete após falha com intervalo de 60 segundos. Se a instalação foi
interrompida, o próximo boot retoma usando os mesmos arquivos. Estado e identidade
ficam em `/var/lib/xna-dual-miner`; configurações em `/etc/xna-dual-miner` e
binários em `/opt/xna-dual-miner`. O marcador `complete` confirma instalação e
serviços ativos, **não shares aceitas**: confirme a aceitação nos logs ou APIs.

```bash
curl --fail http://127.0.0.1:12000/metrics
curl --fail http://127.0.0.1:18089/2/summary
```

As APIs são locais. A API autenticada do relay para o painel continua descrita
em [MONITOR-API.md](MONITOR-API.md).

Para parar ou reiniciar a mineração:

```bash
sudo systemctl stop xna-dual-prl xna-dual-xmr
sudo systemctl start xna-dual-prl xna-dual-xmr
```

Para impedir o início após reboot:

```bash
sudo systemctl disable --now xna-dual-prl xna-dual-xmr
```

## Comportamento da instalação

- KRig oficial 1.5.1 minera PRL em todas as GPUs NVIDIA. Alfa 6.26.0 minera XMR
  RandomX na CPU. Downloads têm versões e hashes SHA256 fixos; divergência
  interrompe a instalação. Licenças incluídas nos arquivos são preservadas.
- Workers: `CONTA/ID-gpu` e `CONTA/ID-cpu` (por exemplo,
  `krxYZDM8VP/gpu0002-gpu`). Os serviços usam usuários próprios sem login.
- Por padrão, reserva ao menos 10% dos núcleos físicos em cada nó NUMA para o
  sistema e as GPUs. Não duplica threads SMT. Ajuste no gerador com
  `--reserve-cpu-percent 20`, de 1 a 50. Na máquina de 80 núcleos/2 nós, o
  padrão usa 72 threads para XMR.
- Huge pages de 2 MiB são preparadas para RandomX e restauradas após reboot.
  Reservas pré-existentes não são reduzidas. Configurações incompatíveis falham
  com mensagem, sem sobrescrever serviços existentes. MSR e overclock não são
  alterados.
- O KRig usa o hostname e TLS oficiais da pool. Uma regra NAT local, restrita
  ao usuário PRL e TCP 8048, encaminha essa conexão ao túnel autenticado. DNS
  permanece normal; a regra é removida quando o serviço para. XMR usa a porta
  local 17029, também com TLS da pool dentro do túnel.
- O túnel protege o conteúdo e autentica os participantes. Não torna a
  mineração indetectável nem substitui autorização do provedor.

Para verificar credenciais, hardware e plano de CPU sem instalar ou iniciar:

```bash
sudo python3 /var/lib/xna-dual-bootstrap/install.py \
  --bundle-dir /var/lib/xna-dual-bootstrap --check
```

Mantenha a CA, a CRL e os certificados conforme [PKI.md](PKI.md). Cloud-init de
uma imagem deve usar certificados ainda válidos; renovar a CRL do relay não
renova os certificados já distribuídos.
