# Capacidade inicial: 300 mineradores

Alvo informado: VPS Contabo com 4 vCPUs e 8 GB de RAM, inicialmente 300 mineradores.
Referência de carga: uma conexão por minerador e uma identidade por cliente. Se
houver várias conexões por minerador, dimensione pelo total de conexões.

## Transporte e API — medição local em 17/09/2026

Teste com HAProxy 2.8, stunnel, Uvicorn, duas camadas TLS e 300 certificados
individuais. Duas ondas abriram 300 conexões, mantiveram tráfego por pelo menos
15 segundos e encerraram todas as conexões antes da nova onda. Todas as 10.200
trocas de 1.028 bytes em cada sentido preservaram o conteúdo. Cada conexão envia
aproximadamente uma mensagem por segundo depois da primeira troca.

| Medida | Primeira onda | Reconexão |
|---|---:|---:|
| Conexões ativas verificadas | 300 | 300 |
| Tempo até todas conectarem e receberem a primeira resposta | 0,706 s | 0,379 s |
| Handshake + primeira resposta, p95 | 433,70 ms | 104,86 ms |
| CPU média do HAProxy, em percentual de um núcleo | 5,57% | 4,81% |
| CPU média do monitor, em percentual de um núcleo | 0,94% | 0,90% |

RSS máximo observado por amostragem: HAProxy **35,28 MiB**, monitor **47,84 MiB**.
A API HTTPS teve p95 de **110,10 ms** e publicou amostras recentes com conexão
ativa para todos os 300 IDs. O processo stunnel que simula os clientes consumiu
117,37 MiB; em produção esses clientes ficam nas VMs de origem.

Ambiente: WSL2, afinidade limitada a quatro CPUs lógicas, cerca de 7,7 GiB de RAM
total. Clientes, pool falsa e relay compartilharam a mesma máquina. A afinidade
não reproduz o processador, a disputa de vCPU ou a rede da Contabo. O banco desta
medição era novo. São resultados de um perfil sintético curto, não garantia de
capacidade de mineração, uptime ou limite máximo de instâncias.

## Histórico e crescimento

300 IDs × 72 horas × uma coleta a cada 15 segundos = **5.184.000 amostras**.
O teste separado `load_storage.py` mede leitura das últimas amostras e uma coleta
que insere 300 registros e remove 300 expirados. Ele usa timestamps fracionários,
taxas fracionárias e um identificador de processo representativo do HAProxy.
Os números e os detalhes do perfil estão nos JSONs em `benchmarks/`.

Nesta execução, o banco após checkpoint ocupou **990,50 MiB**. A criação em lote
chegou a **1.988,63 MiB** somando banco e WAL, antes de fechar a conexão inicial.
As três leituras levaram 415,61 / 403,62 / 391,85 ms; a coleta com expiração de
300 linhas levou **431,17 ms**. São tamanhos deste conjunto sintético; valores,
comprimento dos IDs, versão do HAProxy e padrões reais de tráfego podem alterá-los.
Essa medição substitui uma sondagem preliminar com registros artificialmente
menores. A medição de disco não é consumo de RAM do serviço.

O manifesto mantém os padrões de 2.048 conexões globais e oito por certificado.
Não é preciso aumentar esses limites para 300 conexões. O limite global também
é compartilhado com o gateway do painel; não opere permanentemente no teto.
O gerador aceita até 1.024 IDs, e a configuração nesse tamanho passou no parser
real do HAProxy. Isso não equivale a testar 1.024 conexões ativas.

Antes de aumentar a frota, repita o teste com o total previsto de conexões e
acompanhe CPU, memória, disco, banda, erros de conexão e `collection.stale`.
Teste também reinício, reconexão de toda a frota e o tráfego real do minerador.
Todos os clientes dependem desta única VPS; indisponibilidade dela interrompe o
encaminhamento. O projeto ainda não implementa redundância entre relays.

## Reproduzir

No Linux/WSL, depois de preparar as ferramentas e o venv descritos no README:

```sh
.tools/monitor-venv/bin/python tests/load_fleet.py \
  --clients 300 --seconds 15 --cycles 2 --cpus 4 --output build/load-300.json
.tools/monitor-venv/bin/python tests/load_storage.py \
  --clients 300 --hours 72 --output build/storage-300.json
```

Execute separadamente, sem outros testes de carga concorrentes. A simulação usa
apenas loopback e diretórios temporários. Não instala serviços, muda firewall ou
contata pools públicas. O teste de histórico usa espaço temporário considerável
para o banco e WAL; assegure espaço livre antes de executar.

O teste encontrou e corrigiu um defeito de escala: todas as identidades eram
escritas em uma única linha de ACL, excedendo o limite de argumentos do HAProxy.
Agora a mesma ACL é declarada em grupos de 32 identidades. Os 300 clientes foram
autenticados, incluindo os grupos posteriores ao primeiro.
