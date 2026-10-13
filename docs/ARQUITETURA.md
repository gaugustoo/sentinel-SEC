# Arquitetura — SENTINEL

Documento de decisões de projeto. Registra como o sistema está montado, por que está montado assim e onde estão as dívidas técnicas conhecidas.

---

## Visão de camadas

```
┌──────────────────────────────────────────────────────────────┐
│  dashboard/  (Vercel — estático)                             │
│  HTML + CSS + JS · consome a API por HTTP · painéis com       │
│  valores de demonstração                                     │
└───────────────────────────┬──────────────────────────────────┘
                            │  HTTP / JSON
                            ▼
┌──────────────────────────────────────────────────────────────┐
│  api/  (Render — uvicorn + FastAPI)                          │
│  security.py    CORS · API key · rate limit                  │
│  main.py        rotas, modelos Pydantic, motor de varredura  │
└───────────┬──────────────────────────────┬───────────────────┘
            │                              │
            ▼                              ▼
┌────────────────────────┐      ┌──────────────────────────────┐
│  Rede alvo             │      │  Base de serviços            │
│  TCP connect · TLS     │      │  porta → severidade/CVE/fix  │
└────────────────────────┘      └──────────────────────────────┘
            ▲                              ▲
            │                              │
┌───────────┴──────────────────────────────┴───────────────────┐
│  scanner/  (CLI — asyncio + argparse)                        │
│  Mesmo desenho de varredura, com relatório JSON em disco      │
└──────────────────────────────────────────────────────────────┘
```

Três componentes, dois serviços em produção, um núcleo de varredura duplicado — a dívida estrutural central, detalhada adiante.

---

## Decisões de projeto

### FastAPI como camada de API

O FastAPI entrega três coisas que o projeto precisa e não teria de graça em Flask: validação de entrada via Pydantic, geração automática de OpenAPI e suporte nativo a `async`.

A validação importa mais aqui do que num CRUD comum. O `ScanTarget` restringe `timeout` entre `0.5` e `10.0` segundos — sem isso, um timeout alto transforma uma requisição em socket pendurado, e um timeout baixo produz falso negativo em rede com latência. O Pydantic é a primeira linha de defesa, antes de qualquer conexão.

O OpenAPI gerado (`/api/docs`, `/api/redoc`) elimina a necessidade de manter documentação de endpoints em paralelo ao código. A rota está no schema ou não existe.

### Duas hospedagens, não uma

O dashboard é estático e não precisa de processo em execução; a API precisa. Separá-los permite publicar o front no Vercel (CDN, deploy instantâneo, custo zero) e deixar o backend no Render, onde o processo pode rodar. O custo da escolha é CORS — que, na configuração original com `allow_origins=["*"]`, virou o principal risco do projeto.

### asyncio no scanner, socket síncrono na API

Parece incoerência, e é intencional. O CLI varre 20 portas em paralelo contra um alvo: `asyncio.gather` sobre `open_connection` despacha todas ao mesmo tempo e o tempo total passa a ser o do timeout mais lento, não a soma. Já a API recebe requisições HTTP em um worker do uvicorn e o volume é baixo o bastante para que `connect_ex` sequencial seja suficiente — e mais simples de ler.

A unificação levaria asyncio para dentro da API. É a direção natural, mas entra junto com a extração do núcleo.

### Relatório JSON como formato de saída

JSON é o formato que serve aos dois consumidores: o dashboard renderiza direto, e um pipeline de reconhecimento consome com `jq` sem camada de parsing. SARIF está no roadmap para integração com ferramentas de análise estática; Markdown, para leitura humana no PR.

---

## Fluxo de uma varredura

```
POST /api/scan/ports
        │
        ├─ 1. CORS ............ origem autorizada?
        ├─ 2. rate_limit ...... dentro da cota do IP?
        ├─ 3. verify_api_key .. chave confere?
        ├─ 4. ScanTarget ...... timeout em faixa, target presente?
        ├─ 5. Validação do alvo
        │       ipaddress.ip_address(target)
        │         └─ falhou → socket.gethostbyname(target)
        │              └─ falhou → HTTP 400, sem abrir socket
        │
        ├─ 6. Loop de portas (connect_ex + settimeout)
        │       result == 0 → consulta a base de serviços
        │                     → append em open_ports
        │
        ├─ 7. Derivação do risco
        │       crítico > alto > médio > baixo > safe
        │
        └─ 8. PortScanResult (Pydantic) → JSON
```

O ponto de ordem que importa: **o alvo é validado antes de qualquer socket**. Uma entrada inválida custa zero conexões. Sem essa checagem, uma string malformada viraria uma tentativa de DNS e um timeout de rede por requisição.

O passo 7 merece nota: o `risk_level` da resposta é uma redução — o pior achado determina o rótulo do conjunto. É a leitura certa para triagem, mas perde nuance. Um alvo com uma porta `critical` e quinze portas `low` recebe `CRITICAL` e nada mais. O modelo `ScanReport` do CLI já carrega um `risk_score` numérico além do nível; a API não. Unificar os dois levaria o score para o JSON da API.

---

## Fronteira entre funcional e demonstração

| Camada | Estado | Detalhe |
| --- | --- | --- |
| Motor de varredura | Funcional | Conexões TCP e TLS reais |
| Base de serviços | Funcional | Classificação, severidade e remediação corretas; **CVE ilustrativos** |
| Relatório e score (CLI) | Funcional | Derivado dos achados |
| `/api/vulnerabilities` | Funcional | Lê a base interna de portas do próprio código |
| Dashboard — painéis | Demonstração | Consome `/api/dashboard/stats`, cujos agregados são gerados por `random` |
| Dashboard — Top Threat IPs | Demonstração | Endereços são exemplos e blocos reservados |
| `/api/threats/ioc` | Demonstração | Consulta uma lista fixa de cinco IPs em memória |
| `/api/dashboard/stats` | Misto | A rota responde de verdade, mas os números saem de `random` a cada chamada |

A regra que separa as duas: **tudo que faz I/O de rede contra o alvo é funcional; tudo que agrega em tela é demonstração.** Serve como critério para avaliar qualquer adição futura.

Duas rotas pedem nuance. `/api/dashboard/stats` é funcional enquanto rota — responde, valida parâmetros e devolve JSON —, mas o conteúdo é aleatório a cada chamada, o que explica por que os números do dashboard mudam a cada atualização. `/api/threats/ioc` é honesta em relação ao seu propósito: compara o valor recebido com cinco IPs em memória e, para qualquer outro, calcula um score a partir do hash do texto, o que produz um resultado determinístico mas arbitrário. Nenhuma das duas deve ser lida como fonte de inteligência.

---

## Dívidas técnicas

### 1. Núcleo de varredura duplicado

`api/main.py` e `scanner/scanner.py` mantêm cópias independentes da base de serviços, do modelo de risco e da lógica de varredura. A duplicação já produziu divergência observável:

| Porta | API | CLI |
| --- | --- | --- |
| 21 (FTP) | `high` | `critical` |
| 23 (Telnet) | `critical` | `critical` |
| 445 (SMB) | ausente | `critical` |
| 3389 (RDP) | ausente | `high` |
| 6379 (Redis) | ausente | `critical` |
| Cobertura total | 9 portas | 20 portas |

O CLI cobre portas que a API simplesmente não conhece — 445, 3389 e 6379 entre elas, justamente as de maior impacto. Uma varredura feita pelo dashboard nunca reporta EternalBlue ou BlueKeep; a mesma faixa, pelo CLI, reporta.

O mesmo alvo recebe classificações diferentes conforme o ponto de entrada. A extração de `sentinel_core/` resolve e é o item de maior impacto no roadmap.

### 2. Ausência de autenticação e limite — resolvido

A configuração original tinha CORS aberto, nenhuma autenticação e nenhum rate limit. Um terceiro podia disparar varreduras a partir da infraestrutura do projeto, sem deixar rastro e sem custo — deslocando a responsabilidade legal para o operador.

Fechado em duas partes. `api/security.py` implementa as três camadas; `api/main.py` as registra: `install_cors(app)` substitui o middleware anterior, e as rotas `POST /api/scan/ports` e `GET /api/scan/ssl` encadeiam `Depends(rate_limit)` e `Depends(verify_api_key)`.

A proteção só passa a valer com as variáveis definidas no Render:

| Variável | Sem ela |
| --- | --- |
| `SENTINEL_ALLOWED_ORIGINS` | CORS cai no padrão de desenvolvimento e o dashboard deixa de conseguir chamar a API |
| `SENTINEL_API_KEY` | A autenticação é ignorada e a API permanece aberta |

O segundo caso é deliberado — sem a variável definida, `verify_api_key` retorna sem bloquear, para não travar desenvolvimento local. Em produção, defini-la é o que fecha o buraco.

### 3. Estado do rate limit em memória

O contador vive num `dict` do processo. Funciona numa instância única — que é o caso do tier gratuito — e falha silenciosamente se o serviço escalar horizontalmente, porque cada réplica mantém sua própria cota. Com múltiplas réplicas, migrar para Redis.

### 4. `except Exception: pass` no loop de portas

O bloco que envolve `connect_ex` engole qualquer exceção sem registro. Uma porta inacessível e uma falha de socket por falta de descritor produzem o mesmo resultado: ausência silenciosa na resposta. Correção: capturar tipos específicos (`socket.timeout`, `OSError`), logar em nível debug e contabilizar as portas que falharam.

### 5. CVE não verificados

Os identificadores da base não foram conferidos contra o NVD. Em contexto de segurança, isso é o defeito que mais custa credibilidade — um CVE inventado num relatório é pior que a ausência do campo. Substituir por identificadores verificados ou remover o campo, mantendo severidade e remediação, que estão corretas.

### 6. Ausência de testes

O CI garante que a aplicação importa, sobe e documenta rotas — o piso, não a cobertura. Faltam testes de comportamento contra alvo controlado em container: varredura com porta aberta e fechada, derivação do `risk_level` nos cinco casos, parsing do relatório e rejeição de alvo inválido.

---

## Configuração e operação

### Variáveis de ambiente

| Variável | Padrão | Efeito |
| --- | --- | --- |
| `SENTINEL_ALLOWED_ORIGINS` | `localhost:8000`, `localhost:5500` | Origens autorizadas no CORS, separadas por vírgula |
| `SENTINEL_API_KEY` | ausente | Se definida, exigida nos endpoints de varredura |
| `SENTINEL_RATE_WINDOW` | `60` | Janela do rate limit, em segundos |
| `SENTINEL_RATE_MAX` | `30` | Requisições permitidas por janela, por IP |
| `SENTINEL_RATE_DISABLED` | ausente | `1` desliga o rate limit (uso local e CI) |

Se `SENTINEL_API_KEY` não estiver definida, a autenticação é ignorada e a API fica aberta — deliberado, para não travar o desenvolvimento local. Em produção, a chave é obrigatória.

A segunda variável não tem esse mecanismo de escape: se `SENTINEL_ALLOWED_ORIGINS` não for definida, o CORS usa o padrão de desenvolvimento e **o dashboard para de conseguir chamar a API**. Definir as duas no Render é o que completa o hardening.

### Comportamento esperado do tier gratuito

O Render suspende a instância após inatividade e a primeira requisição leva de 30 a 60 segundos para responder. Isso é visível para o usuário do dashboard e é tratado na interface como estado de conexão, não como erro.

---

## Direção

O próximo passo estrutural é `sentinel_core/`, com o motor, a base de serviços e o modelo de risco compartilhados entre API e CLI. A partir dele, o motor de varredura migra para asyncio na API, o `risk_score` do CLI passa a integrar a resposta HTTP e a divergência das bases deixa de ser possível por construção.

Depois disso, as adições que ampliam o projeto sem mudar sua forma: descoberta por faixa CIDR, identificação de serviço por banner em vez de inferência por porta, e exportação em SARIF.
