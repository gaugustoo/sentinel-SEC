# SENTINEL â€” Security Monitoring & Threat Intelligence Platform

Plataforma de reconhecimento e auditoria de superfÃ­cie de ataque, com API REST, scanner assÃ­ncrono de linha de comando e dashboard de visualizaÃ§Ã£o.

Executa descoberta de portas TCP, auditoria de certificados TLS, classificaÃ§Ã£o de risco por serviÃ§o exposto e geraÃ§Ã£o de relatÃ³rio estruturado â€” o suficiente para alimentar um fluxo de avaliaÃ§Ã£o autorizada de rede.

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100%2B-009688?style=flat-square&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![License](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)](LICENSE)
[![Frontend](https://img.shields.io/badge/Frontend-Vercel-000000?style=flat-square&logo=vercel&logoColor=white)](https://sentinel-sec.vercel.app/)
[![API](https://img.shields.io/badge/API-Render-46E3B7?style=flat-square&logo=render&logoColor=black)](https://sentinel-api.onrender.com)

**Dashboard:** https://sentinel-sec.vercel.app/ Â· **API:** https://sentinel-api.onrender.com Â· **OpenAPI:** https://sentinel-api.onrender.com/api/docs

> A instÃ¢ncia da API roda no tier gratuito do Render, que suspende o serviÃ§o apÃ³s inatividade. A primeira requisiÃ§Ã£o apÃ³s a suspensÃ£o leva de 30 a 60 segundos â€” comportamento esperado, nÃ£o indisponibilidade.

---

## SumÃ¡rio

- [Escopo](#escopo)
- [Arquitetura](#arquitetura)
- [Estrutura do projeto](#estrutura-do-projeto)
- [InstalaÃ§Ã£o](#instalaÃ§Ã£o)
- [Uso](#uso)
- [API](#api)
- [Base de conhecimento de portas](#base-de-conhecimento-de-portas)
- [O que Ã© funcional e o que Ã© demonstraÃ§Ã£o](#o-que-Ã©-funcional-e-o-que-Ã©-demonstraÃ§Ã£o)
- [Hardening pendente](#hardening-pendente)
- [Deploy](#deploy)
- [Testes e integraÃ§Ã£o contÃ­nua](#testes-e-integraÃ§Ã£o-contÃ­nua)
- [Roadmap](#roadmap)
- [Uso autorizado](#uso-autorizado)
- [Autor](#autor)
- [LicenÃ§a](#licenÃ§a)

---

## Escopo

O projeto cobre quatro capacidades, todas apoiadas num Ãºnico nÃºcleo de varredura:

| Capacidade | ImplementaÃ§Ã£o | Estado |
| --- | --- | --- |
| Descoberta de portas TCP | `socket.connect_ex` (API) e `asyncio.open_connection` (CLI) | Funcional |
| Auditoria de certificado TLS | `ssl.create_default_context` com leitura de validade, emissor e expiraÃ§Ã£o | Funcional |
| ClassificaÃ§Ã£o de exposiÃ§Ã£o | Base de serviÃ§os por porta com severidade, CVE e remediaÃ§Ã£o | Funcional |
| RelatÃ³rio estruturado | JSON com achados, duraÃ§Ã£o, score e nÃ­vel de risco agregado | Funcional |

O dashboard consome a API e apresenta os resultados; seus painÃ©is agregados usam valores de demonstraÃ§Ã£o. A [seÃ§Ã£o dedicada](#o-que-Ã©-funcional-e-o-que-Ã©-demonstraÃ§Ã£o) detalha a fronteira.

---

## Arquitetura

```mermaid
flowchart LR
    CLI[scanner/scanner.py<br/>asyncio + argparse] --> NET[(Rede alvo)]
    BROWSER[dashboard/index.html] -->|HTTP / JSON| API
    API[api/main.py<br/>FastAPI] --> NET
    API --> KB[(Base de<br/>serviÃ§os e CVE)]
    CLI --> KB
    API --> SSL[Auditoria TLS]
    CLI --> SSL
```

TrÃªs componentes, dois serviÃ§os em produÃ§Ã£o. `dashboard/` Ã© estÃ¡tico e hospedado no Vercel; `api/` roda no Render e concentra a lÃ³gica de rede. `scanner/` compartilha o mesmo desenho de varredura, em versÃ£o de linha de comando com relatÃ³rio em disco â€” Ãºtil para execuÃ§Ã£o agendada em pipeline de reconhecimento.

O nÃºcleo de varredura estÃ¡ duplicado entre `api/main.py` e `scanner/scanner.py`. A unificaÃ§Ã£o num pacote `sentinel_core/` estÃ¡ no roadmap e Ã© a refatoraÃ§Ã£o de maior impacto estrutural pendente.

---

## Estrutura do projeto

Legenda: `[x]` presente no repositÃ³rio Â· `[ ]` planejado

```
sentinel-SEC/
â”œâ”€â”€ [x] README.md
â”œâ”€â”€ [x] .gitignore
â”œâ”€â”€ [x] LICENSE                   # MIT
â”œâ”€â”€ [x] requirements.txt          # dependÃªncias do projeto
â”œâ”€â”€ [x] render.yaml               # definiÃ§Ã£o de serviÃ§o no Render
â”œâ”€â”€ [x] vercel.json               # publicaÃ§Ã£o estÃ¡tica no Vercel
â”œâ”€â”€ [x] railway.json              # definiÃ§Ã£o de serviÃ§o no Railway
â”œâ”€â”€ [x] Procfile                  # comando de start da API
â”œâ”€â”€ [x] nixpacks.toml             # configuraÃ§Ã£o de build
â”œâ”€â”€ [x] runtime.txt               # versÃ£o do Python em produÃ§Ã£o
â”œâ”€â”€ [ ] .github/
â”‚   â””â”€â”€ [ ] workflows/
â”‚       â””â”€â”€ [ ] ci.yml            # lint, import check e validaÃ§Ã£o do OpenAPI
â”œâ”€â”€ api/
â”‚   â”œâ”€â”€ [x] main.py               # aplicaÃ§Ã£o FastAPI
â”‚   â”œâ”€â”€ [ ] security.py           # CORS restrito, API key e rate limit
â”‚   â””â”€â”€ [x] requirements.txt      # dependÃªncias da API
â”œâ”€â”€ scanner/
â”‚   â””â”€â”€ [x] scanner.py            # CLI assÃ­ncrono com relatÃ³rio JSON
â”œâ”€â”€ dashboard/
â”‚   â””â”€â”€ [x] index.html            # dashboard
â””â”€â”€ [ ] docs/
    â””â”€â”€ [ ] ARQUITETURA.md        # decisÃµes de projeto e fluxo de dados
```

TrÃªs arquivos de deploy coexistem na raiz â€” `render.yaml`, `vercel.json` e `railway.json` â€”, o que dÃ¡ trÃªs caminhos de publicaÃ§Ã£o. Os dois primeiros estÃ£o em uso; `railway.json` fica como alternativa documentada.

---

## InstalaÃ§Ã£o

Requer **Python 3.10+** (uso de `list[int]` e `X | None` em anotaÃ§Ãµes) e Git.

```bash
git clone https://github.com/gaugustoo/sentinel-SEC.git
cd sentinel-SEC

python -m venv .venv
source .venv/bin/activate        # Linux / macOS
.venv\Scripts\activate           # Windows

pip install -r requirements.txt
```

Para contribuir, instale tambÃ©m o linter:

```bash
pip install ruff
ruff check api scanner
```

---

## Uso

### API

```bash
uvicorn api.main:app --reload --port 8000
```

Sobe em `http://localhost:8000`. DocumentaÃ§Ã£o gerada pelo FastAPI:

- **Swagger UI** â€” http://localhost:8000/api/docs
- **ReDoc** â€” http://localhost:8000/api/redoc
- **EspecificaÃ§Ã£o OpenAPI** â€” http://localhost:8000/openapi.json

### Scanner CLI

```bash
# Conjunto padrÃ£o de 20 portas
python scanner/scanner.py --target 192.168.1.1

# Portas especÃ­ficas
python scanner/scanner.py --target 10.0.0.5 --ports 22 80 443 3306

# Timeout reduzido e relatÃ³rio em caminho definido
python scanner/scanner.py --target 172.16.0.10 --timeout 2 --output recon/172.16.0.10.json
```

| Argumento | ObrigatÃ³rio | PadrÃ£o | DescriÃ§Ã£o |
| --- | --- | --- | --- |
| `--target` | sim | â€” | IP ou hostname alvo |
| `--ports` | nÃ£o | 20 portas de exposiÃ§Ã£o comum | Lista de portas separadas por espaÃ§o |
| `--timeout` | nÃ£o | `1.5` | Timeout por porta, em segundos |
| `--output` | nÃ£o | `scan_<alvo>_<timestamp>.json` | Caminho do relatÃ³rio JSON |

A saÃ­da traz, por porta aberta, serviÃ§o identificado, severidade, CVE associado quando houver e a recomendaÃ§Ã£o de remediaÃ§Ã£o, alÃ©m do score agregado de risco no fim da execuÃ§Ã£o.

---

## API

Base local `http://localhost:8000` Â· base em produÃ§Ã£o `https://sentinel-api.onrender.com`

| MÃ©todo | Rota | DescriÃ§Ã£o |
| --- | --- | --- |
| `GET` | `/` | Status do serviÃ§o e versÃ£o |
| `POST` | `/api/scan/ports` | Varredura de portas TCP no alvo informado |
| `GET` | `/api/scan/ssl` | Auditoria do certificado TLS de um hostname |
| `GET` | `/api/threat/intel` | Consulta de IoC (dados de demonstraÃ§Ã£o) |
| `GET` | `/api/threat/stats` | EstatÃ­sticas agregadas (dados de demonstraÃ§Ã£o) |
| `GET` | `/api/report/generate` | RelatÃ³rio executivo de seguranÃ§a para o alvo |

### `POST /api/scan/ports`

Corpo aceito, conforme o modelo `ScanTarget`:

| Campo | Tipo | ObrigatÃ³rio | PadrÃ£o | RestriÃ§Ãµes |
| --- | --- | --- | --- | --- |
| `target` | string | sim | â€” | IP vÃ¡lido ou hostname resolvÃ­vel |
| `ports` | inteiros | nÃ£o | `[21, 22, 23, 25, 80, 443, 3306, 5432, 8080]` | Portas individuais por requisiÃ§Ã£o |
| `timeout` | float | nÃ£o | `2.0` | Entre `0.5` e `10.0` segundos |

O alvo Ã© validado com `ipaddress.ip_address` e, na falha, com resoluÃ§Ã£o via `socket.gethostbyname` â€” entrada invÃ¡lida retorna HTTP 400 antes de qualquer conexÃ£o. O `risk_level` da resposta Ã© derivado da severidade mais alta entre as portas abertas: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` ou `SAFE` quando nada responde.

```bash
curl -X POST https://sentinel-api.onrender.com/api/scan/ports \
  -H "Content-Type: application/json" \
  -d '{
    "target": "example.com",
    "ports": [21, 22, 80, 443, 3306],
    "timeout": 2.0
  }'
```

```json
{
  "target": "example.com",
  "open_ports": [
    {
      "port": 80,
      "service": "HTTP",
      "severity": "low",
      "cve": null,
      "description": "TrÃ¡fego HTTP nÃ£o criptografado."
    }
  ],
  "scan_duration": 1.24,
  "risk_level": "LOW",
  "timestamp": "2026-10-13T16:11:13"
}
```

### `GET /api/scan/ssl`

```bash
curl "https://sentinel-api.onrender.com/api/scan/ssl?hostname=example.com"
```

Retorna validade, data de expiraÃ§Ã£o, dias restantes, emissor, versÃ£o de protocolo, nÃ­vel de risco e a lista de problemas encontrados.

### `GET /`

```bash
curl https://sentinel-api.onrender.com/
```

```json
{
  "service": "SENTINEL Security Platform",
  "version": "1.0.0",
  "status": "operational"
}
```

---

## Base de conhecimento de portas

Cada porta aberta Ã© confrontada com uma tabela de serviÃ§os que carrega severidade, descriÃ§Ã£o, CVE quando aplicÃ¡vel e recomendaÃ§Ã£o de correÃ§Ã£o. Trecho da base:

| Porta | ServiÃ§o | Severidade | CVE | RemediaÃ§Ã£o |
| --- | --- | --- | --- | --- |
| 21 | FTP | HIGH | CVE-2023-1234 | Migre para SFTP ou FTPS |
| 23 | Telnet | CRITICAL | CVE-2022-5678 | Desabilite e migre para SSH |
| 445 | SMB | CRITICAL | CVE-2017-0144 | Aplique MS17-010, desabilite SMBv1 |
| 1433 | MSSQL | CRITICAL | â€” | Restrinja ao localhost e aplique firewall |
| 3306 | MySQL | CRITICAL | CVE-2023-9999 | Restrinja Ã  rede interna |
| 3389 | RDP | HIGH | CVE-2019-0708 | VPN obrigatÃ³ria antes do RDP |
| 5432 | PostgreSQL | CRITICAL | â€” | Restrinja via `pg_hba.conf` |
| 5900 | VNC | HIGH | â€” | Acesso por VPN com autenticaÃ§Ã£o forte |
| 6379 | Redis | CRITICAL | CVE-2022-0543 | Configure `requirepass` e bind em localhost |

> **Os identificadores CVE sÃ£o ilustrativos.** Servem para demonstrar a estrutura do achado e do relatÃ³rio; nÃ£o foram validados contra o NVD. Antes de usar a classificaÃ§Ã£o como referÃªncia, substitua-os por identificadores verificados â€” ou remova o campo e mantenha apenas severidade e remediaÃ§Ã£o, que sÃ£o corretas.

### DivergÃªncia conhecida entre as duas bases

`api/main.py` e `scanner/scanner.py` mantÃªm tabelas independentes, e elas **jÃ¡ divergem**: a porta 21 Ã© `high` na API e `critical` no CLI, e a cobertura nÃ£o Ã© a mesma (a API parte de 9 portas, o CLI de 20). O mesmo alvo pode receber classificaÃ§Ãµes diferentes conforme o ponto de entrada. A correÃ§Ã£o Ã© o mÃ³dulo compartilhado `sentinel_core/` descrito no roadmap.

---

## O que Ã© funcional e o que Ã© demonstraÃ§Ã£o

| Componente | Estado | ObservaÃ§Ã£o |
| --- | --- | --- |
| Varredura de portas (API e CLI) | **Funcional** | Abre conexÃµes TCP reais; reporta apenas portas que responderam |
| Auditoria TLS | **Funcional** | Handshake real, leitura do certificado e cÃ¡lculo de expiraÃ§Ã£o |
| ClassificaÃ§Ã£o de severidade | **Funcional** | Aplicada sobre o resultado efetivamente obtido |
| RelatÃ³rio JSON e score de risco | **Funcional** | Derivados dos achados da execuÃ§Ã£o |
| Agregados e feed do dashboard | **DemonstraÃ§Ã£o** | Valores estÃ¡ticos na interface, sem coleta em segundo plano |
| Top Threat IPs do dashboard | **DemonstraÃ§Ã£o** | Lista fixa; os endereÃ§os sÃ£o exemplos e blocos reservados para documentaÃ§Ã£o |
| `/api/threat/intel` e `/api/threat/stats` | **DemonstraÃ§Ã£o** | NÃ£o consultam base externa de threat intelligence |

A fronteira Ã© deliberada e estÃ¡ registrada aqui para que ninguÃ©m dimensione o projeto por engano â€” nem para cima, nem para baixo. O nÃºcleo faz trabalho de rede real; a camada visual Ã© demonstraÃ§Ã£o e se identifica como tal na prÃ³pria interface.

---

## Hardening pendente

Itens levantados na revisÃ£o do prÃ³prio cÃ³digo, em ordem de prioridade. **Enquanto o primeiro nÃ£o for resolvido, a API pÃºblica nÃ£o deve permanecer no ar.**

| # | Item | SituaÃ§Ã£o | AÃ§Ã£o | Estado |
| --- | --- | --- | --- | --- |
| 1 | **CORS** | `allow_origins=["*"]` com todos os mÃ©todos e headers | Restringir Ã  origem do dashboard via variÃ¡vel de ambiente | MÃ³dulo pronto, nÃ£o registrado |
| 2 | **AutenticaÃ§Ã£o** | Ausente | Chave de API obrigatÃ³ria nos endpoints de varredura | MÃ³dulo pronto, nÃ£o registrado |
| 3 | **Rate limiting** | Ausente | Limite por IP, com janela deslizante | MÃ³dulo pronto, nÃ£o registrado |
| 4 | **AutorizaÃ§Ã£o de alvo** | Apenas validaÃ§Ã£o de formato | Bloquear faixas que nÃ£o pertencem ao operador | Pendente |
| 5 | **DivergÃªncia das bases** | Porta 21 classificada de forma diferente na API e no CLI | Unificar em `sentinel_core/` | Pendente |
| 6 | **Tratamento de exceÃ§Ãµes** | `except Exception: pass` engole falha de socket | Logar em nÃ­vel debug e contabilizar por porta | Pendente |

Os itens 1, 2 e 3 estÃ£o implementados em `api/security.py`, que ainda **nÃ£o foi adicionado ao repositÃ³rio** e nÃ£o Ã© importado por `api/main.py`. Enquanto o registro nÃ£o acontecer, o comportamento em produÃ§Ã£o permanece o descrito na coluna "SituaÃ§Ã£o".

O risco combinado de 1, 2 e 3 Ã© concreto: qualquer origem na internet pode disparar varreduras a partir da infraestrutura do projeto, sem autenticaÃ§Ã£o e sem limite. Isso desloca a responsabilidade legal do atacante para o operador da API.

ConfiguraÃ§Ã£o pretendida, jÃ¡ suportada por `security.py`:

```bash
# .env â€” nunca versionado
SENTINEL_ALLOWED_ORIGINS=https://sentinel-sec.vercel.app
SENTINEL_API_KEY=<chave-gerada>
```

---

## Deploy

TrÃªs arquivos de configuraÃ§Ã£o coexistem na raiz. Os serviÃ§os em uso hoje:

| Alvo | Arquivo | Estado |
| --- | --- | --- |
| API | `render.yaml`, `Procfile`, `nixpacks.toml`, `runtime.txt` | Ativo |
| Dashboard | `vercel.json` | Ativo |
| API (alternativa) | `railway.json` | NÃ£o utilizado |

### API â€” Render

`render.yaml` descreve o serviÃ§o; com o repositÃ³rio conectado, cada push na `main` dispara deploy.

```yaml
services:
  - type: web
    name: sentinel-api
    runtime: python
    buildCommand: pip install -r requirements.txt
    startCommand: uvicorn api.main:app --host 0.0.0.0 --port $PORT
```

### Dashboard â€” Vercel

`vercel.json` publica `dashboard/` como site estÃ¡tico. Importar o repositÃ³rio no Vercel Ã© suficiente; nÃ£o hÃ¡ configuraÃ§Ã£o adicional.

### VariÃ¡veis de ambiente

| VariÃ¡vel | ObrigatÃ³ria | Finalidade |
| --- | --- | --- |
| `SENTINEL_ALLOWED_ORIGINS` | sim (apÃ³s o hardening) | Origens autorizadas no CORS |
| `SENTINEL_API_KEY` | sim (apÃ³s o hardening) | Chave exigida nos endpoints de varredura |
| `SENTINEL_RATE_WINDOW` | nÃ£o (`60`) | Janela do rate limit, em segundos |
| `SENTINEL_RATE_MAX` | nÃ£o (`30`) | RequisiÃ§Ãµes por janela, por IP |
| `SENTINEL_RATE_DISABLED` | nÃ£o | `1` desliga o rate limit em desenvolvimento e no CI |

---

## Testes e integraÃ§Ã£o contÃ­nua

O workflow em `.github/workflows/ci.yml` roda em cada push e pull request contra `main`, em Python 3.10, 3.11 e 3.12:

1. VerificaÃ§Ã£o de sintaxe e importaÃ§Ã£o de `api/` e `scanner/`
2. Lint com Ruff
3. Subida da API e validaÃ§Ã£o do health check
4. Leitura do `openapi.json` e conferÃªncia de que as rotas foram documentadas

> O workflow **ainda nÃ£o estÃ¡ no repositÃ³rio**. Enquanto nÃ£o for adicionado, o GitHub sugere configuraÃ§Ãµes prontas de Python na aba Actions â€” vale usar o workflow versionado, que roda as quatro etapas acima em vez de um lint isolado.

```bash
# Mesmas verificaÃ§Ãµes, localmente
python -m compileall -q api scanner
ruff check api scanner
uvicorn api.main:app --port 8000 &
curl -sf http://localhost:8000/ && echo "OK"
```

Os testes automatizados de comportamento (varredura contra alvo controlado, parsing do relatÃ³rio, derivaÃ§Ã£o do score) ainda nÃ£o existem â€” estÃ£o no roadmap. O CI atual garante que a aplicaÃ§Ã£o importa, sobe e documenta suas rotas, que Ã© o piso mÃ­nimo.

---

## Roadmap

- [ ] Adicionar `api/security.py` ao repositÃ³rio e registrÃ¡-lo em `api/main.py`
- [ ] Adicionar `.github/workflows/ci.yml` ao repositÃ³rio
- [ ] Adicionar `docs/ARQUITETURA.md` ao repositÃ³rio
- [ ] Extrair `sentinel_core/` com o motor de varredura, a base de serviÃ§os e o modelo de risco, eliminando a duplicaÃ§Ã£o entre API e CLI
- [ ] Substituir os CVE ilustrativos por identificadores verificados ou remover o campo
- [ ] SuÃ­te de testes com `pytest` e alvo controlado em container
- [ ] Descoberta de hosts por faixa CIDR, em vez de alvo Ãºnico
- [ ] IdentificaÃ§Ã£o de serviÃ§o por banner grabbing, substituindo a inferÃªncia por porta
- [ ] ExportaÃ§Ã£o de relatÃ³rio em SARIF e Markdown para integraÃ§Ã£o em pipeline
- [ ] Capturas de tela do dashboard neste README

---

## Uso autorizado

Varredura apenas em sistemas prÃ³prios ou com **autorizaÃ§Ã£o escrita prÃ©via** do responsÃ¡vel. O acesso nÃ£o autorizado a sistema informatizado Ã© crime no Brasil â€” Lei 12.737/2012, art. 154-A do CÃ³digo Penal â€” e Ã© tipificado em praticamente todas as jurisdiÃ§Ãµes relevantes.

A ferramenta foi construÃ­da para laboratÃ³rio prÃ³prio, ambiente de teste autorizado e estudo de seguranÃ§a. O autor nÃ£o se responsabiliza pelo uso indevido nem por danos decorrentes dele.

---

## Autor

**Guilherme Augusto** â€” Cybersecurity Â· SOC Â· Pentesting Â· Security QA

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Guilherme_Augusto-0A66C2?style=flat-square&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/guilherme-augusto-966824234)

Contribuidor: **362514Gui** â€” correÃ§Ã£o da configuraÃ§Ã£o de deploy no Vercel.

---

## LicenÃ§a

MIT. Consulte [LICENSE](LICENSE).
