# 🛡️ SENTINEL — Security Monitoring & Threat Intelligence Platform

<div align="center">

![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-009688?style=for-the-badge&logo=fastapi&logoColor=white)
![JavaScript](https://img.shields.io/badge/JavaScript-ES2024-F7DF1E?style=for-the-badge&logo=javascript&logoColor=black)
![Render](https://img.shields.io/badge/API-Render-46E3B7?style=for-the-badge&logo=render&logoColor=white)
![Vercel](https://img.shields.io/badge/Dashboard-Vercel-000000?style=for-the-badge&logo=vercel&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

**Plataforma open-source de monitoramento de segurança com API REST, dashboard interativo e automação de varredura.**

</div>

---

## 📋 Visão Geral

**SENTINEL** é uma plataforma de segurança ofensiva e defensiva para profissionais de **SOC**, **Pentesting** e **Security QA**.

| Componente | Tecnologia | Deploy | Função |
|---|---|---|---|
| `api/` | Python + FastAPI | **Render** | API REST para scans e threat intel |
| `scanner/` | Python asyncio | Local / CLI | Automação de varredura |
| `dashboard/` | HTML + CSS + JS | **Vercel** | Visualização em tempo real |

---

## 🚀 Deploy em Produção

### 🔵 API → Render (gratuito)

1. Acesse [render.com](https://render.com) e crie conta
2. Clique **New → Web Service** e conecte este repositório
3. Configure:
   - **Runtime:** Python 3
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `uvicorn api.main:app --host 0.0.0.0 --port $PORT`
4. Clique **Create Web Service**
5. URL gerada: `https://sentinel-api.onrender.com`

> ✅ O arquivo `render.yaml` na raiz já preenche tudo automaticamente.

### ⚫ Dashboard → Vercel (gratuito)

1. Acesse [vercel.com](https://vercel.com) e crie conta
2. Clique **Add New → Project** e importe este repositório
3. **Framework Preset:** Other — deixe raiz em branco
4. Clique **Deploy**
5. URL gerada: `https://sentinel-dashboard.vercel.app`

> ✅ O arquivo `vercel.json` na raiz já configura o build.

---

## 💻 Rodar Localmente

```bash
git clone https://github.com/guilherme-augusto/sentinel.git
cd sentinel
pip install -r requirements.txt
uvicorn api.main:app --reload --port 8000
# Docs: http://localhost:8000/api/docs
# Dashboard: abra dashboard/index.html no browser
```

---

## 📡 Endpoints da API

| Método | Endpoint | Descrição |
|--------|----------|-----------|
| `GET` | `/` | Status |
| `POST` | `/api/scan/ports` | Varredura de portas |
| `GET` | `/api/scan/ssl` | Verificação SSL/TLS |
| `GET` | `/api/threats/ioc` | Consulta de IoC |
| `GET` | `/api/vulnerabilities` | Lista CVEs |
| `GET` | `/api/dashboard/stats` | Stats do dashboard |
| `GET` | `/api/report/generate` | Relatório executivo |

---

## 🏗️ Estrutura

```
sentinel/
├── README.md
├── .gitignore
├── LICENSE
├── requirements.txt
├── render.yaml          ← deploy automático no Render
├── vercel.json          ← deploy automático no Vercel
├── api/
│   ├── main.py          ← FastAPI app completa
│   └── requirements.txt
├── scanner/
│   └── scanner.py       ← CLI scanner assíncrono
└── dashboard/
    └── index.html       ← Dashboard visual
```

---

## ⚠️ Aviso Legal

Use apenas em sistemas com permissão explícita. Este projeto é educacional.

---

## 👨‍💻 Autor

**Guilherme Augusto** — Cybersecurity · SOC · Pentesting · Security QA

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Guilherme_Augusto-0077B5?style=flat&logo=linkedin)](https://www.linkedin.com/in/guilherme-augusto-966824234)

---

MIT License
