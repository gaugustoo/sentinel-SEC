"""
SENTINEL - Camada de segurança da API

CORS restrito, autenticação por chave e rate limiting por IP.

Author: Guilherme Augusto
"""

import os
import time
from collections import defaultdict, deque
from typing import Optional

from fastapi import Header, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware

# ─── Configuração ─────────────────────────────────────────────────────────────

def _split_env(name: str, default: str = "") -> list[str]:
    """Lê uma variável de ambiente em formato de lista separada por vírgula."""
    raw = os.getenv(name, default)
    return [item.strip() for item in raw.split(",") if item.strip()]


ALLOWED_ORIGINS: list[str] = _split_env(
    "SENTINEL_ALLOWED_ORIGINS",
    "http://localhost:8000,http://127.0.0.1:8000,http://localhost:5500",
)

API_KEY: Optional[str] = os.getenv("SENTINEL_API_KEY") or None

# Limite por IP: janela deslizante em segundos e requisições permitidas
RATE_LIMIT_WINDOW: int = int(os.getenv("SENTINEL_RATE_WINDOW", "60"))
RATE_LIMIT_MAX: int = int(os.getenv("SENTINEL_RATE_MAX", "30"))

# O desligamento do rate limit existe para desenvolvimento local e para o CI.
# Em produção, mantenha a variável ausente.
RATE_LIMIT_ENABLED: bool = os.getenv("SENTINEL_RATE_DISABLED", "").lower() not in ("1", "true", "yes")


# ─── CORS ─────────────────────────────────────────────────────────────────────

def install_cors(app) -> None:
    """
    Aplica o middleware de CORS com origens explícitas.

    Substitui o `allow_origins=["*"]` anterior: em uma API que dispara conexões
    de rede, origem aberta significa que qualquer página na internet pode usar a
    infraestrutura do serviço para varrer terceiros.
    """
    app.add_middleware(
        CORSMiddleware,
        allow_origins=ALLOWED_ORIGINS,
        allow_credentials=False,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["Content-Type", "X-API-Key"],
        max_age=600,
    )


# ─── Autenticação ─────────────────────────────────────────────────────────────

async def verify_api_key(x_api_key: Optional[str] = Header(default=None)) -> None:
    """
    Dependência de autenticação dos endpoints que executam varredura.

    Comportamento:
      - `SENTINEL_API_KEY` definida  → a chave é obrigatória e comparada em tempo
        constante via `secrets.compare_digest`.
      - `SENTINEL_API_KEY` ausente   → a checagem é ignorada e a API permanece
        aberta (útil para desenvolvimento local), com aviso no log de inicialização.
    """
    import secrets

    if API_KEY is None:
        return

    if not x_api_key or not secrets.compare_digest(x_api_key, API_KEY):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Chave de API ausente ou inválida.",
            headers={"WWW-Authenticate": "X-API-Key"},
        )


# ─── Rate limiting ────────────────────────────────────────────────────────────

# Estado em memória: suficiente para uma instância única no tier gratuito.
# Com múltiplas réplicas, migre para Redis — cada processo tem seu próprio contador.
_hits: dict[str, deque[float]] = defaultdict(deque)


def _client_ip(request: Request) -> str:
    """Extrai o IP do cliente, respeitando o proxy do Render."""
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


async def rate_limit(request: Request) -> None:
    """
    Dependência de rate limiting por IP, com janela deslizante.

    Protege os endpoints de varredura contra uso automatizado e contra o custo de
    um alvo que não responde — cada porta aberta consome tempo de socket.
    """
    if not RATE_LIMIT_ENABLED:
        return

    ip = _client_ip(request)
    now = time.monotonic()
    window = _hits[ip]

    # Descarta marcas fora da janela
    while window and now - window[0] > RATE_LIMIT_WINDOW:
        window.popleft()

    if len(window) >= RATE_LIMIT_MAX:
        retry_after = int(RATE_LIMIT_WINDOW - (now - window[0])) + 1
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Limite de {RATE_LIMIT_MAX} requisições por {RATE_LIMIT_WINDOW}s excedido.",
            headers={"Retry-After": str(retry_after)},
        )

    window.append(now)


def rate_limit_status() -> dict:
    """Resumo da configuração de segurança, para o endpoint de status."""
    return {
        "cors_origins": ALLOWED_ORIGINS,
        "auth_required": API_KEY is not None,
        "rate_limit": {
            "enabled": RATE_LIMIT_ENABLED,
            "max_requests": RATE_LIMIT_MAX,
            "window_seconds": RATE_LIMIT_WINDOW,
        },
    }
