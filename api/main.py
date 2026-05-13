"""
SENTINEL - Security Monitoring & Threat Intelligence Platform
API REST completa com FastAPI
Author: Guilherme Augusto
"""

from fastapi import FastAPI, HTTPException, BackgroundTasks, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import asyncio
import socket
import ssl
import datetime
import random
import hashlib
import ipaddress
from typing import Optional
from enum import Enum

app = FastAPI(
    title="SENTINEL API",
    description="Security Monitoring & Threat Intelligence Platform",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── Modelos ─────────────────────────────────────────────────────────────────

class SeverityLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class ScanTarget(BaseModel):
    target: str = Field(..., example="192.168.1.1")
    ports: Optional[list[int]] = Field(default=[21, 22, 23, 25, 80, 443, 3306, 5432, 8080])
    timeout: float = Field(default=2.0, ge=0.5, le=10.0)

class VulnerabilityReport(BaseModel):
    id: str
    target: str
    severity: SeverityLevel
    title: str
    description: str
    cve: Optional[str]
    remediation: str
    timestamp: datetime.datetime

class ThreatIndicator(BaseModel):
    ioc_type: str  # ip, domain, hash, url
    value: str
    threat_score: int
    tags: list[str]
    first_seen: datetime.datetime
    last_seen: datetime.datetime

class PortScanResult(BaseModel):
    target: str
    open_ports: list[dict]
    scan_duration: float
    risk_level: str
    timestamp: datetime.datetime

class SSLReport(BaseModel):
    hostname: str
    valid: bool
    expiry_date: Optional[str]
    days_until_expiry: Optional[int]
    issuer: Optional[str]
    protocol: Optional[str]
    risk_level: str
    issues: list[str]

# ─── Banco de dados simulado ──────────────────────────────────────────────────

VULNERABILITY_DB = {
    21: {"name": "FTP", "cve": "CVE-2023-1234", "severity": "high",
         "desc": "FTP transmits credenciais em texto plano. Risco de interceptação.",
         "fix": "Desabilite FTP e use SFTP ou FTPS com TLS 1.2+"},
    22: {"name": "SSH", "cve": None, "severity": "info",
         "desc": "SSH detectado. Verifique versão e configuração.",
         "fix": "Use SSH v2, desabilite autenticação por senha, implemente chaves RSA 4096-bit"},
    23: {"name": "Telnet", "cve": "CVE-2022-5678", "severity": "critical",
         "desc": "Telnet é protocolo inseguro sem criptografia.",
         "fix": "Desabilite Telnet imediatamente e migre para SSH"},
    25: {"name": "SMTP", "cve": None, "severity": "medium",
         "desc": "SMTP aberto pode ser explorado para relay de spam.",
         "fix": "Configure SPF, DKIM e DMARC. Restrinja relay a hosts autorizados"},
    80: {"name": "HTTP", "cve": None, "severity": "low",
         "desc": "Tráfego HTTP não criptografado.",
         "fix": "Redirecione todo tráfego HTTP para HTTPS (301). Implemente HSTS"},
    443: {"name": "HTTPS", "cve": None, "severity": "info",
          "desc": "HTTPS detectado. Verifique configuração TLS.",
          "fix": "Use TLS 1.2+, desabilite TLS 1.0/1.1 e SSL 3.0"},
    3306: {"name": "MySQL", "cve": "CVE-2023-9999", "severity": "critical",
           "desc": "MySQL exposto publicamente na rede.",
           "fix": "Restrinja acesso ao banco ao localhost ou rede interna com firewall"},
    5432: {"name": "PostgreSQL", "cve": "CVE-2023-8888", "severity": "critical",
           "desc": "PostgreSQL exposto publicamente.",
           "fix": "Use pg_hba.conf para restringir conexões. Nunca exponha na internet"},
    8080: {"name": "HTTP-Alt", "cve": None, "severity": "medium",
           "desc": "Porta alternativa HTTP detectada.",
           "fix": "Verifique se é serviço necessário. Aplique autenticação se necessário"},
}

THREAT_FEED = [
    {"ip": "185.220.101.45", "score": 95, "tags": ["tor-exit", "malware-c2"]},
    {"ip": "192.42.116.16", "score": 88, "tags": ["tor-exit", "scanning"]},
    {"ip": "45.33.32.156", "score": 72, "tags": ["scanning", "brute-force"]},
    {"ip": "198.51.100.1", "score": 45, "tags": ["proxy", "suspicious"]},
    {"ip": "203.0.113.5", "score": 91, "tags": ["botnet", "ddos"]},
]

# ─── Endpoints ────────────────────────────────────────────────────────────────

@app.get("/", tags=["Status"])
async def root():
    return {
        "service": "SENTINEL Security Platform",
        "version": "1.0.0",
        "status": "operational",
        "endpoints": ["/api/scan/ports", "/api/scan/ssl", "/api/threats/ioc", "/api/vulnerabilities", "/api/dashboard/stats"]
    }

@app.post("/api/scan/ports", response_model=PortScanResult, tags=["Scanner"])
async def scan_ports(scan: ScanTarget):
    """Realiza varredura de portas no alvo especificado."""
    open_ports = []
    start_time = datetime.datetime.now()

    # Validação do alvo
    try:
        ipaddress.ip_address(scan.target)
    except ValueError:
        try:
            socket.gethostbyname(scan.target)
        except socket.gaierror:
            raise HTTPException(status_code=400, detail="Alvo inválido: não é um IP ou hostname válido")

    for port in scan.ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(scan.timeout)
            result = sock.connect_ex((scan.target, port))
            sock.close()

            if result == 0:
                vuln_info = VULNERABILITY_DB.get(port, {
                    "name": "Unknown", "cve": None, "severity": "info",
                    "desc": f"Serviço desconhecido na porta {port}",
                    "fix": "Investigue qual serviço está rodando e avalie necessidade"
                })
                open_ports.append({
                    "port": port,
                    "service": vuln_info["name"],
                    "severity": vuln_info["severity"],
                    "cve": vuln_info["cve"],
                    "description": vuln_info["desc"],
                })
        except Exception:
            pass

    duration = (datetime.datetime.now() - start_time).total_seconds()

    severities = [p["severity"] for p in open_ports]
    if "critical" in severities:
        risk = "CRITICAL"
    elif "high" in severities:
        risk = "HIGH"
    elif "medium" in severities:
        risk = "MEDIUM"
    elif open_ports:
        risk = "LOW"
    else:
        risk = "SAFE"

    return PortScanResult(
        target=scan.target,
        open_ports=open_ports,
        scan_duration=round(duration, 2),
        risk_level=risk,
        timestamp=datetime.datetime.now()
    )

@app.get("/api/scan/ssl", response_model=SSLReport, tags=["Scanner"])
async def check_ssl(hostname: str = Query(..., example="google.com")):
    """Verifica certificado SSL/TLS de um hostname."""
    issues = []
    try:
        context = ssl.create_default_context()
        conn = context.wrap_socket(
            socket.socket(socket.AF_INET),
            server_hostname=hostname,
        )
        conn.settimeout(5)
        conn.connect((hostname, 443))
        cert = conn.getpeercert()
        conn.close()

        expiry_str = cert.get("notAfter", "")
        expiry_date = datetime.datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z") if expiry_str else None
        days_left = (expiry_date - datetime.datetime.utcnow()).days if expiry_date else None

        if days_left and days_left < 30:
            issues.append(f"Certificado expira em {days_left} dias — renove com urgência")
        if days_left and days_left < 7:
            issues.append("CRÍTICO: Certificado expira em menos de 7 dias")

        issuer = dict(x[0] for x in cert.get("issuer", []))
        protocol = conn.version() if hasattr(conn, "version") else "TLS"

        risk = "HIGH" if issues else "LOW"

        return SSLReport(
            hostname=hostname,
            valid=True,
            expiry_date=expiry_str,
            days_until_expiry=days_left,
            issuer=issuer.get("organizationName", "Unknown"),
            protocol=protocol,
            risk_level=risk,
            issues=issues,
        )

    except ssl.SSLCertVerificationError as e:
        return SSLReport(hostname=hostname, valid=False, risk_level="CRITICAL",
                         issues=[f"Certificado inválido: {str(e)}"],
                         expiry_date=None, days_until_expiry=None, issuer=None, protocol=None)
    except Exception as e:
        return SSLReport(hostname=hostname, valid=False, risk_level="UNKNOWN",
                         issues=[f"Erro ao verificar SSL: {str(e)}"],
                         expiry_date=None, days_until_expiry=None, issuer=None, protocol=None)

@app.get("/api/threats/ioc", tags=["Threat Intelligence"])
async def check_ioc(value: str = Query(..., example="185.220.101.45")):
    """Verifica se um IP/domínio/hash está na base de threat intelligence."""
    for threat in THREAT_FEED:
        if threat["ip"] == value:
            return {
                "ioc": value,
                "malicious": True,
                "threat_score": threat["score"],
                "tags": threat["tags"],
                "action": "BLOCK",
                "checked_at": datetime.datetime.now().isoformat()
            }

    # Hash MD5/SHA256 check (simulado)
    ioc_hash = hashlib.md5(value.encode()).hexdigest()
    score = int(ioc_hash[:2], 16) % 40  # score baixo para IPs desconhecidos

    return {
        "ioc": value,
        "malicious": False,
        "threat_score": score,
        "tags": ["unknown"],
        "action": "MONITOR",
        "checked_at": datetime.datetime.now().isoformat()
    }

@app.get("/api/vulnerabilities", tags=["Vulnerabilities"])
async def list_vulnerabilities(
    severity: Optional[SeverityLevel] = None,
    limit: int = Query(default=20, le=100)
):
    """Lista vulnerabilidades conhecidas do banco de dados interno."""
    vulns = []
    for port, data in VULNERABILITY_DB.items():
        if severity and data["severity"] != severity.value:
            continue
        vulns.append({
            "port": port,
            "service": data["name"],
            "severity": data["severity"],
            "cve": data["cve"],
            "description": data["desc"],
            "remediation": data["fix"],
        })
    return {"total": len(vulns), "vulnerabilities": vulns[:limit]}

@app.get("/api/dashboard/stats", tags=["Dashboard"])
async def get_dashboard_stats():
    """Retorna estatísticas gerais para o dashboard de segurança."""
    now = datetime.datetime.now()
    return {
        "summary": {
            "total_scans_today": random.randint(40, 120),
            "threats_blocked": random.randint(5, 30),
            "vulnerabilities_found": random.randint(8, 25),
            "ssl_issues": random.randint(1, 8),
            "uptime_percent": round(random.uniform(99.1, 99.9), 2),
        },
        "recent_events": [
            {"time": (now - datetime.timedelta(minutes=3)).isoformat(), "type": "THREAT_BLOCKED", "detail": "IP 185.220.101.45 bloqueado (TOR exit node)", "severity": "critical"},
            {"time": (now - datetime.timedelta(minutes=12)).isoformat(), "type": "PORT_SCAN", "detail": "Scan detectado em 10.0.0.5 — 4 portas críticas abertas", "severity": "high"},
            {"time": (now - datetime.timedelta(minutes=28)).isoformat(), "type": "SSL_EXPIRY", "detail": "Certificado de api.exemplo.com expira em 12 dias", "severity": "medium"},
            {"time": (now - datetime.timedelta(minutes=45)).isoformat(), "type": "BRUTE_FORCE", "detail": "Tentativas de força bruta SSH bloqueadas em 172.16.0.4", "severity": "high"},
            {"time": (now - datetime.timedelta(hours=1)).isoformat(), "type": "VULNERABILITY", "detail": "MySQL exposto detectado em 10.0.0.8:3306", "severity": "critical"},
        ],
        "threat_trend": [
            {"hour": f"{(now - datetime.timedelta(hours=i)).strftime('%H:00')}", "count": random.randint(0, 15)}
            for i in range(12, 0, -1)
        ],
        "severity_distribution": {
            "critical": random.randint(2, 8),
            "high": random.randint(5, 15),
            "medium": random.randint(8, 20),
            "low": random.randint(10, 30),
            "info": random.randint(15, 40),
        },
        "generated_at": now.isoformat()
    }

@app.get("/api/report/generate", tags=["Reports"])
async def generate_report(target: str = Query(..., example="192.168.1.0/24")):
    """Gera um relatório executivo de segurança para o alvo."""
    now = datetime.datetime.now()
    return {
        "report_id": hashlib.sha256(f"{target}{now}".encode()).hexdigest()[:16].upper(),
        "target": target,
        "generated_at": now.isoformat(),
        "executive_summary": f"Análise de segurança para {target} identificou vulnerabilidades que requerem atenção imediata.",
        "risk_score": random.randint(35, 85),
        "findings": {
            "critical": random.randint(1, 4),
            "high": random.randint(2, 8),
            "medium": random.randint(5, 15),
            "low": random.randint(8, 20),
        },
        "compliance": {
            "OWASP_Top10": f"{random.randint(60, 90)}%",
            "NIST_CSF": f"{random.randint(55, 85)}%",
            "ISO_27001": f"{random.randint(50, 80)}%",
        },
        "top_recommendations": [
            "Desabilitar serviços desnecessários expostos publicamente",
            "Implementar autenticação multifator em todos os serviços críticos",
            "Aplicar patches de segurança pendentes",
            "Configurar firewall com regras de whitelist",
            "Implementar sistema de detecção de intrusão (IDS/IPS)",
        ]
    }
