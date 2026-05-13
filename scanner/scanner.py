"""
SENTINEL - Automated Security Scanner
Script de automação para varredura contínua de segurança
Author: Guilherme Augusto
"""

import asyncio
import socket
import ssl
import json
import hashlib
import datetime
import ipaddress
import argparse
import sys
from typing import Optional
from dataclasses import dataclass, asdict

# ─── Cores ANSI para terminal ──────────────────────────────────────────────────

class Colors:
    RED      = "\033[91m"
    ORANGE   = "\033[38;5;208m"
    YELLOW   = "\033[93m"
    GREEN    = "\033[92m"
    CYAN     = "\033[96m"
    BLUE     = "\033[94m"
    MAGENTA  = "\033[95m"
    WHITE    = "\033[97m"
    GRAY     = "\033[90m"
    BOLD     = "\033[1m"
    RESET    = "\033[0m"

# ─── Modelos de dados ──────────────────────────────────────────────────────────

@dataclass
class PortFinding:
    port: int
    service: str
    severity: str
    description: str
    remediation: str
    cve: Optional[str] = None

@dataclass
class ScanReport:
    target: str
    timestamp: str
    duration_seconds: float
    open_ports: list
    ssl_issues: list
    risk_level: str
    risk_score: int
    total_findings: int

# ─── Banco de vulnerabilidades ─────────────────────────────────────────────────

VULN_DB = {
    21:   ("FTP",        "critical", "CVE-2023-1234", "Protocolo sem criptografia, credenciais expostas",        "Migre para SFTP/FTPS"),
    22:   ("SSH",        "info",     None,             "Verifique versão e política de acesso",                   "Use chaves RSA 4096-bit, desabilite senha"),
    23:   ("Telnet",     "critical", "CVE-2022-5678", "Protocolo completamente inseguro",                        "Desabilite imediatamente, use SSH"),
    25:   ("SMTP",       "medium",   None,             "Verifique relay aberto e autenticação",                   "Configure SPF, DKIM, DMARC"),
    53:   ("DNS",        "medium",   None,             "Servidor DNS público pode permitir zone transfer",        "Restrinja zone transfer a servidores autorizados"),
    80:   ("HTTP",       "low",      None,             "Tráfego sem criptografia",                                "Redirecione para HTTPS, implemente HSTS"),
    110:  ("POP3",       "high",     None,             "Protocolo de email sem criptografia",                     "Use POP3S (porta 995)"),
    143:  ("IMAP",       "high",     None,             "Protocolo de email sem criptografia",                     "Use IMAPS (porta 993)"),
    443:  ("HTTPS",      "info",     None,             "Verifique versão TLS e certificado",                      "Use TLS 1.2+, desabilite versões antigas"),
    445:  ("SMB",        "critical", "CVE-2017-0144",  "EternalBlue — vulnerabilidade crítica de ransomware",    "Patch MS17-010, desabilite SMBv1"),
    1433: ("MSSQL",      "critical", None,             "Banco de dados exposto publicamente",                     "Restrinja ao localhost, use firewall"),
    3306: ("MySQL",      "critical", "CVE-2023-9999", "Banco de dados exposto na internet",                      "Bloqueie porta, use rede interna"),
    3389: ("RDP",        "high",     "CVE-2019-0708",  "BlueKeep — RDP exposto permite execução remota",        "VPN obrigatória antes do RDP, patch MS19-0708"),
    5432: ("PostgreSQL", "critical", None,             "Banco de dados exposto publicamente",                     "Restrinja via pg_hba.conf"),
    5900: ("VNC",        "high",     None,             "Acesso remoto de desktop exposto",                       "Use VPN, implemente autenticação forte"),
    6379: ("Redis",      "critical", "CVE-2022-0543", "Redis sem autenticação permite execução de comandos",     "Configure requirepass, bind somente localhost"),
    8080: ("HTTP-Alt",   "medium",   None,             "Porta HTTP alternativa detectada",                       "Avalie necessidade, aplique autenticação"),
    8443: ("HTTPS-Alt",  "info",     None,             "Porta HTTPS alternativa",                                "Verifique configuração TLS"),
    9200: ("Elasticsearch","critical",None,            "Elasticsearch sem autenticação expõe todos os dados",    "Ative X-Pack security, use firewall"),
    27017:("MongoDB",    "critical", None,             "MongoDB sem autenticação exposta na internet",           "Configure autenticação, restrinja ao localhost"),
}

SEVERITY_COLOR = {
    "critical": Colors.RED,
    "high":     Colors.ORANGE,
    "medium":   Colors.YELLOW,
    "low":      Colors.CYAN,
    "info":     Colors.GRAY,
}

SEVERITY_SCORE = {
    "critical": 40,
    "high":     20,
    "medium":   10,
    "low":      5,
    "info":     1,
}

# ─── Banner ────────────────────────────────────────────────────────────────────

def print_banner():
    banner = f"""
{Colors.RED}{Colors.BOLD}
 ██████  ███████ ███    ██ ████████ ██ ███    ██ ███████ ██     
██      ██      ████   ██    ██    ██ ████   ██ ██      ██     
███████ █████   ██ ██  ██    ██    ██ ██ ██  ██ █████   ██     
     ██ ██      ██  ██ ██    ██    ██ ██  ██ ██ ██      ██     
███████ ███████ ██   ████    ██    ██ ██   ████ ███████ ███████
{Colors.RESET}
{Colors.GRAY}  Security Monitoring & Automation Platform{Colors.RESET}
{Colors.GRAY}  Author: Guilherme Augusto | Cybersecurity Engineer{Colors.RESET}
{Colors.GRAY}  ─────────────────────────────────────────────────{Colors.RESET}
"""
    print(banner)

# ─── Scanner assíncrono de portas ──────────────────────────────────────────────

async def scan_port(host: str, port: int, timeout: float) -> Optional[PortFinding]:
    """Tenta conexão TCP assíncrona na porta especificada."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout
        )
        writer.close()
        await writer.wait_closed()

        vuln = VULN_DB.get(port)
        if vuln:
            name, severity, cve, desc, fix = vuln
        else:
            name, severity, cve = "Unknown", "info", None
            desc = f"Serviço desconhecido na porta {port}"
            fix = "Investigue qual serviço está rodando"

        return PortFinding(
            port=port,
            service=name,
            severity=severity,
            description=desc,
            remediation=fix,
            cve=cve,
        )
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return None

async def run_port_scan(host: str, ports: list[int], timeout: float = 1.5) -> list[PortFinding]:
    """Executa varredura paralela de portas."""
    tasks = [scan_port(host, port, timeout) for port in ports]
    results = await asyncio.gather(*tasks)
    return [r for r in results if r is not None]

# ─── Verificador SSL ───────────────────────────────────────────────────────────

def check_ssl_certificate(hostname: str, port: int = 443) -> dict:
    """Analisa certificado SSL/TLS do host."""
    issues = []
    result = {"hostname": hostname, "valid": False, "issues": issues}

    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                protocol = ssock.version()

                expiry_str = cert.get("notAfter", "")
                if expiry_str:
                    expiry = datetime.datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z")
                    days_left = (expiry - datetime.datetime.utcnow()).days
                    result["expiry_date"] = expiry_str
                    result["days_until_expiry"] = days_left

                    if days_left < 0:
                        issues.append("CRÍTICO: Certificado EXPIRADO")
                    elif days_left < 7:
                        issues.append(f"CRÍTICO: Expira em {days_left} dias")
                    elif days_left < 30:
                        issues.append(f"ALERTA: Expira em {days_left} dias")

                result["protocol"] = protocol
                if protocol in ("TLSv1", "TLSv1.1", "SSLv2", "SSLv3"):
                    issues.append(f"Protocolo obsoleto detectado: {protocol}")

                issuer = dict(x[0] for x in cert.get("issuer", []))
                result["issuer"] = issuer.get("organizationName", "Unknown")
                result["valid"] = True

    except ssl.SSLCertVerificationError as e:
        issues.append(f"Certificado inválido: {e}")
    except ssl.SSLError as e:
        issues.append(f"Erro SSL: {e}")
    except (socket.timeout, ConnectionRefusedError):
        issues.append("Porta 443 inacessível")
    except Exception as e:
        issues.append(f"Erro: {e}")

    result["risk_level"] = "CRITICAL" if any("CRÍTICO" in i for i in issues) else \
                           "HIGH" if issues else "LOW"
    return result

# ─── Geração de relatório ──────────────────────────────────────────────────────

def calculate_risk(findings: list[PortFinding]) -> tuple[str, int]:
    score = sum(SEVERITY_SCORE.get(f.severity, 0) for f in findings)
    score = min(score, 100)

    if score >= 60:   return "CRITICAL", score
    elif score >= 40: return "HIGH", score
    elif score >= 20: return "MEDIUM", score
    elif score >= 5:  return "LOW", score
    return "SAFE", score

def print_section(title: str):
    print(f"\n{Colors.BOLD}{Colors.WHITE}{'─' * 60}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}  {title}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.WHITE}{'─' * 60}{Colors.RESET}")

def print_finding(finding: PortFinding, index: int):
    color = SEVERITY_COLOR.get(finding.severity, Colors.WHITE)
    sev_label = f"[{finding.severity.upper()}]".ljust(10)
    cve_str = f" {Colors.GRAY}({finding.cve}){Colors.RESET}" if finding.cve else ""

    print(f"\n  {Colors.GRAY}{index}.{Colors.RESET} {color}{Colors.BOLD}{sev_label}{Colors.RESET} "
          f"Port {finding.port}/{finding.service}{cve_str}")
    print(f"     {Colors.WHITE}⚠  {finding.description}{Colors.RESET}")
    print(f"     {Colors.GREEN}✓  {finding.remediation}{Colors.RESET}")

def save_report(report: ScanReport, filename: str):
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(asdict(report), f, indent=2, default=str)
    print(f"\n  {Colors.GREEN}✓ Relatório salvo em: {Colors.BOLD}{filename}{Colors.RESET}")

# ─── Função principal ──────────────────────────────────────────────────────────

async def main_scan(target: str, ports: list[int], timeout: float, output: Optional[str]):
    print_banner()

    # Resolução de hostname
    try:
        ipaddress.ip_address(target)
        host_ip = target
    except ValueError:
        try:
            host_ip = socket.gethostbyname(target)
            print(f"  {Colors.GRAY}Hostname resolvido: {target} → {host_ip}{Colors.RESET}")
        except socket.gaierror:
            print(f"  {Colors.RED}✗ Erro: Não foi possível resolver '{target}'{Colors.RESET}")
            sys.exit(1)

    print(f"\n  {Colors.CYAN}Alvo:{Colors.RESET}    {Colors.BOLD}{target}{Colors.RESET}")
    print(f"  {Colors.CYAN}Portas:{Colors.RESET}  {len(ports)} portas")
    print(f"  {Colors.CYAN}Timeout:{Colors.RESET} {timeout}s por porta")
    print(f"  {Colors.CYAN}Início:{Colors.RESET}  {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # ── Port Scan ──
    print_section("VARREDURA DE PORTAS")
    print(f"  {Colors.GRAY}Escaneando {len(ports)} portas em paralelo...{Colors.RESET}")

    start = datetime.datetime.now()
    findings = await run_port_scan(host_ip, ports, timeout)
    duration = (datetime.datetime.now() - start).total_seconds()

    if not findings:
        print(f"\n  {Colors.GREEN}✓ Nenhuma porta aberta detectada nos alvos selecionados.{Colors.RESET}")
    else:
        print(f"\n  {Colors.RED}✗ {len(findings)} porta(s) aberta(s) detectada(s):{Colors.RESET}")
        for i, finding in enumerate(sorted(findings, key=lambda x: SEVERITY_SCORE.get(x.severity, 0), reverse=True), 1):
            print_finding(finding, i)

    # ── SSL Check ──
    print_section("VERIFICAÇÃO SSL/TLS")
    ssl_result = check_ssl_certificate(target)

    if ssl_result["valid"]:
        print(f"\n  {Colors.GREEN}✓ Certificado válido{Colors.RESET}")
        print(f"  {Colors.GRAY}  Emissor:  {ssl_result.get('issuer', 'N/A')}{Colors.RESET}")
        print(f"  {Colors.GRAY}  Protocolo: {ssl_result.get('protocol', 'N/A')}{Colors.RESET}")
        print(f"  {Colors.GRAY}  Validade:  {ssl_result.get('days_until_expiry', 'N/A')} dias restantes{Colors.RESET}")
    else:
        print(f"\n  {Colors.ORANGE}⚠ Problema com SSL detectado{Colors.RESET}")

    if ssl_result["issues"]:
        for issue in ssl_result["issues"]:
            print(f"  {Colors.RED}  ✗ {issue}{Colors.RESET}")

    # ── Relatório Final ──
    risk_level, risk_score = calculate_risk(findings)
    risk_color = {"CRITICAL": Colors.RED, "HIGH": Colors.ORANGE, "MEDIUM": Colors.YELLOW,
                  "LOW": Colors.CYAN, "SAFE": Colors.GREEN}.get(risk_level, Colors.WHITE)

    print_section("RESUMO EXECUTIVO")
    print(f"\n  {Colors.BOLD}Alvo analisado:{Colors.RESET}    {target}")
    print(f"  {Colors.BOLD}Duração do scan:{Colors.RESET}   {duration:.2f}s")
    print(f"  {Colors.BOLD}Portas abertas:{Colors.RESET}    {len(findings)}")
    print(f"  {Colors.BOLD}Problemas SSL:{Colors.RESET}     {len(ssl_result['issues'])}")
    print(f"  {Colors.BOLD}Nível de risco:{Colors.RESET}    {risk_color}{Colors.BOLD}{risk_level}{Colors.RESET}")
    print(f"  {Colors.BOLD}Score de risco:{Colors.RESET}    {risk_color}{risk_score}/100{Colors.RESET}")

    # Barra de risco visual
    bar_filled = int(risk_score / 5)
    bar = "█" * bar_filled + "░" * (20 - bar_filled)
    print(f"\n  {Colors.GRAY}Risco: {risk_color}[{bar}]{Colors.RESET} {risk_color}{risk_score}%{Colors.RESET}")

    # Salvar relatório
    report = ScanReport(
        target=target,
        timestamp=datetime.datetime.now().isoformat(),
        duration_seconds=round(duration, 2),
        open_ports=[asdict(f) for f in findings],
        ssl_issues=ssl_result.get("issues", []),
        risk_level=risk_level,
        risk_score=risk_score,
        total_findings=len(findings),
    )

    if output:
        save_report(report, output)
    else:
        default_file = f"sentinel_report_{target.replace('.', '_')}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        save_report(report, default_file)

    print(f"\n{Colors.GRAY}{'═' * 60}{Colors.RESET}\n")
    return report

# ─── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="SENTINEL - Automated Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos de uso:
  python scanner.py --target 192.168.1.1
  python scanner.py --target example.com --ports 80 443 22 3306
  python scanner.py --target 10.0.0.1 --timeout 2 --output report.json
        """
    )
    parser.add_argument("--target",  required=True, help="IP ou hostname alvo")
    parser.add_argument("--ports",   nargs="+", type=int,
                        default=[21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
                                 1433, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017],
                        help="Lista de portas para escanear")
    parser.add_argument("--timeout", type=float, default=1.5, help="Timeout por porta (segundos)")
    parser.add_argument("--output",  help="Arquivo de saída do relatório JSON")

    args = parser.parse_args()
    asyncio.run(main_scan(args.target, args.ports, args.timeout, args.output))
