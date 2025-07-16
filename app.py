import asyncio
import socket
from collections import Counter, deque
from datetime import datetime

import dns.resolver
import httpx
from fastapi import FastAPI, Query, Request, Response
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from dnslib import DNSRecord, DNSHeader

# --- Configuração Inicial ---
app = FastAPI()
# Monta o diretório 'static' para servir o index.html
app.mount("/static", StaticFiles(directory="static"), name="static")

# --- Constantes e Configurações ---
UPSTREAM_DNS = "1.1.1.1"  # Servidor DNS da Cloudflare
MAX_LOG_SIZE = 1000
PROFILES = ["pessoal", "trabalho", "familia"] # Perfis de exemplo
BLOCKLIST_FRIENDLY_NAMES = {
    "https://easylist-downloads.adblockplus.org/easyprivacy.txt": "EasyPrivacy List",
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts": "StevenBlack Hosts",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/pro.plus.txt": "HaGeZi Pro++"
}

# --- Armazenamento de Dados em Memória ---
blocklists_sets = {url: set() for url in BLOCKLIST_FRIENDLY_NAMES}
query_logs = deque(maxlen=MAX_LOG_SIZE)


# --- Funções do Servidor ---

async def update_blocklists():
    """Baixa e processa CADA lista de bloqueio, adaptando-se ao formato."""
    print("Atualizando listas de bloqueio...")
    for url, friendly_name in BLOCKLIST_FRIENDLY_NAMES.items():
        print(f"- Processando '{friendly_name}'...")
        try:
            async with httpx.AsyncClient(timeout=60) as client:
                response = await client.get(url)
                response.raise_for_status()
            
            new_domains = set()
            lines = response.text.splitlines()
            
            for line in lines:
                # Ignora comentários, linhas vazias e regras de exceção/permissão
                if not line.strip() or line.startswith('!') or line.startswith('#') or '@@' in line:
                    continue

                # Formato Hosts (ex: 0.0.0.0 example.com)
                if line.startswith('0.0.0.0') or line.startswith('127.0.0.1'):
                    parts = line.split()
                    if len(parts) >= 2:
                        new_domains.add(parts[1].strip().lower())
                
                # Formato Adblock de Bloqueio de Domínio (ex: ||example.com^)
                elif line.startswith('||') and '^' in line:
                    # Extrai o domínio entre '||' e '^'
                    domain = line.split('||')[1].split('^')[0]
                    # Garante que é um domínio, não um caminho de URL
                    if '/' not in domain and '*' not in domain:
                        new_domains.add(domain.strip().lower())

            blocklists_sets[url] = new_domains
            print(f"  -> '{friendly_name}' atualizada com {len(new_domains)} domínios extraídos.")
        except httpx.RequestError as e:
            print(f"Erro ao baixar a lista '{friendly_name}': {e}")
        except Exception as e:
            print(f"Erro ao processar a lista '{friendly_name}': {e}")

def check_domain_block(domain: str) -> str | None:
    """Verifica se o domínio está em alguma lista e retorna a URL da lista."""
    domain_lower = domain.lower().rstrip('.')
    parts = domain_lower.split('.')
    for i in range(len(parts)):
        sub_domain = ".".join(parts[i:])
        for url, domain_set in blocklists_sets.items():
            if sub_domain in domain_set:
                return url
    return None

def log_query(qname: str, status: str, client_ip: str, profile: str, blocked_by: str = None):
    """Adiciona um registro de consulta à lista de logs em memória."""
    query_logs.append({
        "timestamp": datetime.now().isoformat(), "qname": qname, "status": status,
        "client_ip": client_ip, "profile": profile, "blocked_by": blocked_by
    })

def filter_logs_by_profile(logs, profile):
    if profile == 'all':
        return logs
    return [log for log in logs if log['profile'] == profile]

# --- Rotas da API para o Painel (Frontend) ---
@app.get("/api/profiles")
async def get_profiles():
    return PROFILES

@app.get("/api/stats/{profile:path}")
async def get_stats(profile: str):
    logs = filter_logs_by_profile(list(query_logs), profile)
    total_queries = len(logs)
    if total_queries == 0:
        return {"total_queries": 0, "blocked_queries": 0, "percent_blocked": 0, "top_queried": [], "top_blocked": [], "top_root": []}
    
    blocked_queries = sum(1 for log in logs if log['status'] == 'Bloqueado')
    queried_counter = Counter(log['qname'] for log in logs)
    blocked_counter = Counter(log['qname'] for log in logs if log['status'] == 'Bloqueado')
    def get_root_domain(domain):
        parts = domain.split('.')
        return '.'.join(parts[-2:]) if len(parts) >= 2 else domain
    root_counter = Counter(get_root_domain(log['qname']) for log in logs)
    
    return {
        "total_queries": total_queries, "blocked_queries": blocked_queries,
        "percent_blocked": (blocked_queries / total_queries * 100) if total_queries > 0 else 0,
        "top_queried": queried_counter.most_common(10), "top_blocked": blocked_counter.most_common(10), "top_root": root_counter.most_common(10),
    }

@app.get("/api/blocklist-stats/{profile:path}")
async def get_blocklist_stats(profile: str):
    logs = filter_logs_by_profile(list(query_logs), profile)
    filter_counter = Counter(log['blocked_by'] for log in logs if log.get('blocked_by'))
    return [{"name": name, "count": count} for name, count in filter_counter.items()]

@app.get("/api/query-log/{profile:path}")
async def get_query_log(profile: str):
    return {"logs": list(filter_logs_by_profile(query_logs, profile))}


# --- Rotas Principais do DNS ---
@app.on_event("startup")
async def on_startup(): await update_blocklists()

@app.get("/", response_class=FileResponse, include_in_schema=False)
async def read_index(): return "static/index.html"

@app.head("/", include_in_schema=False)
async def head_index(): return Response(headers={"content-type": "text/html; charset=utf-8"})

# Manipulador DoH para requisições GET com perfil
@app.get("/dns-query/{profile_name:path}", summary="DNS-over-HTTPS (RFC8484) - GET")
async def doh_get(request: Request, profile_name: str, name: str = Query(...), type: str = Query("A")):
    client_ip = request.client.host
    blocking_list_url = check_domain_block(name)
    if blocking_list_url:
        friendly_name = BLOCKLIST_FRIENDLY_NAMES.get(blocking_list_url, blocking_list_url)
        log_query(name, "Bloqueado", client_ip, profile_name, blocked_by=friendly_name)
        return JSONResponse(content={"Status": 3, "Question": [{"name": name, "type": dns.rdatatype.from_text(type)}]})
    try:
        resolver = dns.resolver.Resolver()
        answer = resolver.resolve(name, type.upper())
        log_query(name, "Encaminhado", client_ip, profile_name)
        result = {
            "Status": 0, "TC": False, "RD": True, "RA": True, "AD": False, "CD": False,
            "Question": [{"name": name, "type": dns.rdatatype.from_text(type.upper())}],
            "Answer": [{"name": r.name.to_text(), "type": dns.rdatatype.from_text(type.upper()), "TTL": r.ttl, "data": r.to_text()} for r in answer]
        }
        return JSONResponse(content=result)
    except Exception as e:
        log_query(name, "Erro", client_ip, profile_name, blocked_by=f"Resolver: {e}")
        return JSONResponse(status_code=500, content={"error": f"Erro ao resolver domínio: {e}"})

# Manipulador DoH para requisições POST com perfil
@app.post("/dns-query/{profile_name:path}", summary="DNS-over-HTTPS (RFC8484) - POST")
async def doh_post(request: Request, profile_name: str):
    client_ip = request.client.host
    qname = "Desconhecido"
    if request.headers.get("content-type") != "application/dns-message":
        return Response(status_code=415, content="Content-Type 'application/dns-message' esperado.")
    
    body = await request.body()
    if not body:
        return Response(status_code=400, content="O corpo da requisição POST está vazio.")
        
    try:
        dns_request = DNSRecord.parse(body)
        qname = str(dns_request.q.qname)
        
        blocking_list_url = check_domain_block(qname)
        if blocking_list_url:
            friendly_name = BLOCKLIST_FRIENDLY_NAMES.get(blocking_list_url, blocking_list_url)
            log_query(qname, "Bloqueado", client_ip, profile_name, blocked_by=friendly_name)
            header = DNSHeader(id=dns_request.header.id, qr=1, aa=1, rcode=3)
            response_record = DNSRecord(header, q=dns_request.q)
            return Response(content=response_record.pack(), media_type="application/dns-message")

        log_query(qname, "Encaminhado", client_ip, profile_name)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(5)
            s.sendto(body, (UPSTREAM_DNS, 53))
            dns_response, _ = s.recvfrom(4096)
        return Response(content=dns_response, media_type="application/dns-message")
    except Exception as e:
        log_query(qname, "Erro", client_ip, profile_name, blocked_by=f"Processamento: {e}")
        print(f"Erro ao processar a requisição POST para '{qname}': {e}")
        return Response(status_code=500, content="Erro interno do servidor.")
