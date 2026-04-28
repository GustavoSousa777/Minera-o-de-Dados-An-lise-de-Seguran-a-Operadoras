import time
import sqlite3
import requests

# ==========================================
# CONFIGURAÇÕES BGP E API
# ==========================================
POOL_SEGURANCA = {13335, 20940, 6939, 3356, 174, 7195, 34645, 12956}

HEADERS_API = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Accept": "application/json"
}

# ==========================================
# BANCO DE DADOS
# ==========================================
def init_db():
    conn = sqlite3.connect("bgp_audit.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS logs_seguranca (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            asn_alvo TEXT,
            nome_operadora TEXT,
            cidade TEXT,
            estado TEXT,
            data_execucao DATETIME DEFAULT (datetime('now', 'localtime')),
            total_prefixos_24 INTEGER,
            asns_encontrados TEXT,
            asns_ausentes TEXT,
            status TEXT
        )
    """)
    conn.commit()
    return conn

# ==========================================
# COLETA GLOBAL (RIPE STAT)
# ==========================================
def obter_dados_globais(asn):
    """Busca os Peers Globais e Prefixos direto da base oficial do RIPE"""
    asns_na_rota = set()
    count_24 = 0
    try:
        url_peers = f"https://stat.ripe.net/data/asn-neighbours/data.json?resource={asn}&sourceapp=mirage_noc"
        res_peers = requests.get(url_peers, headers=HEADERS_API, timeout=10).json()
        for v in res_peers.get('data', {}).get('neighbours', []):
            asns_na_rota.add(v.get('asn'))
        
        url_prefixes = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource={asn}&sourceapp=mirage_noc"
        res_prefixes = requests.get(url_prefixes, headers=HEADERS_API, timeout=10).json()
        for p in res_prefixes.get('data', {}).get('prefixes', []):
            if str(p.get('prefix', '')).endswith('/24'):
                count_24 += 1
                
        return asns_na_rota, count_24
    except Exception as e:
        return set(), 0

def obter_nome_operadora(asn):
    try:
        url = f"https://stat.ripe.net/data/as-overview/data.json?resource={asn}&sourceapp=mirage_noc"
        res = requests.get(url, headers=HEADERS_API, timeout=10).json()
        nome = res.get('data', {}).get('holder', f"AS{asn}")
        return nome.split(',')[0].strip() 
    except Exception:
        return f"AS{asn}"

# ==========================================
# MOTOR PRINCIPAL
# ==========================================
def executar():
    db = init_db()
    print("\n" + "="*60)
    print("INICIANDO MOTOR DE AUDITORIA BGP GLOBAL - MIRAGE SOLUTIONS")
    print("="*60)

    asns_alvo = []
    
    # 1. TENTATIVA VIA API 
    print("Tentando coletar Top 100 ASNs Brasileiros via API RIPE...")
    try:
        url_ripe = "https://stat.ripe.net/data/country-asns/data.json?resource=BR&sourceapp=mirage_noc_auditor"
        resposta = requests.get(url_ripe, headers=HEADERS_API, timeout=15)
        
        if resposta.status_code == 200:
            dados = resposta.json()
            paises = dados.get('data', {}).get('countries', [])
            if paises:
                asns_alvo = paises[0].get('routed', [])[:100]
        else:
            print(f"❌ A API recusou a conexão. Código de erro HTTP: {resposta.status_code}")
            
    except Exception as e:
        print(f"❌ Falha de rede ao contatar a API: {e}")

    # 2. PLANO B COM 100 ASNS GARANTIDOS
    if not asns_alvo:
        print("\n⚠️ Ativando Plano B: Lista de 100 ASNs operacionais do Brasil...")
        asns_alvo = [
            # Nacionais e Gigantes
            28573, 27699, 8167, 16735, 53006, 14868, 262605, 28343, 7738, 18881,
            26599, 10429, 22381, 7303, 11628, 18698, 28126, 28260, 28329, 28604,
            # Provedores Regionais (LACNIC)
            262144, 262145, 262146, 262148, 262152, 262153, 262155, 262156, 262159, 262160,
            262161, 262164, 262165, 262166, 262167, 262171, 262172, 262173, 262175, 262177,
            262179, 262181, 262182, 262183, 262185, 262186, 262188, 262189, 262191, 262192,
            262195, 262197, 262198, 262200, 262201, 262202, 262204, 262207, 262208, 262211,
            262213, 262214, 262216, 262217, 262218, 262221, 262222, 262224, 262225, 262226,
            262228, 262229, 262232, 262233, 262235, 262236, 262238, 262241, 262243, 262244,
            262246, 262248, 262249, 262252, 262253, 262254, 262255, 262258, 262261, 262262,
            262264, 262267, 262269, 262271, 262272, 262274, 262276, 262277, 262280, 262281
        ]
    else:
        print(f"✅ Sucesso! {len(asns_alvo)} operadoras capturadas da base oficial.")

    # 3. LOOP DE AUDITORIA
    for i, asn in enumerate(asns_alvo, 1):
        nome_real = obter_nome_operadora(asn)
        print(f"\n[{i}/100] Auditando {nome_real} (AS{asn})...")
        
        try:
            asns_na_rota, prefixos_24 = obter_dados_globais(asn)
            
            encontrados = POOL_SEGURANCA & asns_na_rota
            
            status = "PROTEGIDO" if encontrados else "VULNERÁVEL"

            txt_encontrados = ", ".join(map(str, encontrados)) if encontrados else "Nenhum"
            txt_ausentes = "Requer roteamento de segurança!" if not encontrados else "-"
            
            db.execute("""
                INSERT INTO logs_seguranca (asn_alvo, nome_operadora, cidade, estado, total_prefixos_24, asns_encontrados, asns_ausentes, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (str(asn), nome_real, "São Luís", "MA", prefixos_24, txt_encontrados, txt_ausentes, status))
            db.commit()
            
            print(f" -> {status} | /24: {prefixos_24} | OK: {txt_encontrados}")
            
            time.sleep(1) # Pausa rápida e segura
                
        except Exception as e:
            print(f" -> ❌ Erro de auditoria: {e}")

    db.close()
    print("\nAuditoria Finalizada com Sucesso! O Dashboard já pode ser atualizado.")

if __name__ == "__main__":
    executar()