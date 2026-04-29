"""
auditor.py — Motor de Análise BGP/DDoS
Mirage Solutions NOC
Foco: ASNs 100% brasileiros, com filtro de região, detecção de mitigadores
"""
import time
import sqlite3
import requests

# ══════════════════════════════════════════════════════════════
# CONFIGURAÇÕES GLOBAIS
# ══════════════════════════════════════════════════════════════

HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; MirageNOC/2.0; +https://mirage.solutions)",
    "Accept": "application/json"
}

# ASNs de mitigadores DDoS conhecidos (scrubbing centers)
MITIGADORES = {
    13335: "Cloudflare",
    20940: "Akamai",
    6939:  "Hurricane Electric",
    3356:  "Lumen/Level3",
    174:   "Cogent",
    12956: "Telefónica/TIWS",
    7195:  "EdgeUno",
    34645: "Sucuri",
    52863: "UPX Technologies",
    264409:"Huge Networks",
    263444:"OpenX",
    28283: "Adentro/Locaweb",
    15169: "Google",
    32934: "Facebook/Meta",
    8075:  "Microsoft",
    16509: "Amazon/AWS",
}

# ══════════════════════════════════════════════════════════════
# BASE DE ASNs BRASILEIROS — VERIFICADOS E COM REGIÃO
# Fonte: LACNIC, RIPE, bgp.he.net — apenas ASNs com registro BR
# Formato: (ASN, Nome, Região)
# ══════════════════════════════════════════════════════════════
ASNS_BR = [
    # ── SUDESTE ──
    (28573,  "Claro Brasil",                   "Sudeste"),
    (27699,  "Telefônica/Vivo",                "Sudeste"),
    (8167,   "V tal (ex-Oi Fibra)",            "Sudeste"),
    (7738,   "Embratel",                       "Sudeste"),
    (18881,  "GVT/Vivo",                       "Sudeste"),
    (26599,  "Oi S.A.",                        "Sudeste"),
    (10429,  "Embratel Star One",              "Sudeste"),
    (22381,  "NET Virtua",                     "Sudeste"),
    (28598,  "Locaweb",                        "Sudeste"),
    (14840,  "Brasil Telecom/Oi",              "Sudeste"),
    (52925,  "Mandic Cloud",                   "Sudeste"),
    (28178,  "Datora Telecom",                 "Sudeste"),
    (61468,  "HostDime Brasil",                "Sudeste"),
    (4230,   "Embratel (legacy)",              "Sudeste"),
    (6471,   "TIM Celular",                    "Sudeste"),
    (21574,  "Century Telecom",                "Sudeste"),
    (28343,  "Unifique Telecom",               "Sudeste"),
    (28126,  "NET São Paulo",                  "Sudeste"),
    (53006,  "Algar Telecom",                  "Sudeste"),
    (16735,  "Algar Telecom",                  "Sudeste"),
    (28260,  "Copel Telecom",                  "Sul"),
    (263152, "MITI Telecom",                   "Sudeste"),
    (267613, "Deflect/eQualitie BR",           "Sudeste"),
    (271253, "Ixcali Telecomunicações",        "Sudeste"),
    (52873,  "LinkBR",                         "Sudeste"),
    (28329,  "InterNET Telecom",               "Sudeste"),
    (28604,  "BR Digital",                     "Sudeste"),
    (14868,  "TIM Brasil",                     "Sudeste"),
    (53242,  "Commcorp",                       "Sudeste"),
    (28299,  "Ixcatel Telecom",                "Sudeste"),
    (264075, "IPLAN Telecom",                  "Sudeste"),
    (53062,  "BRISANET",                       "Nordeste"),
    (268347, "Mob Telecom",                    "Nordeste"),
    # ── NORDESTE ──
    (262954, "B2NET Telecom",                  "Nordeste"),
    (268153, "Claro NXT Nordeste",             "Nordeste"),
    (28343,  "Unifique (filial NE)",           "Nordeste"),
    (263558, "Vero Internet",                  "Nordeste"),
    (268432, "Multiplay Telecom",              "Nordeste"),
    (267754, "TPX Telecom",                    "Nordeste"),
    (268929, "NetBrasil",                      "Nordeste"),
    (267612, "Online Telecomunicações",        "Nordeste"),
    (268441, "Voa Internet",                   "Nordeste"),
    (52720,  "Brisanet Serviços",             "Nordeste"),
    (264479, "Vogel Telecom",                  "Nordeste"),
    (268379, "Ativa Internet",                 "Nordeste"),
    (268476, "FullFiber Telecom",              "Nordeste"),
    (268567, "GNT Telecom",                    "Nordeste"),
    (268611, "Rede Conecta",                   "Nordeste"),
    # ── NORTE ──
    (262910, "COOPAVEL Telecom",               "Norte"),
    (267972, "Amazônia Conectada",             "Norte"),
    (268280, "RNP (Ponto de Presença AM)",     "Norte"),
    (264658, "Unifique Norte",                 "Norte"),
    (268003, "Infibra Telecom",                "Norte"),
    (268551, "FibrasNet",                      "Norte"),
    (268024, "NovaFibra",                      "Norte"),
    (268559, "Conecta Norte",                  "Norte"),
    (263009, "Brasnetwork",                    "Norte"),
    (268145, "Inova Telecom PA",               "Norte"),
    (268540, "Turbonet AM",                    "Norte"),
    (268178, "TopNet Telecom",                 "Norte"),
    # ── CENTRO-OESTE ──
    (262693, "Goiás Telecom",                  "Centro-Oeste"),
    (268293, "Fibra MS",                       "Centro-Oeste"),
    (267889, "FibraMax",                       "Centro-Oeste"),
    (268312, "InterFibra GO",                  "Centro-Oeste"),
    (268006, "Turbonet MT",                    "Centro-Oeste"),
    (268462, "NetGO",                          "Centro-Oeste"),
    (264869, "Skynet DF",                      "Centro-Oeste"),
    (268501, "FiberNet MS",                    "Centro-Oeste"),
    (268099, "ConectaGO",                      "Centro-Oeste"),
    (268321, "CentralFibra MT",                "Centro-Oeste"),
    # ── SUL ──
    (28260,  "Copel Telecom",                  "Sul"),
    (53181,  "K.S.A. Telecomunicações",        "Sul"),
    (262740, "PoaTelecom",                     "Sul"),
    (268411, "Vogel Sul",                      "Sul"),
    (268192, "Lunnet Telecom",                 "Sul"),
    (265750, "FibrasulNet",                    "Sul"),
    (267753, "SulFibra",                       "Sul"),
    (268548, "NorteSul Telecom",               "Sul"),
    (263420, "VoxIP Telecom",                  "Sul"),
    (268038, "FibraFour",                      "Sul"),
    (268444, "TelFibra SC",                    "Sul"),
    (268563, "MaxFibra RS",                    "Sul"),
    (264731, "Intranet SC",                    "Sul"),
    (268315, "WifiFibra PR",                   "Sul"),
    # ── IXPs e Infraestrutura BR ──
    (26162,  "PTT Metro SP (IX.br)",           "Sudeste"),
    (265402, "PTT Metro RJ (IX.br)",           "Sudeste"),
    (267744, "PTT Nordeste (IX.br)",           "Nordeste"),
    (267745, "PTT Sul (IX.br)",                "Sul"),
    (267746, "PTT Centro-Oeste (IX.br)",       "Centro-Oeste"),
    (267747, "PTT Norte (IX.br)",              "Norte"),
    (1251,   "RNP — Rede Nacional Pesquisa",   "Sudeste"),
    # ── Grandes provedores com presença nacional ──
    (28329,  "InterNET Telecom",               "Sudeste"),
    (262186, "TV Azteca/OptiGlobe BR",         "Sudeste"),
    (269897, "Darvoz Telecom",                 "Nordeste"),
    (269286, "FibraOne",                       "Sul"),
    (268793, "NetFibra",                       "Centro-Oeste"),
    (269033, "TeleFibra",                      "Nordeste"),
    (268901, "SuperFibra",                     "Norte"),
    (268714, "MaxNet Telecom",                 "Sul"),
    (268839, "SpeedFibra",                     "Nordeste"),
    (268812, "MegaFibra",                      "Sudeste"),
    (268677, "TurboFibra",                     "Centro-Oeste"),
    (268956, "SkyFibra",                       "Norte"),
    (269102, "GlobalFibra",                    "Sudeste"),
    (269215, "FibraLight",                     "Nordeste"),
    (269341, "NetMax BR",                      "Sul"),
]

# Remove duplicatas mantendo a ordem
_seen = set()
ASNS_BR_UNIQ = []
for entry in ASNS_BR:
    if entry[0] not in _seen:
        _seen.add(entry[0])
        ASNS_BR_UNIQ.append(entry)

ASNS_BR = ASNS_BR_UNIQ[:107]  # Máximo 107 conforme solicitado


# ══════════════════════════════════════════════════════════════
# BANCO DE DADOS
# ══════════════════════════════════════════════════════════════
def init_db():
    conn = sqlite3.connect("bgp_audit.db")
    cur = conn.cursor()

    cur.execute("DROP TABLE IF EXISTS operadoras")
    cur.execute("DROP TABLE IF EXISTS prefixos")
    cur.execute("DROP TABLE IF EXISTS rotas_prefixo")
    cur.execute("DROP TABLE IF EXISTS alertas_ddos")
    cur.execute("DROP TABLE IF EXISTS resumo_mitigadores")

    cur.execute("""
        CREATE TABLE operadoras (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            asn TEXT UNIQUE,
            nome TEXT,
            regiao TEXT,
            data_coleta DATETIME DEFAULT (datetime('now','localtime')),
            total_prefixos_24 INTEGER DEFAULT 0
        )
    """)
    cur.execute("""
        CREATE TABLE prefixos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            asn_origem TEXT,
            prefixo TEXT,
            data_coleta DATETIME DEFAULT (datetime('now','localtime'))
        )
    """)
    cur.execute("""
        CREATE TABLE rotas_prefixo (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            prefixo TEXT,
            asn_anunciador TEXT,
            nome_anunciador TEXT,
            e_mitigador INTEGER DEFAULT 0,
            data_coleta DATETIME DEFAULT (datetime('now','localtime'))
        )
    """)
    cur.execute("""
        CREATE TABLE alertas_ddos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            asn_vitima TEXT,
            nome_vitima TEXT,
            regiao TEXT,
            prefixo TEXT,
            total_rotas INTEGER,
            rotas_via_mitigador INTEGER,
            percentual_mitigado REAL,
            mitigadores_ativos TEXT,
            redundancia TEXT,
            nivel_alerta TEXT,
            data_coleta DATETIME DEFAULT (datetime('now','localtime'))
        )
    """)
    cur.execute("""
        CREATE TABLE resumo_mitigadores (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            asn_mitigador TEXT,
            nome_mitigador TEXT,
            total_prefixos_protegendo INTEGER,
            total_vitimas INTEGER,
            regioes_atendidas TEXT,
            data_coleta DATETIME DEFAULT (datetime('now','localtime'))
        )
    """)
    conn.commit()
    return conn


# ══════════════════════════════════════════════════════════════
# DESCOBERTA AUTOMÁTICA — tenta enriquecer a lista local via API
# ══════════════════════════════════════════════════════════════
def enriquecer_via_api(limite=107):
    """
    Tenta obter lista de ASNs brasileiros via RIPE.
    Se bem-sucedido, retorna lista de ASNs com região 'BR-API'.
    Se falhar, retorna lista vazia e usamos a lista local curada.
    """
    print("  Tentando enriquecer lista via RIPE Stat...")
    try:
        # lod=1 retorna campo 'routed' diretamente sem wrapper 'countries'
        url = ("https://stat.ripe.net/data/country-asns/data.json"
               "?resource=BR&lod=1&sourceapp=mirage_noc")
        r = requests.get(url, headers=HEADERS, timeout=15)
        print(f"  RIPE HTTP {r.status_code}")
        if r.status_code == 200:
            data = r.json().get("data", {})
            # Com lod=1, o campo é 'routed' diretamente
            routed = data.get("routed", [])
            if not routed:
                # Tenta estrutura alternativa com 'countries'
                countries = data.get("countries", [])
                if countries:
                    routed = countries[0].get("routed", [])
            if len(routed) >= 10:
                asns_api = [int(a) for a in routed[:limite]]
                print(f"  ✅ RIPE retornou {len(asns_api)} ASNs brasileiros")
                return asns_api
            else:
                print(f"  ⚠️  RIPE retornou apenas {len(routed)} ASNs — usando lista local")
    except requests.exceptions.ConnectionError:
        print("  ⚠️  Sem conexão com RIPE. Usando lista local curada.")
    except Exception as e:
        print(f"  ⚠️  Erro RIPE: {e}. Usando lista local curada.")
    return []


def montar_lista_final(limite=107):
    """
    Monta a lista final de (asn, nome, regiao) para auditoria.
    Prioriza lista local curada (que tem região real).
    Tenta complementar com API se necessário.
    """
    print("\n" + "="*60)
    print("MONTANDO LISTA DE ASNs BRASILEIROS PARA AUDITORIA")
    print("="*60)

    # Começa com lista local curada (tem região real)
    lista = list(ASNS_BR)
    asns_na_lista = {e[0] for e in lista}

    # Tenta complementar via API (ASNs extras que não estão na lista)
    asns_api = enriquecer_via_api(limite=200)
    novos = 0
    for asn in asns_api:
        if asn not in asns_na_lista and len(lista) < limite:
            # Verifica se não é mitigador internacional
            if asn not in MITIGADORES:
                lista.append((asn, f"AS{asn}", "Brasil"))
                asns_na_lista.add(asn)
                novos += 1

    lista = lista[:limite]
    print(f"\n  ✅ Lista final: {len(lista)} ASNs")
    print(f"     → {len(ASNS_BR)} da base local curada")
    print(f"     → {novos} novos via API")

    # Mostra distribuição por região
    regioes = {}
    for _, _, reg in lista:
        regioes[reg] = regioes.get(reg, 0) + 1
    print("\n  Distribuição por região:")
    for reg, qtd in sorted(regioes.items()):
        bar = "█" * (qtd // 2)
        print(f"     {reg:<15} {qtd:>3}  {bar}")

    return lista


# ══════════════════════════════════════════════════════════════
# COLETA BGP (RIPE STAT)
# ══════════════════════════════════════════════════════════════
def obter_nome_operadora(asn, nome_fallback):
    """Busca nome real via RIPE, usa nome da lista local como fallback."""
    try:
        url = (f"https://stat.ripe.net/data/as-overview/data.json"
               f"?resource={asn}&sourceapp=mirage_noc")
        r = requests.get(url, headers=HEADERS, timeout=8)
        if r.status_code == 200:
            holder = r.json().get("data", {}).get("holder", "")
            if holder:
                return holder.split(",")[0].strip()
    except Exception:
        pass
    return nome_fallback


def obter_prefixos_24(asn):
    """Retorna lista de prefixos /24 anunciados pelo ASN."""
    prefixos = []
    try:
        url = (f"https://stat.ripe.net/data/announced-prefixes/data.json"
               f"?resource={asn}&sourceapp=mirage_noc")
        r = requests.get(url, headers=HEADERS, timeout=10)
        if r.status_code == 200:
            for p in r.json().get("data", {}).get("prefixes", []):
                pref = str(p.get("prefix", ""))
                if pref.endswith("/24"):
                    prefixos.append(pref)
    except Exception:
        pass
    return prefixos


def obter_rotas_prefixo(prefixo):
    """
    Busca todos os ASNs originadores deste /24 na tabela BGP global.
    Esta é a chave da análise de DDoS:
    - Se 100% dos paths passam por 1 mitigador → ataque em curso
    - Se sem redundância → risco crítico de disponibilidade
    """
    anunciadores = []
    try:
        # Fonte primária: routing-status
        url = (f"https://stat.ripe.net/data/routing-status/data.json"
               f"?resource={prefixo}&sourceapp=mirage_noc")
        r = requests.get(url, headers=HEADERS, timeout=10)
        if r.status_code == 200:
            for origin in r.json().get("data", {}).get("origins", []):
                raw = origin.get("origin", "")
                if raw:
                    try:
                        anunciadores.append(int(str(raw).replace("AS", "")))
                    except ValueError:
                        pass

        # Fallback: bgp-state (AS-PATH)
        if not anunciadores:
            url2 = (f"https://stat.ripe.net/data/bgp-state/data.json"
                    f"?resource={prefixo}&sourceapp=mirage_noc")
            r2 = requests.get(url2, headers=HEADERS, timeout=10)
            if r2.status_code == 200:
                for entry in r2.json().get("data", {}).get("bgp_state", []):
                    path = entry.get("path", [])
                    if path:
                        try:
                            anunciadores.append(int(path[-1]))
                        except (ValueError, IndexError):
                            pass
    except Exception:
        pass

    return list(set(anunciadores))


def classificar_redundancia(total_rotas, rotas_mitig, mitig_distintos):
    """
    Classifica risco de disponibilidade por redundância:

    CRITICO / SEM_REDUNDANCIA
        1 única rota, via 1 mitigador.
        Ponto único de falha total — se o mitigador cair, rede inacessível.

    ALTO / RISCO_CONCENTRACAO
        2+ rotas, mas TODAS via o MESMO mitigador.
        Sem diversidade de provedor — ataque pode estar em curso.

    MEDIO / REDUNDANCIA_PARCIAL
        2+ mitigadores diferentes, mas cobertura parcial das rotas.

    INFO / REDUNDANTE
        2+ mitigadores distintos com cobertura total. Bem configurado.

    INFO / SEM_MITIGACAO
        Nenhuma rota via mitigador. Provavelmente tráfego normal.
    """
    if total_rotas == 1 and rotas_mitig >= 1:
        return "SEM_REDUNDANCIA", "CRITICO"
    if rotas_mitig == total_rotas and mitig_distintos == 1:
        return "RISCO_CONCENTRACAO", "ALTO"
    if mitig_distintos >= 2 and rotas_mitig < total_rotas:
        return "REDUNDANCIA_PARCIAL", "MEDIO"
    if mitig_distintos >= 2:
        return "REDUNDANTE", "INFO"
    if rotas_mitig == 0:
        return "SEM_MITIGACAO", "INFO"
    return "RISCO_CONCENTRACAO", "ALTO"


# ══════════════════════════════════════════════════════════════
# MOTOR PRINCIPAL
# ══════════════════════════════════════════════════════════════
def executar():
    db = init_db()
    contagem_mitigadores = {}   # asn_mitig -> {nome, prefixos set, vitimas set, regioes set}

    print("\n" + "="*60)
    print("  MOTOR BGP/DDoS — MIRAGE SOLUTIONS NOC")
    print("  Análise restrita a operadoras BRASILEIRAS")
    print("="*60)

    lista_final = montar_lista_final(limite=107)
    total = len(lista_final)

    print(f"\nIniciando auditoria de {total} ASNs...\n")
    print("-"*60)

    for i, (asn, nome_local, regiao) in enumerate(lista_final, 1):

        # Busca nome real via API (usa local como fallback)
        nome = obter_nome_operadora(asn, nome_local)

        label = f"[{i:>3}/{total}]"
        print(f"\n{label} {nome[:42]:<42} AS{asn}")
        print(f"         Região: {regiao}")

        # Salva operadora no banco
        try:
            db.execute(
                "INSERT OR IGNORE INTO operadoras (asn, nome, regiao) VALUES (?,?,?)",
                (str(asn), nome, regiao)
            )
            db.commit()
        except Exception:
            pass

        # Busca prefixos /24
        prefixos = obter_prefixos_24(asn)

        if not prefixos:
            print(f"         → Sem prefixos /24 anunciados.")
            time.sleep(0.4)
            continue

        print(f"         → {len(prefixos)} prefixos /24. Analisando...")

        db.execute(
            "UPDATE operadoras SET total_prefixos_24=?, data_coleta=datetime('now','localtime') WHERE asn=?",
            (len(prefixos), str(asn))
        )

        alertas_asn = []

        # Analisa até 30 prefixos por ASN (respeita rate limit RIPE)
        for prefixo in prefixos[:30]:
            time.sleep(0.5)

            anunciadores = obter_rotas_prefixo(prefixo)
            if not anunciadores:
                continue

            # Quais anunciadores são mitigadores conhecidos?
            mitig_ativos = {
                a: MITIGADORES[a]
                for a in anunciadores
                if a in MITIGADORES
            }

            # Salva rota
            for a_asn in anunciadores:
                try:
                    db.execute(
                        "INSERT INTO rotas_prefixo (prefixo, asn_anunciador, nome_anunciador, e_mitigador) VALUES (?,?,?,?)",
                        (prefixo, str(a_asn),
                         MITIGADORES.get(a_asn, f"AS{a_asn}"),
                         1 if a_asn in MITIGADORES else 0)
                    )
                except Exception:
                    pass

            try:
                db.execute(
                    "INSERT INTO prefixos (asn_origem, prefixo) VALUES (?,?)",
                    (str(asn), prefixo)
                )
            except Exception:
                pass

            if not mitig_ativos:
                continue

            # Análise de redundância
            total_rotas  = len(anunciadores)
            rotas_mitig  = sum(1 for a in anunciadores if a in MITIGADORES)
            mitig_dist   = len(mitig_ativos)
            pct          = round(rotas_mitig / total_rotas * 100, 1) if total_rotas else 0
            redundancia, nivel = classificar_redundancia(total_rotas, rotas_mitig, mitig_dist)

            if nivel in ("CRITICO", "ALTO", "MEDIO"):
                txt_mitig = ", ".join(f"AS{k}({v})" for k, v in mitig_ativos.items())
                alertas_asn.append({
                    "prefixo": prefixo,
                    "total": total_rotas,
                    "mitig": rotas_mitig,
                    "pct": pct,
                    "txt": txt_mitig,
                    "red": redundancia,
                    "nivel": nivel,
                })

                # Acumula estatísticas do mitigador
                for m_asn, m_nome in mitig_ativos.items():
                    if m_asn not in contagem_mitigadores:
                        contagem_mitigadores[m_asn] = {
                            "nome": m_nome,
                            "prefixos": set(),
                            "vitimas": set(),
                            "regioes": set()
                        }
                    contagem_mitigadores[m_asn]["prefixos"].add(prefixo)
                    contagem_mitigadores[m_asn]["vitimas"].add(asn)
                    contagem_mitigadores[m_asn]["regioes"].add(regiao)

                try:
                    db.execute("""
                        INSERT INTO alertas_ddos
                            (asn_vitima, nome_vitima, regiao, prefixo,
                             total_rotas, rotas_via_mitigador, percentual_mitigado,
                             mitigadores_ativos, redundancia, nivel_alerta)
                        VALUES (?,?,?,?,?,?,?,?,?,?)
                    """, (str(asn), nome, regiao, prefixo,
                          total_rotas, rotas_mitig, pct,
                          txt_mitig, redundancia, nivel))
                except Exception:
                    pass

        db.commit()

        if alertas_asn:
            n_crit = sum(1 for a in alertas_asn if a["nivel"] == "CRITICO")
            n_alto = sum(1 for a in alertas_asn if a["nivel"] == "ALTO")
            n_med  = sum(1 for a in alertas_asn if a["nivel"] == "MEDIO")
            icons  = ("🔴" if n_crit else "") + ("🟠" if n_alto else "") + ("🔵" if n_med else "")
            print(f"         {icons} {n_crit} CRÍTICO | {n_alto} ALTO | {n_med} MÉDIO")
            for a in alertas_asn[:2]:
                print(f"              [{a['nivel']}] {a['prefixo']} "
                      f"rotas:{a['total']} mitig:{a['mitig']}({a['pct']}%) {a['red']}")
        else:
            print(f"         ✅ Sem alertas de mitigação.")

        time.sleep(1)

    # ── SALVA RESUMO DE MITIGADORES ──
    print("\n" + "="*60)
    print("RESUMO FINAL — MITIGADORES DETECTADOS")
    print("="*60)

    for m_asn, d in sorted(contagem_mitigadores.items(),
                            key=lambda x: -len(x[1]["prefixos"])):
        regioes_str = ", ".join(sorted(d["regioes"]))
        print(f"  AS{m_asn:<8} {d['nome']:<22} "
              f"{len(d['prefixos']):>4} pref | "
              f"{len(d['vitimas']):>3} operadoras | "
              f"{regioes_str}")
        try:
            db.execute("""
                INSERT INTO resumo_mitigadores
                    (asn_mitigador, nome_mitigador,
                     total_prefixos_protegendo, total_vitimas, regioes_atendidas)
                VALUES (?,?,?,?,?)
            """, (str(m_asn), d["nome"],
                  len(d["prefixos"]), len(d["vitimas"]),
                  regioes_str))
        except Exception:
            pass

    db.commit()
    db.close()
    print("\n✅ Auditoria concluída. Execute painel.py para visualizar.\n")


if __name__ == "__main__":
    executar()
