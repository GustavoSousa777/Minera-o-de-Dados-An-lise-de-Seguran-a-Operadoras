"""
painel.py — Dashboard NOC Mirage Solutions
Análise BGP/DDoS — Operadoras Brasileiras
"""
from flask import Flask, render_template_string, request
import sqlite3

app = Flask(__name__)

# ──────────────────────────────────────────
def db_query(sql, params=()):
    try:
        conn = sqlite3.connect("bgp_audit.db")
        conn.row_factory = sqlite3.Row
        rows = conn.execute(sql, params).fetchall()
        conn.close()
        return rows
    except Exception:
        return []

def db_one(sql, params=()):
    try:
        conn = sqlite3.connect("bgp_audit.db")
        conn.row_factory = sqlite3.Row
        row = conn.execute(sql, params).fetchone()
        conn.close()
        return row
    except Exception:
        return None

def get_regioes():
    rows = db_query("SELECT DISTINCT regiao FROM operadoras WHERE regiao IS NOT NULL ORDER BY regiao")
    return [r["regiao"] for r in rows]
# ──────────────────────────────────────────

@app.route('/')
def dashboard():
    regiao_filtro = request.args.get("regiao", "")
    filtro_sql    = "AND o.regiao = ?" if regiao_filtro else ""
    filtro_params = (regiao_filtro,) if regiao_filtro else ()

    # Cards de resumo
    stats = db_one(f"""
        SELECT
            (SELECT COUNT(DISTINCT asn_vitima) FROM alertas_ddos
             WHERE 1=1 {'AND regiao=?' if regiao_filtro else ''})       AS vitimas,
            (SELECT COUNT(*) FROM alertas_ddos
             WHERE nivel_alerta='CRITICO'
             {'AND regiao=?' if regiao_filtro else ''})                 AS criticos,
            (SELECT COUNT(*) FROM alertas_ddos
             WHERE nivel_alerta='ALTO'
             {'AND regiao=?' if regiao_filtro else ''})                 AS altos,
            (SELECT COUNT(DISTINCT asn_mitigador) FROM resumo_mitigadores) AS mitigadores,
            (SELECT COUNT(*) FROM operadoras
             WHERE 1=1 {'AND regiao=?' if regiao_filtro else ''})       AS operadoras,
            (SELECT SUM(total_prefixos_24) FROM operadoras
             WHERE 1=1 {'AND regiao=?' if regiao_filtro else ''})       AS prefixos
    """, filtro_params * 5 if regiao_filtro else ())

    regioes       = get_regioes()

    # Alertas DDoS
    alertas = db_query(f"""
        SELECT a.* FROM alertas_ddos a
        WHERE 1=1 {'AND a.regiao=?' if regiao_filtro else ''}
        ORDER BY
            CASE a.nivel_alerta WHEN 'CRITICO' THEN 0 WHEN 'ALTO' THEN 1 ELSE 2 END,
            a.data_coleta DESC
        LIMIT 300
    """, filtro_params)

    # Vítimas (operadoras em risco)
    vitimas = db_query(f"""
        SELECT
            a.asn_vitima, a.nome_vitima, a.regiao,
            COUNT(*)                                                  AS total_alertas,
            SUM(CASE WHEN a.nivel_alerta='CRITICO' THEN 1 ELSE 0 END) AS criticos,
            SUM(CASE WHEN a.nivel_alerta='ALTO'    THEN 1 ELSE 0 END) AS altos,
            SUM(CASE WHEN a.redundancia='SEM_REDUNDANCIA'    THEN 1 ELSE 0 END) AS sem_red,
            SUM(CASE WHEN a.redundancia='RISCO_CONCENTRACAO' THEN 1 ELSE 0 END) AS conc,
            GROUP_CONCAT(DISTINCT a.mitigadores_ativos)               AS mitig_txt
        FROM alertas_ddos a
        WHERE 1=1 {'AND a.regiao=?' if regiao_filtro else ''}
        GROUP BY a.asn_vitima, a.nome_vitima, a.regiao
        ORDER BY criticos DESC, altos DESC
        LIMIT 60
    """, filtro_params)

    # Mitigadores
    mitigadores = db_query("""
        SELECT asn_mitigador, nome_mitigador,
               SUM(total_prefixos_protegendo) AS total_prefixos,
               SUM(total_vitimas)             AS total_vitimas,
               GROUP_CONCAT(DISTINCT regioes_atendidas) AS regioes
        FROM resumo_mitigadores
        GROUP BY asn_mitigador, nome_mitigador
        ORDER BY total_prefixos DESC
    """)

    # Prefixos sem redundância (críticos)
    prefixos_crit = db_query(f"""
        SELECT a.prefixo, a.asn_vitima, a.nome_vitima, a.regiao,
               a.mitigadores_ativos, a.total_rotas, a.data_coleta
        FROM alertas_ddos a
        WHERE a.redundancia = 'SEM_REDUNDANCIA'
        {'AND a.regiao=?' if regiao_filtro else ''}
        ORDER BY a.data_coleta DESC
        LIMIT 100
    """, filtro_params)

    # Distribuição por região
    dist_regioes = db_query("""
        SELECT
            o.regiao,
            COUNT(DISTINCT o.asn)                                       AS total_op,
            COALESCE(SUM(o.total_prefixos_24), 0)                       AS total_pref,
            COUNT(DISTINCT a.asn_vitima)                                AS em_risco,
            SUM(CASE WHEN a.nivel_alerta='CRITICO' THEN 1 ELSE 0 END)  AS criticos
        FROM operadoras o
        LEFT JOIN alertas_ddos a ON a.asn_vitima = o.asn
        GROUP BY o.regiao
        ORDER BY criticos DESC, em_risco DESC
    """)

    return render_template_string(TEMPLATE,
        stats=stats or {},
        regioes=regioes,
        regiao_ativa=regiao_filtro,
        alertas=alertas,
        vitimas=vitimas,
        mitigadores=mitigadores,
        prefixos_crit=prefixos_crit,
        dist_regioes=dist_regioes,
    )


# ══════════════════════════════════════════════════════════════
TEMPLATE = r"""<!DOCTYPE html>
<html lang="pt-br">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Mirage NOC — Análise BGP/DDoS Brasil</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Space+Mono:wght@400;700&family=Inter:wght@300;400;500;600;700&display=swap');
:root{
  --bg:#07080d; --s1:#0d1117; --s2:#161b27; --s3:#1c2333;
  --b1:#1e2535; --b2:#2a3347; --b3:#3d4f6e;
  --tx:#cdd6f4; --mu:#7988a8; --mu2:#4a5568;
  --br:#8b6fef; --bl:#3d9eff; --gr:#00d68f;
  --rd:#ff4d6a; --or:#ff8c42; --yw:#f4d03f;
  --mono:'Space Mono',monospace;
  --sans:'Inter',sans-serif;
}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--tx);font-family:var(--sans);font-size:14px;min-height:100vh}

/* HEADER */
header{background:var(--s1);border-bottom:1px solid var(--b1);
  padding:14px 36px;display:flex;align-items:center;justify-content:space-between;gap:20px}
.logo{font-family:var(--mono);font-size:10px;letter-spacing:3px;color:var(--br);text-transform:uppercase;white-space:nowrap}
.logo span{color:var(--mu)}
.hd-title{font-size:1rem;font-weight:600}
.hd-sub{font-size:.75rem;color:var(--mu);margin-top:2px}

/* REGIÃO FILTER */
.region-bar{
  background:var(--s1);border-bottom:1px solid var(--b1);
  padding:10px 36px;display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.region-bar span{font-size:.7rem;text-transform:uppercase;letter-spacing:1px;color:var(--mu);margin-right:4px}
.reg-btn{
  background:var(--s2);border:1px solid var(--b1);border-radius:6px;
  padding:5px 12px;font-size:.75rem;font-family:var(--sans);color:var(--mu);
  cursor:pointer;text-decoration:none;transition:all .15s}
.reg-btn:hover{border-color:var(--b3);color:var(--tx)}
.reg-btn.active{background:rgba(139,111,239,.15);border-color:var(--br);color:var(--br);font-weight:600}

/* STATS */
.stats{display:grid;grid-template-columns:repeat(6,1fr);gap:10px;padding:24px 36px 0}
.stat{background:var(--s1);border:1px solid var(--b1);border-radius:10px;padding:14px 18px;position:relative;overflow:hidden}
.stat::after{content:'';position:absolute;top:0;left:0;right:0;height:2px}
.rd-a::after{background:var(--rd)} .or-a::after{background:var(--or)}
.bl-a::after{background:var(--bl)} .br-a::after{background:var(--br)}
.gr-a::after{background:var(--gr)} .mu-a::after{background:var(--mu)}
.stat .lb{font-size:.65rem;text-transform:uppercase;letter-spacing:.8px;color:var(--mu);margin-bottom:6px}
.stat .vl{font-family:var(--mono);font-size:1.7rem;font-weight:700}
.rd-a .vl{color:var(--rd)} .or-a .vl{color:var(--or)} .bl-a .vl{color:var(--bl)}
.br-a .vl{color:var(--br)} .gr-a .vl{color:var(--gr)} .mu-a .vl{color:var(--mu)}

/* REGION MAP */
.reg-map{display:grid;grid-template-columns:repeat(5,1fr);gap:10px;padding:16px 36px 0}
.reg-card{background:var(--s1);border:1px solid var(--b1);border-radius:8px;padding:12px 14px}
.reg-card .rname{font-size:.7rem;text-transform:uppercase;letter-spacing:1px;color:var(--mu);margin-bottom:6px}
.reg-card .rval{font-family:var(--mono);font-size:1.1rem;font-weight:700;color:var(--tx)}
.reg-card .rsub{font-size:.7rem;color:var(--mu);margin-top:2px}
.reg-card .rbadge{display:inline-block;margin-top:4px;font-size:.65rem;font-weight:700;
  padding:2px 7px;border-radius:10px;font-family:var(--mono)}
.rbadge.has-crit{background:rgba(255,77,106,.12);color:var(--rd);border:1px solid rgba(255,77,106,.3)}
.rbadge.ok{background:rgba(0,214,143,.1);color:var(--gr);border:1px solid rgba(0,214,143,.3)}

/* TABS */
.tabs{display:flex;gap:4px;padding:20px 36px 0;border-bottom:1px solid var(--b1)}
.tab{background:none;border:none;cursor:pointer;font-family:var(--sans);font-size:.82rem;
  font-weight:500;color:var(--mu);padding:9px 16px;border-radius:8px 8px 0 0;
  border:1px solid transparent;border-bottom:none;transition:all .15s;position:relative;bottom:-1px}
.tab:hover{color:var(--tx);background:var(--s1)}
.tab.on{color:var(--tx);background:var(--s2);border-color:var(--b1);border-bottom-color:var(--s2)}
.tc{display:inline-block;margin-left:5px;font-size:.68rem;background:var(--b2);
  border-radius:20px;padding:1px 6px;color:var(--mu);font-family:var(--mono)}
.tc.rd{background:rgba(255,77,106,.15);color:var(--rd)}

/* CONTENT */
.content{background:var(--s2);border:1px solid var(--b1);border-top:none;
  margin:0 36px 36px;border-radius:0 0 10px 10px;padding:24px}
.pane{display:none}.pane.on{display:block}
.sec{font-size:.65rem;text-transform:uppercase;letter-spacing:1.2px;color:var(--mu);
  margin-bottom:14px;font-weight:600}

/* TABLE */
.tw{border-radius:8px;overflow:hidden;border:1px solid var(--b1)}
table{width:100%;border-collapse:collapse;font-size:.82rem}
th{background:var(--s1);color:var(--mu);font-size:.65rem;text-transform:uppercase;
  letter-spacing:.6px;padding:10px 14px;font-weight:600;text-align:left;border-bottom:1px solid var(--b1)}
td{padding:10px 14px;border-bottom:1px solid var(--b1);vertical-align:middle}
tr:last-child td{border-bottom:none}
tr:hover td{background:rgba(255,255,255,.015)}

/* BADGES */
.badge{display:inline-block;font-family:var(--mono);font-size:.65rem;font-weight:700;
  text-transform:uppercase;padding:3px 9px;border-radius:20px;letter-spacing:.4px}
.CRITICO{background:rgba(255,77,106,.12);color:var(--rd);border:1px solid rgba(255,77,106,.3)}
.ALTO{background:rgba(255,140,66,.12);color:var(--or);border:1px solid rgba(255,140,66,.3)}
.MEDIO{background:rgba(61,158,255,.12);color:var(--bl);border:1px solid rgba(61,158,255,.3)}
.INFO{background:rgba(90,106,138,.1);color:var(--mu);border:1px solid var(--b2)}
.SEM_REDUNDANCIA{background:rgba(255,77,106,.12);color:var(--rd);border:1px solid rgba(255,77,106,.3)}
.RISCO_CONCENTRACAO{background:rgba(255,140,66,.12);color:var(--or);border:1px solid rgba(255,140,66,.3)}
.REDUNDANCIA_PARCIAL{background:rgba(61,158,255,.12);color:var(--bl);border:1px solid rgba(61,158,255,.3)}
.REDUNDANTE{background:rgba(0,214,143,.1);color:var(--gr);border:1px solid rgba(0,214,143,.3)}

.asn{font-family:var(--mono);font-size:.8rem;font-weight:700;color:var(--bl)}
.dim{color:var(--mu);font-size:.75rem}
.mono{font-family:var(--mono);font-size:.78rem}
.reg-tag{display:inline-block;background:var(--s3);border:1px solid var(--b2);
  border-radius:5px;padding:2px 7px;font-size:.7rem;color:var(--mu)}

/* MITIGADORES CARDS */
.mit-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:10px}
.mit-card{background:var(--s1);border:1px solid var(--b1);border-radius:8px;
  padding:14px 16px;display:flex;align-items:center;gap:14px}
.mit-rank{font-family:var(--mono);font-size:1.4rem;font-weight:700;color:var(--b2);min-width:28px}
.mit-name{font-weight:600;font-size:.88rem}
.mit-asn{font-family:var(--mono);font-size:.7rem;color:var(--br);margin-top:2px}
.mit-bar-wrap{flex:1;height:5px;background:var(--b1);border-radius:3px;overflow:hidden;margin-top:6px}
.mit-bar{height:100%;background:linear-gradient(90deg,var(--br),var(--bl));border-radius:3px}
.mit-num{font-family:var(--mono);font-size:.82rem;font-weight:700;text-align:right}
.mit-sub{font-size:.68rem;color:var(--mu);text-align:right}

/* PULSE */
.pulse{display:inline-block;width:7px;height:7px;border-radius:50%;
  background:var(--rd);margin-right:5px;vertical-align:middle;
  animation:p 1.4s ease-in-out infinite}
@keyframes p{0%,100%{opacity:1;transform:scale(1)}50%{opacity:.3;transform:scale(.7)}}

.empty{padding:50px;text-align:center;color:var(--mu)}
.empty h3{color:var(--tx);margin-bottom:8px}
</style>
</head>
<body>

<!-- HEADER -->
<header>
  <div>
    <div class="hd-title">Análise BGP / Detecção DDoS</div>
    <div class="hd-sub">Monitoramento de operadoras brasileiras · Mitigadores · Redundância</div>
  </div>
  <div class="logo">MIRAGE <span>SOLUTIONS</span> — NOC</div>
</header>

<!-- FILTRO DE REGIÃO -->
<div class="region-bar">
  <span>🗺 Região:</span>
  <a class="reg-btn {% if not regiao_ativa %}active{% endif %}" href="/">Todas</a>
  {% for r in regioes %}
  <a class="reg-btn {% if regiao_ativa==r %}active{% endif %}"
     href="/?regiao={{ r }}">{{ r }}</a>
  {% endfor %}
</div>

<!-- STATS -->
<div class="stats">
  <div class="stat rd-a">
    <div class="lb"><span class="pulse"></span>Alertas Críticos</div>
    <div class="vl">{{ stats.criticos or 0 }}</div>
  </div>
  <div class="stat or-a">
    <div class="lb">Alertas Altos</div>
    <div class="vl">{{ stats.altos or 0 }}</div>
  </div>
  <div class="stat rd-a">
    <div class="lb">Operadoras em Risco</div>
    <div class="vl">{{ stats.vitimas or 0 }}</div>
  </div>
  <div class="stat br-a">
    <div class="lb">Mitigadores Ativos</div>
    <div class="vl">{{ stats.mitigadores or 0 }}</div>
  </div>
  <div class="stat bl-a">
    <div class="lb">Operadoras Auditadas</div>
    <div class="vl">{{ stats.operadoras or 0 }}</div>
  </div>
  <div class="stat mu-a">
    <div class="lb">Prefixos /24 Total</div>
    <div class="vl">{{ stats.prefixos or 0 }}</div>
  </div>
</div>

<!-- MAPA DE REGIÕES -->
{% if dist_regioes %}
<div class="reg-map">
{% for r in dist_regioes %}
  <div class="reg-card">
    <div class="rname">{{ r.regiao }}</div>
    <div class="rval">{{ r.total_op }} operadoras</div>
    <div class="rsub">{{ r.total_pref }} prefixos /24</div>
    {% if r.criticos and r.criticos > 0 %}
      <span class="rbadge has-crit">🔴 {{ r.criticos }} críticos</span>
    {% else %}
      <span class="rbadge ok">✅ sem alertas críticos</span>
    {% endif %}
  </div>
{% endfor %}
</div>
{% endif %}

<!-- TABS -->
<div class="tabs" style="margin:18px 36px 0;padding:0">
  <button class="tab on"  onclick="sw('alertas',this)">
    🔴 Alertas DDoS <span class="tc rd">{{ alertas|length }}</span>
  </button>
  <button class="tab" onclick="sw('vitimas',this)">
    ⚠️ Operadoras em Risco <span class="tc">{{ vitimas|length }}</span>
  </button>
  <button class="tab" onclick="sw('mitigadores',this)">
    🛡️ Mitigadores <span class="tc">{{ mitigadores|length }}</span>
  </button>
  <button class="tab" onclick="sw('prefixos',this)">
    🎯 Sem Redundância <span class="tc rd">{{ prefixos_crit|length }}</span>
  </button>
</div>

<div class="content">

  <!-- ABA ALERTAS -->
  <div id="p-alertas" class="pane on">
    <p class="sec">Prefixos /24 com comportamento de mitigação ativo · ordenado por criticidade</p>
    {% if alertas %}
    <div class="tw"><table>
      <thead><tr>
        <th>Nível</th><th>Operadora</th><th>Região</th><th>Prefixo /24</th>
        <th>Rotas</th><th>Via Mitig.</th><th>% Mitig.</th>
        <th>Mitigadores</th><th>Redundância</th><th>Hora</th>
      </tr></thead>
      <tbody>
      {% for a in alertas %}
      <tr>
        <td><span class="badge {{ a.nivel_alerta }}">{{ a.nivel_alerta }}</span></td>
        <td>
          <div class="asn">AS{{ a.asn_vitima }}</div>
          <div class="dim">{{ a.nome_vitima[:30] }}</div>
        </td>
        <td><span class="reg-tag">{{ a.regiao }}</span></td>
        <td class="mono">{{ a.prefixo }}</td>
        <td style="text-align:center" class="mono">{{ a.total_rotas }}</td>
        <td style="text-align:center" class="mono">{{ a.rotas_via_mitigador }}</td>
        <td style="text-align:center">
          <span class="mono" style="color:{% if a.percentual_mitigado==100 %}var(--rd)
            {% elif a.percentual_mitigado>=50 %}var(--or){% else %}var(--bl){% endif %}">
            {{ a.percentual_mitigado }}%
          </span>
        </td>
        <td style="font-size:.75rem;color:var(--br)">{{ a.mitigadores_ativos }}</td>
        <td><span class="badge {{ a.redundancia }}">{{ a.redundancia|replace('_',' ') }}</span></td>
        <td class="dim">{{ (a.data_coleta or '').split(' ')[1][:5] if a.data_coleta else '—' }}</td>
      </tr>
      {% endfor %}
      </tbody>
    </table></div>
    {% else %}
    <div class="empty"><h3>Nenhum alerta encontrado</h3><p>Execute o auditor.py primeiro.</p></div>
    {% endif %}
  </div>

  <!-- ABA VÍTIMAS -->
  <div id="p-vitimas" class="pane">
    <p class="sec">Operadoras com maior concentração de alertas — possíveis alvos de ataques DDoS</p>
    {% if vitimas %}
    <div class="tw"><table>
      <thead><tr>
        <th>Operadora</th><th>Região</th><th>Críticos</th><th>Altos</th>
        <th>Sem Redundância</th><th>Concentração</th><th>Total</th><th>Mitigadores Usados</th>
      </tr></thead>
      <tbody>
      {% for v in vitimas %}
      <tr>
        <td>
          <div class="asn">AS{{ v.asn_vitima }}</div>
          <div class="dim">{{ v.nome_vitima[:35] }}</div>
        </td>
        <td><span class="reg-tag">{{ v.regiao }}</span></td>
        <td style="text-align:center">
          {% if v.criticos %}<span class="mono" style="color:var(--rd);font-weight:700">{{ v.criticos }}</span>
          {% else %}<span class="dim">0</span>{% endif %}
        </td>
        <td style="text-align:center">
          {% if v.altos %}<span class="mono" style="color:var(--or);font-weight:700">{{ v.altos }}</span>
          {% else %}<span class="dim">0</span>{% endif %}
        </td>
        <td style="text-align:center">
          {% if v.sem_red %}<span class="mono" style="color:var(--rd)">{{ v.sem_red }}</span>
          {% else %}<span class="dim">0</span>{% endif %}
        </td>
        <td style="text-align:center">
          {% if v.conc %}<span class="mono" style="color:var(--or)">{{ v.conc }}</span>
          {% else %}<span class="dim">0</span>{% endif %}
        </td>
        <td style="text-align:center" class="mono">{{ v.total_alertas }}</td>
        <td style="font-size:.72rem;color:var(--mu)">{{ (v.mitig_txt or '—')[:60] }}</td>
      </tr>
      {% endfor %}
      </tbody>
    </table></div>
    {% else %}
    <div class="empty"><h3>Sem dados</h3><p>Execute o auditor.py.</p></div>
    {% endif %}
  </div>

  <!-- ABA MITIGADORES -->
  <div id="p-mitigadores" class="pane">
    <p class="sec">ASNs de scrubbing centers identificados · volume de prefixos protegidos</p>
    {% if mitigadores %}
      {% set mx = mitigadores[0].total_prefixos or 1 %}
      <div class="mit-grid">
      {% for m in mitigadores %}
      <div class="mit-card">
        <div class="mit-rank">{{ loop.index }}</div>
        <div style="flex:1;min-width:0">
          <div class="mit-name">{{ m.nome_mitigador }}</div>
          <div class="mit-asn">AS{{ m.asn_mitigador }}</div>
          <div class="mit-bar-wrap">
            <div class="mit-bar" style="width:{{ (((m.total_prefixos or 0)/(mx or 1))*100)|int }}%"></div>
          </div>
          {% if m.regioes %}
          <div style="font-size:.65rem;color:var(--mu);margin-top:4px">{{ m.regioes[:50] }}</div>
          {% endif %}
        </div>
        <div>
          <div class="mit-num" style="color:var(--tx)">{{ m.total_prefixos or 0 }}</div>
          <div class="mit-sub">prefixos</div>
          <div class="mit-num" style="color:var(--mu);margin-top:4px">{{ m.total_vitimas or 0 }}</div>
          <div class="mit-sub">operadoras</div>
        </div>
      </div>
      {% endfor %}
      </div>
    {% else %}
    <div class="empty"><h3>Nenhum mitigador identificado</h3><p>Execute o auditor.py.</p></div>
    {% endif %}
  </div>

  <!-- ABA PREFIXOS CRÍTICOS -->
  <div id="p-prefixos" class="pane">
    <p class="sec">
      Prefixos /24 com rota ÚNICA via mitigador — risco máximo de indisponibilidade<br>
      <span style="color:var(--rd);font-size:.68rem">
        ⚠ 1 rota + 1 mitigador = zero fallback. Se o mitigador cair, a rede fica inacessível.
      </span>
    </p>
    {% if prefixos_crit %}
    <div class="tw"><table>
      <thead><tr>
        <th>Prefixo /24</th><th>Operadora</th><th>Região</th>
        <th>Mitigador Exclusivo</th><th>Rotas Totais</th><th>Situação</th><th>Detectado</th>
      </tr></thead>
      <tbody>
      {% for p in prefixos_crit %}
      <tr>
        <td class="mono" style="color:var(--rd)">{{ p.prefixo }}</td>
        <td>
          <div class="asn">AS{{ p.asn_vitima }}</div>
          <div class="dim">{{ p.nome_vitima[:30] }}</div>
        </td>
        <td><span class="reg-tag">{{ p.regiao }}</span></td>
        <td style="font-size:.75rem;color:var(--br)">{{ p.mitigadores_ativos }}</td>
        <td style="text-align:center" class="mono">{{ p.total_rotas }}</td>
        <td><span class="badge SEM_REDUNDANCIA">SEM REDUNDÂNCIA</span></td>
        <td class="dim">{{ p.data_coleta or '—' }}</td>
      </tr>
      {% endfor %}
      </tbody>
    </table></div>
    {% else %}
    <div class="empty"><h3>Nenhum prefixo sem redundância</h3></div>
    {% endif %}
  </div>

</div>

<script>
function sw(id,btn){
  document.querySelectorAll('.pane').forEach(p=>p.classList.remove('on'));
  document.querySelectorAll('.tab').forEach(b=>b.classList.remove('on'));
  document.getElementById('p-'+id).classList.add('on');
  btn.classList.add('on');
}
</script>
</body>
</html>
"""

if __name__ == '__main__':
    print("─"*50)
    print("  NOC Mirage Solutions — Dashboard BGP/DDoS")
    print("  Acesse: http://127.0.0.1:5000")
    print("─"*50)
    app.run(host='127.0.0.1', port=5000, debug=True)
