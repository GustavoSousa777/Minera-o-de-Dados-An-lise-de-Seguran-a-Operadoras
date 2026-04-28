from flask import Flask, render_template_string
import sqlite3

app = Flask(__name__)

def get_db_connection():
    conn = sqlite3.connect("bgp_audit.db")
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/')
def dashboard():
    try:
        conn = get_db_connection()
        logs = conn.execute("SELECT * FROM logs_seguranca ORDER BY data_execucao DESC LIMIT 100").fetchall()
    except Exception as e:
        logs = []
    finally:
        if 'conn' in locals():
            conn.close()

    html_template = """
    <!DOCTYPE html>
    <html lang="pt-br">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>NOC Mirage Solutions - Auditoria BGP</title>
        <style>
            :root {
                --bg: #0a0a0f;
                --surface: #161b22;
                --text-main: #e6edf3;
                --text-muted: #8b949e;
                --border: #30363d;
                --brand: #b478ff; 
            }
            * { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Segoe UI', Tahoma, sans-serif; }
            body { background: var(--bg); color: var(--text-main); padding: 40px; }
            
            header { display: flex; justify-content: space-between; align-items: flex-end; border-bottom: 1px solid var(--border); padding-bottom: 20px; margin-bottom: 30px; }
            h1 { color: var(--text-main); font-weight: 600; font-size: 1.8rem; }
            p.subtitle { color: var(--text-muted); margin-top: 5px; font-size: 0.95rem; }
            .brand-logo { font-family: 'Syne', sans-serif; font-size: 14px; font-weight: 700; color: var(--brand); letter-spacing: 2px; text-transform: uppercase; }

            .table-container { background: var(--surface); border: 1px solid var(--border); border-radius: 12px; overflow: hidden; box-shadow: 0 8px 32px rgba(0,0,0,0.2); }
            table { width: 100%; border-collapse: collapse; text-align: left; }
            th, td { padding: 14px 20px; border-bottom: 1px solid var(--border); vertical-align: middle; }
            th { background: rgba(255,255,255,0.02); color: var(--text-muted); font-size: 0.8rem; text-transform: uppercase; font-weight: 600; letter-spacing: 0.5px; }
            tr:last-child td { border-bottom: none; }
            tr:hover { background: rgba(255,255,255,0.03); }

            .asn-bold { font-weight: 600; color: #58a6ff; }
            .operadora-nome { font-weight: 500; font-size: 0.95rem; }
            .local-tag { background: #21262d; padding: 4px 8px; border-radius: 6px; font-size: 0.8rem; border: 1px solid var(--border); display: inline-block; white-space: nowrap; }
            
            .badge { padding: 6px 12px; border-radius: 20px; font-size: 0.75rem; font-weight: 700; text-transform: uppercase; display: inline-block; text-align: center; width: 110px; }
            .badge.PROTEGIDO { background: rgba(63,185,80,0.1); color: #3fb950; border: 1px solid rgba(63,185,80,0.3); }
            .badge.VULNERÁVEL { background: rgba(248,81,73,0.1); color: #f85149; border: 1px solid rgba(248,81,73,0.3); }
            
            .asn-list { font-family: 'Consolas', monospace; font-size: 0.85rem; padding: 4px 8px; border-radius: 4px; display: inline-block; }
            .asn-ok { background: rgba(63,185,80,0.1); color: #3fb950; border: 1px dashed rgba(63,185,80,0.4); }
            .asn-falha { background: rgba(248,81,73,0.1); color: #ff7b72; border: 1px dashed rgba(248,81,73,0.4); }

            .empty-state { padding: 40px; text-align: center; color: var(--text-muted); }
        </style>
    </head>
    <body>
        <header>
            <div>
                <h1>Auditoria de Segurança BGP</h1>
                <p class="subtitle">Verificação em tempo real do tráfego através dos Scrubbing Centers</p>
            </div>
            <div class="brand-logo">MIRAGE SOLUTIONS</div>
        </header>

        <div class="table-container">
            {% if logs %}
            <table>
                <thead>
                    <tr>
                        <th>Hora / Data</th>
                        <th>Alvo</th>
                        <th>Operadora</th>
                        <th>Localização</th>
                        <th>Rotas /24</th>
                        <th>Segurança: OK (Ativos)</th>
                        <th>Segurança: Falha (Ausentes)</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
                    {% for log in logs %}
                    <tr>
                        <td style="font-size: 0.85rem; color: #8b949e; white-space: nowrap;">
                            {{ log.data_execucao.split(' ')[1] }}<br>
                            <span style="font-size: 0.75rem;">{{ log.data_execucao.split(' ')[0] }}</span>
                        </td>
                        <td class="asn-bold">AS{{ log.asn_alvo }}</td>
                        <td class="operadora-nome">{{ log.nome_operadora }}</td>
                        <td><span class="local-tag">{{ log.cidade }} / {{ log.estado }}</span></td>
                        <td style="text-align: center; font-weight: bold;">{{ log.total_prefixos_24 }}</td>
                        
                        <td>
                            {% if log.asns_encontrados != 'Nenhum' %}
                                <span class="asn-list asn-ok">{{ log.asns_encontrados }}</span>
                            {% else %}
                                <span style="color: var(--text-muted); font-size: 0.85rem;">-</span>
                            {% endif %}
                        </td>
                        
                        <td>
                            {% if log.asns_ausentes != 'Nenhum' %}
                                <span class="asn-list asn-falha">{{ log.asns_ausentes }}</span>
                            {% else %}
                                <span style="color: var(--text-muted); font-size: 0.85rem;">-</span>
                            {% endif %}
                        </td>
                        
                        <td><span class="badge {{ log.status }}">{{ log.status }}</span></td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
            {% else %}
            <div class="empty-state">
                <h2>Nenhum dado encontrado no banco de dados.</h2>
                <p>Certifique-se de executar o arquivo <b>auditor.py</b> primeiro para coletar os dados reais da internet.</p>
            </div>
            {% endif %}
        </div>
    </body>
    </html>
    """
    return render_template_string(html_template, logs=logs)

if __name__ == '__main__':
    print("--- Servidor NOC Mirage Solutions Ativo ---")
    print("Acesse no navegador: http://127.0.0.1:5000")
    app.run(host='127.0.0.1', port=5000, debug=True)