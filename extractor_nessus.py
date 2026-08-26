"""
Extrai informações de uma instância Nessus Professional (standalone) para
documentar uma migração para Tenable One: policies e scans (config completa,
targets, schedule).

Uso:
    1. Copie .env.example para .env e preencha usuário/senha OU API keys
    2. pip install -r requirements.txt
    3. python extrair_nessus.py

Autenticação no Nessus Pro:
    Nessus Pro aceita dois métodos:
    a) API Keys (Settings > My Account > API Keys) - recomendado
    b) Usuário/senha (gera um token de sessão via /session) - fallback,
       necessário em instalações mais antigas ou se API Keys estiverem
       desabilitadas

Observação sobre SSL:
    Por padrão o Nessus Pro usa certificado autoassinado. O script desativa
    a verificação de SSL (verify=False). Se você tiver um certificado válido
    configurado, pode remover isso e usar verify=True.
"""

import os
import time
import json
import requests
import urllib3
from datetime import datetime

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ==== CONFIGURAÇÃO ====
BASE_URL = os.environ.get("NESSUS_BASE_URL", "https://localhost:8834")
ACCESS_KEY = os.environ.get("NESSUS_ACCESS_KEY")
SECRET_KEY = os.environ.get("NESSUS_SECRET_KEY")
USERNAME = os.environ.get("NESSUS_USERNAME")
PASSWORD = os.environ.get("NESSUS_PASSWORD")
VERIFY_SSL = os.environ.get("NESSUS_VERIFY_SSL", "false").lower() == "true"

session_token = None

if ACCESS_KEY and SECRET_KEY:
    HEADERS = {
        "X-ApiKeys": f"accessKey={ACCESS_KEY}; secretKey={SECRET_KEY}",
        "Accept": "application/json",
    }
elif USERNAME and PASSWORD:
    resp = requests.post(
        f"{BASE_URL}/session",
        json={"username": USERNAME, "password": PASSWORD},
        verify=VERIFY_SSL,
    )
    resp.raise_for_status()
    session_token = resp.json()["token"]
    HEADERS = {
        "X-Cookie": f"token={session_token}",
        "Accept": "application/json",
    }
else:
    raise SystemExit(
        "Defina NESSUS_ACCESS_KEY + NESSUS_SECRET_KEY, "
        "ou NESSUS_USERNAME + NESSUS_PASSWORD (via .env)."
    )


def get(endpoint: str):
    resp = requests.get(f"{BASE_URL}{endpoint}", headers=HEADERS, verify=VERIFY_SSL)
    resp.raise_for_status()
    return resp.json()


def extrair_policies():
    data = get("/policies")
    return data.get("policies", [])


def extrair_scans():
    data = get("/scans")
    return data.get("scans", [])


def extrair_scan_detalhe(scan_id: int):
    return get(f"/scans/{scan_id}")


def extrair_server_status():
    """Versão do Nessus, feed de plugins, etc. - útil pra documentação."""
    return get("/server/properties")


def main():
    print(f"Conectando em {BASE_URL} ...")

    relatorio = {
        "data_extracao": datetime.now().isoformat(),
        "server_info": extrair_server_status(),
        "policies": extrair_policies(),
        "scans": extrair_scans(),
    }

    print("Detalhando scans individualmente...")
    detalhes_scans = []
    for scan in relatorio["scans"]:
        try:
            detalhe = extrair_scan_detalhe(scan["id"])
            detalhes_scans.append(detalhe)
        except requests.HTTPError as e:
            print(f"Erro ao detalhar scan {scan.get('id')}: {e}")
            if getattr(e.response, "status_code", None) == 429:
                time.sleep(2)
        time.sleep(0.3)
    relatorio["scans_detalhados"] = detalhes_scans

    os.makedirs("output", exist_ok=True)
    nome_arquivo = f"output/nessus_export_{datetime.now().strftime('%Y%m%d_%H%M')}.json"
    with open(nome_arquivo, "w", encoding="utf-8") as f:
        json.dump(relatorio, f, indent=2, ensure_ascii=False)

    # Encerra a sessão se autenticado via usuário/senha
    if session_token:
        requests.delete(f"{BASE_URL}/session", headers=HEADERS, verify=VERIFY_SSL)

    print(f"\nConcluído! Dados salvos em: {nome_arquivo}")
    print(f"- {len(relatorio['policies'])} policies")
    print(f"- {len(relatorio['scans'])} scans")


if __name__ == "__main__":
    main()
