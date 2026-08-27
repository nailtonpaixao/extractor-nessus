#!/usr/bin/env python3
"""
nessus_pre_migration_audit.py

Script de auditoria/documentação de um ambiente Nessus Professional
(on-prem/standalone) antes de uma migração para o Tenable One.

Consulta a API REST do Nessus Pro e extrai:
    - Pastas de scans (/folders)
    - Scans dentro de cada pasta (/scans), enriquecidos com detalhes de
      /scans/{id}: servidor/instancia (scanner), politica utilizada,
      alvos/faixa de IP, frequencia, horario de execucao e se esta ativo
    - Policies (/policies)

Exporta os resultados em três formatos:
    - JSON bruto (backup/auditoria)
    - CSV (um arquivo por entidade: pastas.csv, scans.csv, policies.csv)
    - XLSX (uma planilha com 3 abas: Pastas, Scans, Policies)

Autenticação suportada:
    - API Keys (X-ApiKeys header) -> recomendado
    - Login/senha com token de sessão (X-Cookie) -> fallback

Uso:
    export NESSUS_URL="https://nessus-host:8834"
    export NESSUS_ACCESS_KEY="xxxx"
    export NESSUS_SECRET_KEY="yyyy"
    python3 nessus_pre_migration_audit.py

    ou, para login/senha:
    export NESSUS_URL="https://nessus-host:8834"
    export NESSUS_USERNAME="admin"
    export NESSUS_PASSWORD="senha"
    python3 nessus_pre_migration_audit.py --auth-method password

Requisitos:
    pip install requests openpyxl python-dotenv
"""

import os
import csv
import json
import logging
import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

import requests
from requests.exceptions import RequestException, Timeout

# Carrega as credenciais a partir de um arquivo .env localizado na MESMA pasta
# do script (boa prática: nunca deixar API keys hardcoded no código-fonte).
# Se o .env não existir, o script segue apenas com variáveis de ambiente já
# exportadas no shell (útil para uso em CI/servidores).
SCRIPT_DIR = Path(__file__).resolve().parent
ENV_PATH = SCRIPT_DIR / ".env"

try:
    from dotenv import load_dotenv

    if ENV_PATH.exists():
        load_dotenv(dotenv_path=ENV_PATH)
    else:
        logging.getLogger("nessus_audit").warning(
            "Arquivo .env não encontrado em %s — utilizando apenas variáveis "
            "de ambiente já exportadas no shell (se houver).",
            ENV_PATH,
        )
except ImportError:
    logging.getLogger("nessus_audit").warning(
        "python-dotenv não instalado — utilizando apenas variáveis de "
        "ambiente já exportadas no shell. Instale com: pip install python-dotenv"
    )

try:
    from openpyxl import Workbook
except ImportError:
    Workbook = None  # tratado em generate_xlsx()

# ---------------------------------------------------------------------------
# Configuração de logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("nessus_audit")

DEFAULT_TIMEOUT = 180  # segundos


# ---------------------------------------------------------------------------
# Cliente Nessus
# ---------------------------------------------------------------------------
class NessusClient:
    """Cliente mínimo para a API REST do Nessus Pro (somente leitura)."""

    def __init__(
        self,
        base_url: str,
        access_key: str = None,
        secret_key: str = None,
        username: str = None,
        password: str = None,
        verify_ssl: bool = True,
        timeout: int = DEFAULT_TIMEOUT,
    ):
        self.base_url = base_url.rstrip("/")
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.session = requests.Session()

        if not verify_ssl:
            logger.warning(
                "Verificação SSL desabilitada (verify_ssl=False). "
                "Use apenas em ambientes controlados/certificados self-signed conhecidos."
            )
            requests.packages.urllib3.disable_warnings()  # evita poluir o log com InsecureRequestWarning

        if access_key and secret_key:
            self._auth_via_api_keys(access_key, secret_key)
        elif username and password:
            self._auth_via_session(username, password)
        else:
            raise ValueError(
                "Credenciais insuficientes: forneça (access_key, secret_key) "
                "ou (username, password)."
            )

    # -- autenticação ------------------------------------------------------
    def _auth_via_api_keys(self, access_key: str, secret_key: str):
        logger.info("Autenticando via API Keys (X-ApiKeys).")
        self.session.headers.update(
            {"X-ApiKeys": f"accessKey={access_key}; secretKey={secret_key}"}
        )
        # valida a credencial com uma chamada leve
        self._request("GET", "/server/properties")

    def _auth_via_session(self, username: str, password: str):
        logger.info("Autenticando via login/senha (token de sessão).")
        resp = self._request(
            "POST",
            "/session",
            json={"username": username, "password": password},
            authenticated=False,
        )
        token = resp.get("token")
        if not token:
            raise RuntimeError("Falha ao obter token de sessão do Nessus.")
        self.session.headers.update({"X-Cookie": f"token={token}"})

    # -- request genérico ----------------------------------------------------
    def _request(self, method: str, path: str, authenticated: bool = True, **kwargs):
        url = f"{self.base_url}{path}"
        try:
            resp = self.session.request(
                method,
                url,
                timeout=self.timeout,
                verify=self.verify_ssl,
                **kwargs,
            )
        except Timeout:
            logger.error("Timeout ao acessar %s", url)
            raise
        except RequestException as exc:
            logger.error("Erro de conexão ao acessar %s: %s", url, exc)
            raise

        if resp.status_code == 401:
            raise PermissionError(f"401 Unauthorized em {path} — credenciais inválidas ou expiradas.")
        if resp.status_code == 403:
            raise PermissionError(f"403 Forbidden em {path} — usuário sem permissão para este recurso.")
        if not resp.ok:
            raise RuntimeError(f"Erro HTTP {resp.status_code} em {path}: {resp.text[:300]}")

        if resp.text:
            return resp.json()
        return {}

    def get(self, path: str, **kwargs):
        return self._request("GET", path, **kwargs)

    # -- endpoints de negócio -------------------------------------------------
    def get_server_properties(self) -> dict:
        return self.get("/server/properties")

    def get_folders(self) -> list:
        data = self.get("/folders")
        return data.get("folders", [])

    def get_scans(self, folder_id: int = None) -> list:
        params = {"folder_id": folder_id} if folder_id is not None else {}
        data = self.get("/scans", params=params)
        return data.get("scans") or []

    def get_policies(self) -> list:
        data = self.get("/policies")
        return data.get("policies", [])

    def get_scan_details(self, scan_id: int) -> dict:
        """Detalhe completo de um scan (inclui política, alvos, scanner e agendamento)."""
        return self.get(f"/scans/{scan_id}")


# ---------------------------------------------------------------------------
# Coleta de dados
# ---------------------------------------------------------------------------
_FREQ_MAP = {
    "DAILY": "Diario",
    "WEEKLY": "Semanal",
    "MONTHLY": "Mensal",
    "YEARLY": "Anual",
    "ONETIME": "Execucao unica",
}


def parse_schedule(info: dict) -> dict:
    """
    Extrai frequencia, horario e status (ativo) do agendamento de um scan a
    partir do bloco "info" retornado por GET /scans/{id}.

    OBS: os nomes exatos dos campos de agendamento (rrules/starttime/enabled)
    podem variar levemente entre versoes do Nessus. Se "Frequencia"/"Horario"
    vierem sempre "--" na sua versao, rode com LOG_LEVEL=DEBUG e inspecione o
    JSON bruto (nessus_audit.json) para ajustar os nomes dos campos abaixo.
    """
    enabled = info.get("enabled")
    rrules = info.get("rrules") or ""
    starttime = info.get("starttime") or ""

    frequency = "--"
    if rrules:
        for part in rrules.split(";"):
            if part.upper().startswith("FREQ="):
                freq_key = part.split("=", 1)[1].strip().upper()
                frequency = _FREQ_MAP.get(freq_key, freq_key.title())
                break

    horario = "--"
    if starttime and "T" in starttime:
        try:
            time_part = starttime.split("T", 1)[1]
            horario = f"{time_part[0:2]}:{time_part[2:4]}"
        except (IndexError, ValueError):
            horario = "--"

    if enabled is True:
        ativo = "Sim"
    elif enabled is False:
        ativo = "Nao"
    else:
        ativo = "--"

    return {"frequencia": frequency, "horario": horario, "ativo": ativo}


def get_scan_extra_details(client: NessusClient, scan_id: int) -> dict:
    """
    Busca o detalhe de um scan (GET /scans/{id}) e extrai as informacoes que
    nao vem na listagem resumida: scanner/servidor, politica, alvos e
    agendamento (frequencia/horario/ativo).
    """
    try:
        detail = client.get_scan_details(scan_id)
    except Exception as exc:
        logger.warning("Falha ao buscar detalhes do scan id=%s: %s", scan_id, exc)
        return {}

    info = detail.get("info", {}) or {}
    logger.debug("Detalhe bruto do scan id=%s: %s", scan_id, json.dumps(info, ensure_ascii=False))

    schedule = parse_schedule(info)

    return {
        "servidor_instancia": info.get("scanner_name", "--"),
        "politica_utilizada": info.get("policy", "--"),
        "alvos_faixa_ip": info.get("targets", "--"),
        "frequencia": schedule["frequencia"],
        "horario_execucao": schedule["horario"],
        "ativo": schedule["ativo"],
    }


def collect_folders_and_scans(client: NessusClient):
    """Retorna (lista_de_pastas, lista_de_scans) já achatadas para exportação."""
    folders_raw = client.get_folders()
    folders_out = []
    scans_out = []

    for folder in folders_raw:
        folder_id = folder.get("id")
        folder_name = folder.get("name")
        folder_type = folder.get("type")

        folders_out.append(
            {
                "folder_id": folder_id,
                "folder_name": folder_name,
                "folder_type": folder_type,
            }
        )

        try:
            scans = client.get_scans(folder_id=folder_id)
        except Exception as exc:
            logger.error("Falha ao listar scans da pasta '%s' (id=%s): %s", folder_name, folder_id, exc)
            continue

        for scan in scans:
            scan_id = scan.get("id")
            last_mod = scan.get("last_modification_date")
            last_mod_str = (
                datetime.fromtimestamp(last_mod, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
                if last_mod
                else ""
            )

            logger.info("Buscando detalhes do scan '%s' (id=%s)...", scan.get("name"), scan_id)
            extra = get_scan_extra_details(client, scan_id) if scan_id is not None else {}

            scans_out.append(
                {
                    "pasta": folder_name,
                    "nome_do_scan": scan.get("name"),
                    "servidor_instancia": extra.get("servidor_instancia", "--"),
                    "politica_utilizada": extra.get("politica_utilizada", "--"),
                    "alvos_faixa_ip": extra.get("alvos_faixa_ip", "--"),
                    "frequencia": extra.get("frequencia", "--"),
                    "horario_execucao": extra.get("horario_execucao", "--"),
                    "ativo_sim_nao": extra.get("ativo", "--"),
                    "status": scan.get("status"),
                    "owner": scan.get("owner"),
                    "scan_id": scan_id,
                    "last_modification_date": last_mod_str,
                }
            )

    logger.info("Coletadas %d pastas e %d scans.", len(folders_out), len(scans_out))
    return folders_out, scans_out


def collect_policies(client: NessusClient):
    policies_raw = client.get_policies()
    policies_out = []

    for pol in policies_raw:
        created = pol.get("creation_date")
        modified = pol.get("last_modification_date")
        policies_out.append(
            {
                "policy_id": pol.get("id"),
                "name": pol.get("name"),
                "template_uuid": pol.get("template_uuid") or pol.get("policy_template_id", ""),
                "description": pol.get("description", ""),
                "owner": pol.get("owner"),
                "creation_date": (
                    datetime.fromtimestamp(created, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
                    if created
                    else ""
                ),
                "last_modification_date": (
                    datetime.fromtimestamp(modified, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
                    if modified
                    else ""
                ),
            }
        )

    logger.info("Coletadas %d policies.", len(policies_out))
    return policies_out


# ---------------------------------------------------------------------------
# Exportação
# ---------------------------------------------------------------------------
def build_metadata(client: NessusClient, base_url: str) -> dict:
    try:
        props = client.get_server_properties()
        nessus_version = props.get("server_version") or props.get("nessus_ui_version", "desconhecida")
    except Exception as exc:
        logger.warning("Não foi possível obter a versão do Nessus: %s", exc)
        nessus_version = "desconhecida"

    return {
        "extraction_datetime_utc": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "nessus_host": base_url,
        "nessus_version": nessus_version,
    }


def export_json(output_dir: Path, metadata: dict, folders, scans, policies):
    payload = {
        "metadata": metadata,
        "folders": folders,
        "scans": scans,
        "policies": policies,
    }
    path = output_dir / "nessus_audit.json"
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)
    logger.info("JSON exportado em %s", path)


def _write_csv(path: Path, rows: list):
    if not rows:
        logger.warning("Nenhum registro para exportar em %s — arquivo criado apenas com cabeçalho vazio.", path)
        path.write_text("")
        return
    fieldnames = list(rows[0].keys())
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    logger.info("CSV exportado em %s (%d linhas)", path, len(rows))


def export_csv(output_dir: Path, folders, scans, policies):
    _write_csv(output_dir / "pastas.csv", folders)
    _write_csv(output_dir / "scans.csv", scans)
    _write_csv(output_dir / "policies.csv", policies)


def export_xlsx(output_dir: Path, metadata: dict, folders, scans, policies):
    if Workbook is None:
        logger.error("openpyxl não instalado — pulando geração do XLSX. Instale com: pip install openpyxl")
        return

    wb = Workbook()

    # Aba de metadados (informativa)
    meta_ws = wb.active
    meta_ws.title = "Metadados"
    meta_ws.append(["Campo", "Valor"])
    for k, v in metadata.items():
        meta_ws.append([k, v])

    def add_sheet(title: str, rows: list):
        ws = wb.create_sheet(title=title)
        if not rows:
            ws.append(["(sem registros)"])
            return
        headers = list(rows[0].keys())
        ws.append(headers)
        for row in rows:
            ws.append([row.get(h, "") for h in headers])
        # largura básica de coluna
        for i, header in enumerate(headers, start=1):
            ws.column_dimensions[chr(64 + i) if i <= 26 else "A"].width = max(15, len(header) + 2)

    add_sheet("Pastas", folders)
    add_sheet("Scans", scans)
    add_sheet("Policies", policies)

    path = output_dir / "nessus_audit.xlsx"
    wb.save(path)
    logger.info("XLSX exportado em %s", path)


# ---------------------------------------------------------------------------
# CLI / main
# ---------------------------------------------------------------------------
def parse_args():
    parser = argparse.ArgumentParser(
        description="Auditoria de Nessus Pro (pastas, scans e policies) para documentação pré-migração ao Tenable One."
    )
    parser.add_argument(
        "--auth-method",
        choices=["apikey", "password"],
        default="apikey",
        help="Método de autenticação: apikey (padrão) ou password.",
    )
    parser.add_argument(
        "--no-verify-ssl",
        action="store_true",
        help="Desabilita verificação de certificado SSL (use apenas se souber o que está fazendo).",
    )
    parser.add_argument(
        "--output-dir",
        default="./nessus_audit_output",
        help="Diretório onde os relatórios serão salvos (padrão: ./nessus_audit_output).",
    )
    return parser.parse_args()


def main():
    args = parse_args()

    base_url = os.environ.get("NESSUS_URL")
    if not base_url:
        logger.error(
            "NESSUS_URL não definida. Configure-a no arquivo .env (%s) ou como "
            "variável de ambiente. Ex: NESSUS_URL=https://nessus-host:8834",
            ENV_PATH,
        )
        sys.exit(1)

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    try:
        if args.auth_method == "apikey":
            access_key = os.environ.get("NESSUS_ACCESS_KEY")
            secret_key = os.environ.get("NESSUS_SECRET_KEY")
            if not access_key or not secret_key:
                logger.error("NESSUS_ACCESS_KEY e/ou NESSUS_SECRET_KEY não definidos.")
                sys.exit(1)
            client = NessusClient(
                base_url,
                access_key=access_key,
                secret_key=secret_key,
                verify_ssl=not args.no_verify_ssl,
            )
        else:
            username = os.environ.get("NESSUS_USERNAME")
            password = os.environ.get("NESSUS_PASSWORD")
            if not username or not password:
                logger.error("NESSUS_USERNAME e/ou NESSUS_PASSWORD não definidos.")
                sys.exit(1)
            client = NessusClient(
                base_url,
                username=username,
                password=password,
                verify_ssl=not args.no_verify_ssl,
            )
    except Exception as exc:
        logger.error("Falha na autenticação com o Nessus: %s", exc)
        sys.exit(1)

    metadata = build_metadata(client, base_url)
    logger.info("Nessus %s em %s", metadata["nessus_version"], metadata["nessus_host"])

    try:
        folders, scans = collect_folders_and_scans(client)
        policies = collect_policies(client)
    except Exception as exc:
        logger.error("Falha durante a coleta de dados: %s", exc)
        sys.exit(1)

    export_json(output_dir, metadata, folders, scans, policies)
    export_csv(output_dir, folders, scans, policies)
    export_xlsx(output_dir, metadata, folders, scans, policies)

    logger.info("Auditoria concluída. Arquivos disponíveis em: %s", output_dir.resolve())


if __name__ == "__main__":
    main()
