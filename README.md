# Auditoria Nessus Pro (pré-migração Tenable One)

Script para levantar e documentar o estado atual de um Nessus Professional
(pastas de scans, scans e policies) antes de uma migração para o Tenable One.

## Como usar

1. Instale as dependências:
   ```
   pip install -r requirements.txt
   ```

2. Renomeie `.env.example` para `.env` e preencha com as credenciais do Nessus.
   Mantenha o `.env` na MESMA pasta do script.

3. Execute:
   ```
   python3 nessus_pre_migration_audit.py
   ```

   Ou, para autenticação via login/senha em vez de API keys:
   ```
   python3 nessus_pre_migration_audit.py --auth-method password
   ```

4. Os relatórios são gerados em `./nessus_audit_output/`:
   - `nessus_audit.json`
   - `pastas.csv`, `scans.csv`, `policies.csv`
   - `nessus_audit.xlsx`

## Observações

- Nunca versionar o `.env` real (adicione ao `.gitignore`).
- Use `--no-verify-ssl` apenas se o Nessus usar certificado self-signed conhecido.
- Use `--output-dir <pasta>` para mudar onde os relatórios são salvos.
