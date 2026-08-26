# Nessus Extractor

Script para extrair informações de uma instância **Nessus Professional**
(standalone) via API, útil para documentar migrações para Tenable One:
policies e scans (configuração completa, targets, schedule, info do servidor).

## O que ele extrai

- Info do servidor (versão do Nessus, feed de plugins)
- Policies (templates de scan e configurações)
- Scans (targets, schedule, detalhe completo por scan)

O resultado é salvo em `output/nessus_export_<data>.json`.

## Requisitos

- Python 3.9+
- Acesso à interface do Nessus Pro (local ou remoto, porta 8834 por padrão)
- API Keys do Nessus **ou** usuário/senha com permissão de leitura

## Instalação

```bash
git clone <url-do-seu-repo>
cd tenable-migration-extractor
pip install -r requirements.txt
```

## Configuração

1. Copie o arquivo de exemplo:
   ```bash
   cp .env.example .env
   ```
2. Preencha o `.env` com um dos dois métodos de autenticação:
   - **API Keys** (recomendado): gere em Nessus Pro > Settings > My Account > API Keys
   - **Usuário/senha**: usado como fallback caso API Keys não estejam disponíveis
     (o script troca por um token de sessão via `/session` e encerra a sessão
     ao final)

## Uso

```bash
python extractor_nessus.py
```

## Sobre o SSL

O Nessus Pro usa certificado autoassinado por padrão, então o script desativa
a verificação SSL (`NESSUS_VERIFY_SSL=false`). Se sua instância tiver um
certificado válido, mude para `true` no `.env`.

## Segurança

- O arquivo `.env` está no `.gitignore` — nunca commite suas credenciais reais.
- A pasta `output/` também é ignorada por padrão, pois os dados extraídos podem
  conter informações sensíveis (nomes de scans, targets, IPs).
- Referências de credenciais usadas nos scans (senhas, chaves) não são
  expostas pela API — apenas metadados.

## Limitações conhecidas

- Nessus Pro standalone não tem conceito de "scanners" múltiplos ou "agent
  groups" gerenciados (isso existe no Tenable.io/Tenable One/Nessus Manager) —
  por isso esses campos não constam aqui.
- A comparação pré/pós migração (validar se tudo foi trazido corretamente para
  o Tenable One) ainda precisa ser feita manualmente.

## Licença

MIT
