# Lima e Silva DevSecOps Toolkit 1.0.0

Este kit contém os arquivos oficiais que o Wizard DevSecOps referencia. Ele não
usa dependências npm externas: requer Node.js 20+ e executa no checkout da sua
pipeline.

## Instalação verificável (com internet na máquina da CI)

Baixe o instalador desta mesma versão e execute-o em um diretório de trabalho:

```bash
curl --fail --proto '=https' --tlsv1.2 -o pipeline-install.mjs https://agentes.limaesilvatecnologia.com.br/downloads/devsecops-toolkit/1.0.0/install.mjs
node pipeline-install.mjs --dest .
```

O instalador baixa `manifest.json`, verifica SHA-256 de cada arquivo e recusa
caminhos fora do checkout. Depois disso, o agente estará em
`pipeline/sast/sast-agent.mjs` e os demais agentes em `pipeline/`.

## Ambiente sem saída para a internet

Baixe o pacote ZIP em uma máquina autorizada com acesso HTTPS, transfira-o
para o ambiente isolado e extraia-o na raiz do checkout:

```bash
unzip -q devsecops-toolkit-1.0.0.zip -d .
node pipeline-install.mjs --offline --dest .
```

O ZIP contém o manifesto, o instalador e todos os agentes/dependências. O modo
`--offline` apenas verifica os SHA-256 locais e não faz nenhuma conexão externa.

## Execução

```bash
node pipeline/check-connection.mjs --agents pipeline-sast
node pipeline/sast/sast-agent.mjs --source . --out artifacts/sast --fail-on high
```

Guarde o token do Console somente como `PIPELINE_TOKEN` no secret store do
GitHub Actions, GitLab CI/CD ou Jenkins. Para upload, acrescente `--upload`,
`--token "$PIPELINE_TOKEN"` e `--require-upload` conforme o workflow gerado.

O código-fonte, dependências da aplicação, segredos e telemetria permanecem na
CI do cliente. O Console recebe somente resumos e findings sanitizados.
