# Lima e Silva DevSecOps Toolkit 1.1.0

Este kit contém os arquivos oficiais que o Wizard DevSecOps referencia. Ele não
usa dependências npm externas: requer Node.js 20+ e executa no checkout da sua
pipeline.

## Instalação verificável (com internet na máquina da CI)

Baixe o instalador desta mesma versão e execute-o em um diretório de trabalho:

```bash
curl --fail --proto '=https' --tlsv1.2 -o pipeline-install.mjs https://agentes.limaesilvatecnologia.com.br/downloads/devsecops-toolkit/1.1.0/install.mjs
node pipeline-install.mjs --dest .
```

O instalador baixa `manifest.json`, verifica SHA-256 de cada arquivo e recusa
caminhos fora do checkout. Depois disso, o agente estará em
`pipeline/sast/sast-agent.mjs` e os demais agentes em `pipeline/`.

Cada agente selecionado também grava `owasp-fix-studio.json` e
`owasp-fix-studio.html` em seu diretório de artefatos. O HTML é um mapa
interativo de categorias OWASP, severidade, localização e correção sugerida;
o Console agrega o mesmo resultado por repositório, branch e commit.

## Ambiente sem saída para a internet

Baixe o pacote ZIP em uma máquina autorizada com acesso HTTPS, transfira-o
para o ambiente isolado e extraia-o na raiz do checkout:

```bash
unzip -q devsecops-toolkit-1.1.0.zip -d .
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

Por padrão a análise estática é local e o upload recebe somente resumos e findings
sanitizados. A revisão opcional por IA requer consentimento explícito:

```bash
node pipeline/sast/sast-agent.mjs --source . --out artifacts/sast --repository org/repo --ai-review --allow-ai-code-sharing
```

Use `PIPELINE_TOKEN` com escopo SAST associado ao repositório. A revisão usa
`POST https://thiago.limaesilvatecnologia.com.br/console/api/pipeline/sast/ai-review`.
A chave da IA fica no backend; não copie essa chave para a CI. Somente trechos
limitados e redigidos são enviados transitoriamente ao Console/OpenAI, sem persistir
os trechos no banco do Console. O repositório completo não é enviado. A redação
automática reduz exposição, mas revise a política da sua empresa antes de autorizar.
Use `--require-ai` se uma falha da revisão por IA precisar reprovar a etapa;
sem esse parâmetro, confira o estado parcial e as limitações nos artefatos.
Achados da IA são sugestões vinculadas a arquivo, linha e evidência; exigem revisão
humana e não garantem a detecção de todas as vulnerabilidades.
