# Cliente novo pelo Wizard — GitHub Actions

Conta indicada: snake121314spbr. Nome proposto do repositório: cliente-agentes-wizard. Este projeto é independente do laboratório anterior.

O conteúdo oficial do ZIP está na raiz, incluindo README.md, package.json, manifesto, instaladores e agentes, sem modificações. A aplicação pequena está em app/. O cálculo legado contém eval deliberado para produzir um achado high; não é executado pela aplicação.

## Sequência do cliente

1. Criar o repositório GitHub e confirmar o identificador completo no Wizard. Destino proposto: snake121314spbr/cliente-agentes-wizard.
2. Antes de gerar o token, definir onde ele ficará: Settings → Secrets and variables → Actions → New repository secret, nome PIPELINE_TOKEN.
3. Gerar no Console um token com escopo pipeline-sast e salvar seu valor nesse secret. Nenhum token anterior está neste projeto.
4. Publicar estes arquivos na raiz do repositório e usar .github/workflows/devsecops.yml, reproduzido da configuração fornecida pelo usuário.
5. O push aciona o workflow: checkout → Node 20 → verificação offline do toolkit pré-instalado → conexão → SAST com upload obrigatório → SARIF → artifact devsecops-results.
6. Conferir a execução no Actions e no Console. O achado high deve bloquear SAST com exit 1 **depois** da tentativa de upload. Falha de upload obrigatório encerra com exit 2 pelo CLI oficial; esses códigos diferem do runner personalizado do laboratório anterior, que não é usado aqui.

Não há etapas extras, adaptadores de request/response ou token embutido. Os identificadores GITHUB_RUN_ID, GITHUB_REPOSITORY, GITHUB_SHA e GITHUB_REF_NAME vêm do próprio GitHub Actions. Não é necessário criar variáveis adicionais para esses valores.

## Limites que serão observados no teste do produto

O workflow foi mantido como gerado, inclusive publicação SARIF. Essa etapa depende da disponibilidade do Code Scanning e das permissões do repositório; falhas nela devem ser distinguidas da ingestão no Console. O toolkit do ZIP escreve SARIF e o JSON local, mas não grava o recibo completo de ingestão. Essa limitação será registrada, sem corrigi-la silenciosamente nesta simulação do onboarding.

O manifesto também valida README.md e package.json oficiais na raiz. Não substitua esses dois arquivos pelo README/configuração da aplicação antes de verificar o pacote: isso quebra os hashes. A documentação específica deste cliente fica neste CLIENTE.md justamente para preservar o pacote. O ZIP não é necessário no Git, porque os arquivos extraídos já estão presentes.

Nenhum repositório remoto, secret novo ou execução hospedada é comprovado apenas pela presença desta pasta. Consulte o relatório de preparação separado para o estado efetivo.
