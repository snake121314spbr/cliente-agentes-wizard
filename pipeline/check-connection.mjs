#!/usr/bin/env node
import process from 'node:process';
import {checkPipelineConnection, CONSOLE_CONNECTION_PATH, CONSOLE_UPLOAD_ORIGIN} from './sast/upload.mjs';

const DEFAULT_URL = `${CONSOLE_UPLOAD_ORIGIN}${CONSOLE_CONNECTION_PATH}`;
const AGENTS = new Set(['pipeline-sast', 'pipeline-sca', 'pipeline-threat-model', 'pipeline-rasp']);
const usage = `Lima e Silva Pipeline connection check\n\nUso:\n  PIPELINE_TOKEN=... node pipeline/check-connection.mjs --repository org/projeto --agents pipeline-sast,pipeline-sca\n\nOpções:\n  --url <url>          Endpoint de conexão oficial (opcional)\n  --token <token>      Evite em shells compartilhados; prefira PIPELINE_TOKEN\n  --repository <id>    Identificador/URL do repositório sem credenciais (obrigatório para token escopado)\n  --agents <lista>     Agentes esperados, separados por vírgula\n`;

function parseArgs(argv) {
  const values = {url: DEFAULT_URL, agents: [], repository: process.env.PIPELINE_REPOSITORY || process.env.GITHUB_REPOSITORY || process.env.CI_PROJECT_PATH || process.env.JOB_NAME || ''};
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === '--help' || arg === '-h') return {help: true};
    if (!arg.startsWith('--')) throw new Error(`Argumento desconhecido: ${arg}`);
    const key = arg.slice(2).replaceAll('-', '_');
    const value = argv[++index];
    if (!value || value.startsWith('--')) throw new Error(`Informe um valor para --${key.replaceAll('_', '-')}`);
    if (key === 'url') values.url = value;
    else if (key === 'token') values.token = value;
    else if (key === 'repository') values.repository = value;
    else if (key === 'agents') values.agents = value.split(',').map(item => item.trim()).filter(Boolean);
    else throw new Error(`Opção desconhecida: --${key.replaceAll('_', '-')}`);
  }
  return values;
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  if (options.help) { process.stdout.write(usage); return 0; }
  const invalid = options.agents.filter(agent => !AGENTS.has(agent));
  if (invalid.length) throw new Error(`Agente inválido: ${invalid.join(', ')}`);
  const token = options.token || process.env.PIPELINE_TOKEN || process.env.PIPELINE_SAST_TOKEN;
  const result = await checkPipelineConnection(options.url, token, options.agents, {repository: options.repository});
  process.stdout.write(JSON.stringify({ok: true, endpoint: options.url, repository: result.repository || options.repository || null, agents: result.agents || options.agents, requestId: result.requestId || null, checkedAt: result.checkedAt || null}) + '\n');
  return 0;
}

main().then(code => { process.exitCode = code; }).catch(error => { process.stderr.write(`Pipeline connection: ${error.message}\n`); process.exitCode = 2; });
