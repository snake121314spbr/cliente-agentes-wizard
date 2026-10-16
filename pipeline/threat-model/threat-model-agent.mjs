#!/usr/bin/env node
import {mkdir, readFile, writeFile} from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import {normalizeForUpload, reviewModel, SCANNER_VERSION, toJunit, toMarkdown} from './core.mjs';
import {uploadPipelineResult} from '../sast/upload.mjs';

const usage = `Lima e Silva Threat Modeling ${SCANNER_VERSION}\n\nUso:\n  node pipeline/threat-model/threat-model-agent.mjs --model threat-model.json --out artifacts/threat-model\n\nOpções:\n  --model <file>        JSON do modelo estruturado\n  --out <dir>           Diretório dos artefatos (padrão: artifacts/threat-model)\n  --release <id>        Identificador da release/build\n  --repository <id>     Nome do repositório\n  --commit <sha>        SHA avaliado\n  --branch <name>      Branch/tag avaliada\n  --upload <url>        Envia resumo sanitizado ao Console\n  --token <token>       Token de pipeline (ou PIPELINE_TOKEN)\n  --require-upload      Falha se o Console recusar o resumo\n  --help                Mostra esta ajuda\n\nSaídas: threat-model-result.json, threat-model.md, threat-model.junit.xml.\n`;

function parseArgs(argv) {
  const values = {model: '', out: 'artifacts/threat-model'};
  const names = {model: 'model', out: 'out', release: 'release', repository: 'repository', commit: 'commit', branch: 'branch', upload: 'upload', token: 'token'};
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--help' || arg === '-h') return {help: true};
    if (arg === '--require-upload') { values.requireUpload = true; continue; }
    if (!arg.startsWith('--')) throw new Error(`Argumento desconhecido: ${arg}`);
    const key = arg.slice(2).replaceAll('-', '_');
    const value = argv[++i];
    if (!value || value.startsWith('--') || !names[key]) throw new Error(`Informe um valor válido para --${key.replaceAll('_', '-')}`);
    values[names[key]] = value;
  }
  if (!values.model) throw new Error('Informe --model');
  return values;
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  if (options.help) { process.stdout.write(usage); return 0; }
  const model = JSON.parse(await readFile(options.model, 'utf8'));
  const result = reviewModel(model);
  const metadata = {release: options.release || process.env.GITHUB_RUN_ID || process.env.CI_PIPELINE_ID || process.env.BUILD_TAG || 'local', repository: options.repository || process.env.GITHUB_REPOSITORY || process.env.CI_PROJECT_PATH || process.env.JOB_NAME || '', commit: options.commit || process.env.GITHUB_SHA || process.env.CI_COMMIT_SHA || process.env.GIT_COMMIT || '', branch: options.branch || process.env.GITHUB_REF_NAME || process.env.CI_COMMIT_REF_NAME || process.env.GIT_BRANCH || ''};
  const out = path.resolve(options.out);
  await mkdir(out, {recursive: true});
  await writeFile(path.join(out, 'threat-model-result.json'), JSON.stringify({...result, ...metadata, upload: normalizeForUpload(result, metadata)}, null, 2) + '\n');
  await writeFile(path.join(out, 'threat-model.md'), toMarkdown(result));
  await writeFile(path.join(out, 'threat-model.junit.xml'), toJunit(result) + '\n');
  let uploaded = null;
  let uploadError = null;
  if (options.upload) {
    try {
      uploaded = await uploadPipelineResult(options.upload, options.token || process.env.PIPELINE_TOKEN || process.env.PIPELINE_SAST_TOKEN, normalizeForUpload(result, metadata));
    } catch (error) {
      uploadError = String(error?.message || 'Falha no upload').slice(0, 240);
      process.stderr.write(`Threat Model Console upload: ${uploadError}\n`);
      if (options.requireUpload) throw error;
    }
  }
  process.stdout.write(JSON.stringify({ok: result.policy.passed && (!options.requireUpload || !!uploaded), status: result.status, gaps: result.issues.length, artifacts: ['threat-model-result.json', 'threat-model.md', 'threat-model.junit.xml'], uploaded: !!uploaded, uploadRunId: uploaded?.runId || null, uploadError}) + '\n');
  return result.policy.passed && (!options.requireUpload || !!uploaded) ? 0 : 1;
}

main().then(code => { process.exitCode = code; }).catch(error => { process.stderr.write(`Threat Model: ${error.message}\n`); process.exitCode = 2; });
