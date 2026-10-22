#!/usr/bin/env node
import {mkdir, readFile, writeFile} from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import {collectInventory, normalizeForUpload, scanInventory, toCycloneDx, toJunit, SCANNER_VERSION} from './core.mjs';
import {uploadPipelineResult} from '../sast/upload.mjs';
import {withFixStudio, writeFixStudioArtifacts} from '../owasp-fix-studio.mjs';

const usage = `Lima e Silva Pipeline SCA ${SCANNER_VERSION}\n\nUso:\n  node pipeline/sca/sca-agent.mjs --source . --out artifacts/sca\n\nOpções:\n  --source <dir>       Raiz do checkout (padrão: .)\n  --out <dir>          Diretório dos artefatos (padrão: artifacts/sca)\n  --advisories <file>  Snapshot JSON local de advisories (opcional)\n  --fail-on <level>    critical|high|medium|low|info (padrão: high)\n  --release <id>       Identificador da release/build\n  --repository <id>    Nome ou URL do repositório\n  --commit <sha>       SHA avaliado\n  --branch <name>      Branch/tag avaliada\n  --origin-id <id>     Identificador estável da origem (repositório/workspace)\n  --origin-label <txt> Nome exibido para a origem\n  --upload <url>       Envia resumo sanitizado ao Console\n  --token <token>      Token de pipeline (ou PIPELINE_TOKEN)\n  --require-upload     Falha se o Console recusar o resumo\n  --help               Mostra esta ajuda\n\nSaídas: sca-result.json, bom.cdx.json, sca.junit.xml. Sem snapshot, o resultado é inventory-only.\n`;

function parseArgs(argv) {
  const values = {source: '.', out: 'artifacts/sca', failOn: 'high'};
  const names = {source: 'source', out: 'out', advisories: 'advisories', fail_on: 'failOn', release: 'release', repository: 'repository', commit: 'commit', branch: 'branch', origin_id: 'originId', origin_label: 'originLabel', upload: 'upload', token: 'token'};
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
  return values;
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  if (options.help) { process.stdout.write(usage); return 0; }
  let advisories = [];
  if (options.advisories) advisories = JSON.parse(await readFile(options.advisories, 'utf8'));
  const source = path.resolve(options.source);
  const result = scanInventory(await collectInventory(source), {advisories, failOn: options.failOn});
  const metadata = {release: options.release || process.env.GITHUB_RUN_ID || process.env.CI_PIPELINE_ID || process.env.BUILD_TAG || 'local', repository: options.repository || process.env.GITHUB_REPOSITORY || process.env.CI_PROJECT_PATH || process.env.JOB_NAME || '', commit: options.commit || process.env.GITHUB_SHA || process.env.CI_COMMIT_SHA || process.env.GIT_COMMIT || '', branch: options.branch || process.env.GITHUB_REF_NAME || process.env.CI_COMMIT_REF_NAME || process.env.GIT_BRANCH || '', originId: options.originId || process.env.PIPELINE_ORIGIN_ID || process.env.PIPELINE_SOURCE_ID || '', originLabel: options.originLabel || process.env.PIPELINE_ORIGIN_LABEL || ''};
  const out = path.resolve(options.out);
  await mkdir(out, {recursive: true});
  const upload = withFixStudio(normalizeForUpload(result, metadata), {...result, agentId: 'pipeline-sca'}, {...metadata, agentId: 'pipeline-sca'});
  await writeFile(path.join(out, 'sca-result.json'), JSON.stringify({...result, ...metadata, upload}, null, 2) + '\n');
  await writeFile(path.join(out, 'bom.cdx.json'), JSON.stringify(toCycloneDx(result), null, 2) + '\n');
  await writeFile(path.join(out, 'sca.junit.xml'), toJunit(result) + '\n');
  await writeFixStudioArtifacts(out, {...result, agentId: 'pipeline-sca'}, {...metadata, agentId: 'pipeline-sca'});
  let uploaded = null;
  let uploadError = null;
  if (options.upload) {
    try {
      uploaded = await uploadPipelineResult(options.upload, options.token || process.env.PIPELINE_TOKEN || process.env.PIPELINE_SAST_TOKEN, upload);
    } catch (error) {
      uploadError = String(error?.message || 'Falha no upload').slice(0, 240);
      process.stderr.write(`SCA Console upload: ${uploadError}\n`);
      if (options.requireUpload) throw error;
    }
  }
  const summary = {ok: result.policy.passed && (!options.requireUpload || !!uploaded), status: result.status, advisoryMode: result.advisoryMode, packages: result.stats.packages, findings: result.stats.findings, artifacts: ['sca-result.json', 'bom.cdx.json', 'sca.junit.xml', 'owasp-fix-studio.json', 'owasp-fix-studio.html'], policyPassed: result.policy.passed, failOn: result.policy.failOn, uploaded: !!uploaded, uploadRunId: uploaded?.runId || null, uploadError};
  process.stdout.write(JSON.stringify(summary) + '\n');
  return result.policy.passed && (!options.requireUpload || !!uploaded) ? 0 : 1;
}

main().then(code => { process.exitCode = code; }).catch(error => { process.stderr.write(`SCA: ${error.message}\n`); process.exitCode = 2; });
