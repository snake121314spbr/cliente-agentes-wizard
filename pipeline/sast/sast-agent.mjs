#!/usr/bin/env node
import {mkdir, readFile, writeFile} from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import {
  SCANNER_VERSION,
  normalizeForUpload,
  scanProject,
  toCheckstyle,
  toGitlabSast,
  toJunit,
  toSarif
} from './core.mjs';
import {uploadResult} from './upload.mjs';
import {reviewWithAi, mergeAiReview} from './ai-review.mjs';
import {withFixStudio, writeFixStudioArtifacts} from '../owasp-fix-studio.mjs';

const usage = `Lima e Silva Pipeline SAST ${SCANNER_VERSION}

Uso:
  node pipeline/sast/sast-agent.mjs --source . --out artifacts/sast

Opções:
  --source <dir>       Raiz do checkout (padrão: .)
  --out <dir>          Diretório dos artefatos (padrão: artifacts/sast)
  --fail-on <level>    critical|high|medium|low|info (padrão: high)
  --release <id>       Identificador da release/build
  --repository <id>    Nome ou URL do repositório (sem código-fonte)
  --commit <sha>       SHA do commit avaliado
  --branch <name>      Branch/tag avaliada
  --origin-id <id>     Identificador estável da origem (repositório/workspace)
  --origin-label <txt> Nome exibido para a origem
  --config <file>      JSON com {"ruleIds":["LS-SAST-001"]}
  --upload <url>       Envia apenas o resumo sanitizado para o Console
  --token <token>      Token de pipeline (ou PIPELINE_SAST_TOKEN)
  --ai-review          Adiciona revisão IA complementar de trechos limitados
  --allow-ai-code-sharing Autoriza envio de trechos higienizados ao Console/provedor IA
  --require-ai         Falha a etapa se a revisão IA solicitada não concluir
  --require-upload     Falha a etapa se o Console não aceitar o resumo
  --help               Mostra esta ajuda

Saídas: sast.sarif, gl-sast-report.json, sast.junit.xml, sast.checkstyle.xml,
sast-result.json. O exit code é 1 quando a política --fail-on é atingida.
`;

function parseArgs(argv) {
  const values = {source: '.', out: 'artifacts/sast', failOn: 'high'};
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === '--help' || arg === '-h') return {help: true};
    if (arg === '--ai-review') { values.aiReview = true; continue; }
    if (arg === '--allow-ai-code-sharing') { values.allowAiCodeSharing = true; continue; }
    if (arg === '--require-ai') { values.requireAi = true; values.aiReview = true; continue; }
    if (arg === '--require-upload') { values.requireUpload = true; continue; }
    if (!arg.startsWith('--')) throw new Error(`Argumento desconhecido: ${arg}`);
    const key = arg.slice(2).replaceAll('-', '_');
    const value = argv[index + 1];
    if (!value || value.startsWith('--')) throw new Error(`Informe um valor para --${key.replaceAll('_', '-')}`);
    index += 1;
    const keys = {fail_on: 'failOn',release: 'release',repository: 'repository',commit: 'commit',branch: 'branch',origin_id: 'originId',origin_label: 'originLabel',source: 'source',out: 'out',config: 'config',upload: 'upload',token: 'token'};
    if (!keys[key]) throw new Error(`Opção desconhecida: --${key.replaceAll('_', '-')}`);
    values[keys[key]] = value;
  }
  return values;
}

const text = value => String(value || '').trim();

async function main() {
  const options = parseArgs(process.argv.slice(2));
  if (options.help) { process.stdout.write(usage); return 0; }
  let config = {};
  if (options.config) {
    const raw = await readFile(options.config, 'utf8');
    config = JSON.parse(raw);
  }
  if(options.aiReview&&!options.allowAiCodeSharing)throw Error('Use --allow-ai-code-sharing para autorizar o envio de trechos higienizados ao Console e ao provedor da IA.');
  let result = await scanProject(options.source, {failOn: options.failOn, ruleIds: config.ruleIds});
  const deterministicComplete=result.status==='completed';
  const metadata = {release: text(options.release) || process.env.GITHUB_RUN_ID || process.env.CI_PIPELINE_ID || process.env.BUILD_TAG || 'local', repository: text(options.repository) || process.env.GITHUB_REPOSITORY || process.env.CI_PROJECT_PATH || process.env.JOB_NAME || '', commit: text(options.commit) || process.env.GITHUB_SHA || process.env.CI_COMMIT_SHA || process.env.GIT_COMMIT || '', branch: text(options.branch) || process.env.GITHUB_REF_NAME || process.env.CI_COMMIT_REF_NAME || process.env.GIT_BRANCH || '', originId: text(options.originId) || process.env.PIPELINE_ORIGIN_ID || process.env.PIPELINE_SOURCE_ID || '', originLabel: text(options.originLabel) || process.env.PIPELINE_ORIGIN_LABEL || ''};
  let aiError=null;
  if(options.aiReview){
    try{result=mergeAiReview(result,await reviewWithAi(options.source,result,metadata,{token:options.token||process.env.PIPELINE_SAST_TOKEN||process.env.PIPELINE_TOKEN,consent:options.allowAiCodeSharing}));}
    catch(error){aiError=String(error?.message||'Revisão IA indisponível').slice(0,240);result.status='partial';result.aiReview={status:'partial',findings:undefined,limitations:[aiError,'A análise determinística foi preservada; a revisão IA não concluiu.']};process.stderr.write('SAST AI: '+aiError+'\n');}
  }
  const out = path.resolve(options.out);
  await mkdir(out, {recursive: true});
  const upload = withFixStudio(normalizeForUpload(result, {...metadata, failOn: options.failOn}), result, {...metadata, agentId: 'pipeline-sast'});
  const outputs = new Map([
    ['sast.sarif', JSON.stringify(toSarif(result, metadata), null, 2)],
    ['gl-sast-report.json', JSON.stringify(toGitlabSast(result, metadata), null, 2)],
    ['sast.junit.xml', toJunit(result)],
    ['sast.checkstyle.xml', toCheckstyle(result)],
    ['sast-result.json', JSON.stringify({...result, ...metadata, upload}, null, 2)]
  ]);
  for (const [filename, content] of outputs) await writeFile(path.join(out, filename), content + (content.endsWith('\n') ? '' : '\n'));
  await writeFixStudioArtifacts(out, result, {...metadata, agentId: 'pipeline-sast'});
  let uploaded = null;
  let uploadError = null;
  if (options.upload) {
    try {
      uploaded = await uploadResult(options.upload, options.token || process.env.PIPELINE_SAST_TOKEN || process.env.PIPELINE_TOKEN, upload);
    } catch (error) {
      uploadError = String(error?.message || 'Falha no upload').slice(0, 240);
      process.stderr.write(`SAST Console upload: ${uploadError}\n`);
      if (options.requireUpload) throw error;
    }
  }
  const summary = {ok: result.policy.passed && result.status === 'completed' && (!options.requireUpload || !!uploaded) && (!options.requireAi || result.aiReview?.status==='completed' || result.aiReview?.status==='not_applicable'), status: result.status, release: metadata.release, repository: metadata.repository, commit: metadata.commit, files: result.stats.files, findings: result.findings.length, counts: result.counts, failOn: result.policy.failOn, policyPassed: result.policy.passed, artifacts: [...outputs.keys(), 'owasp-fix-studio.json', 'owasp-fix-studio.html'], uploaded: !!uploaded, uploadRunId: uploaded?.runId || null, uploadError,aiReview:result.aiReview||{status:'disabled'},aiError};
  process.stdout.write(JSON.stringify(summary) + '\n');
  return result.policy.passed && deterministicComplete && (!options.requireUpload || !!uploaded) && (!options.requireAi || result.aiReview?.status==='completed' || result.aiReview?.status==='not_applicable') ? 0 : 1;
}

main().then(code => { process.exitCode = code; }).catch(error => { process.stderr.write(`SAST: ${error.message}\n`); process.exitCode = 2; });
