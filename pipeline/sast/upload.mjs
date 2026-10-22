// The pipeline can upload only the sanitized result to the first-party
// Console. Keep this policy in a side-effect-free module so it is covered by
// unit tests and cannot be widened by a caller-provided host or path.
export const CONSOLE_UPLOAD_ORIGIN = 'https://thiago.limaesilvatecnologia.com.br';
export const CONSOLE_CONNECTION_PATH = '/console/api/pipeline/connection';
export const CONSOLE_INGEST_PATH = '/console/api/pipeline/ingest';
// Kept for older SAST snippets already copied by customers.
export const CONSOLE_UPLOAD_PATH = '/console/api/pipeline/sast/ingest';

export function safePipelineUrl(value, allowedPaths = [CONSOLE_INGEST_PATH, CONSOLE_UPLOAD_PATH, CONSOLE_CONNECTION_PATH]) {
  const url = new URL(value);
  if (url.origin !== CONSOLE_UPLOAD_ORIGIN || !allowedPaths.includes(url.pathname) ||
      url.search || url.username || url.password || url.hash) {
    throw new Error('O upload exige o endpoint HTTPS oficial do Console, sem query, credenciais ou fragmento.');
  }
  return url;
}

export function safeUploadUrl(value) {
  return safePipelineUrl(value, [CONSOLE_INGEST_PATH, CONSOLE_UPLOAD_PATH]);
}

export function pipelineTokenValid(token) {
  return /^(?:agt_sast_|agt_pipeline_)[A-Za-z0-9_-]{24,200}$/.test(String(token || '').trim());
}

function assertToken(token) {
  if (!pipelineTokenValid(token)) {
    throw new Error('Token de pipeline ausente ou inválido. Gere um token no Wizard DevSecOps do Console.');
  }
}

function pipelineNetworkError(label, url, error) {
  const code = String(error?.cause?.code || error?.cause?.errno || error?.name || 'FETCH_FAILED');
  const host = new URL(url).hostname;
  return new Error(`${label} indisponível (${code}). Verifique DNS, saída TCP/443, proxy e allowlist para ${host}.`, {cause: error});
}

async function pipelineFetch(label, url, options) {
  try {
    return await fetch(url, options);
  } catch (error) {
    throw pipelineNetworkError(label, url, error);
  }
}

function pipelineResponseError(label, status, data) {
  const code = typeof data?.code === 'string' ? data.code : 'HTTP_ERROR';
  const stage = typeof data?.stage === 'string' ? data.stage : 'remote';
  const detail = typeof data?.error === 'string' ? data.error.replace(/[\r\n]+/g, ' ').slice(0, 220) : 'O serviço não aceitou a solicitação.';
  const retryable = data?.retryable === true ? ' Tente novamente após a janela indicada' : '';
  return new Error(`${label} recusado (HTTP ${status}, ${code}, etapa ${stage}).${retryable} ${detail}`);
}

export async function uploadPipelineResult(url, token, payload) {
  assertToken(token);
  const safeUrl = safeUploadUrl(url);
  const response = await pipelineFetch('Upload ao Console', safeUrl, {
    method: 'POST',
    redirect: 'error',
    signal: AbortSignal.timeout(15000),
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json',
      'X-Release-Id': payload.release || 'pipeline-release'
    },
    body: JSON.stringify(payload)
  });
  const body = await response.text();
  let data;
  try { data = JSON.parse(body); } catch { data = {raw: body.slice(0, 500)}; }
  if (!response.ok) throw pipelineResponseError('Upload ao Console', response.status, data);
  return data;
}

// Backwards-compatible name used by the original SAST agent.
export async function uploadResult(url, token, payload) {
  return uploadPipelineResult(url, token, payload);
}

export async function checkPipelineConnection(url, token, agents = [], metadata = {}) {
  assertToken(token);
  const safeUrl = safePipelineUrl(url, [CONSOLE_CONNECTION_PATH]);
  const response = await pipelineFetch('Conexão com o Console', safeUrl, {
    method: 'POST',
    redirect: 'error',
    signal: AbortSignal.timeout(15000),
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      agents: Array.isArray(agents) && agents.length ? agents.slice(0, 8) : undefined,
      repository: typeof metadata?.repository === 'string' && metadata.repository.trim() ? metadata.repository.trim().slice(0, 240) : undefined,
      origin: metadata?.origin && typeof metadata.origin === 'object' ? metadata.origin : undefined
    })
  });
  const body = await response.text();
  let data;
  try { data = JSON.parse(body); } catch { data = {raw: body.slice(0, 500)}; }
  if (!response.ok) throw pipelineResponseError('Teste de conexão', response.status, data);
  return data;
}
