import {mkdir, writeFile} from 'node:fs/promises';
import path from 'node:path';
import {originFromMetadata} from './origin.mjs';

// OWASP Fix Studio is a presentation and remediation layer over the
// deterministic pipeline contracts. It never executes a target application,
// sends source code, or claims OWASP certification. The mapping is deliberately
// conservative: a finding can be mapped to more than one category and every
// recommendation remains subject to developer review.
export const STUDIO_VERSION = '1.0.0';
export const STUDIO_SCHEMA_VERSION = '1.0';

const SEVERITY_ORDER = Object.freeze({critical: 4, high: 3, medium: 2, low: 1, info: 0});
const SEVERITIES = Object.freeze(['critical', 'high', 'medium', 'low', 'info']);

export const OWASP_CATALOG = Object.freeze([
  Object.freeze({id: 'A01', title: 'Broken Access Control', short: 'Authorization and tenant boundaries'}),
  Object.freeze({id: 'A02', title: 'Cryptographic Failures', short: 'Secrets, TLS and protected data'}),
  Object.freeze({id: 'A03', title: 'Injection', short: 'Untrusted input and interpreters'}),
  Object.freeze({id: 'A04', title: 'Insecure Design', short: 'Threats, flows and unsafe defaults'}),
  Object.freeze({id: 'A05', title: 'Security Misconfiguration', short: 'Configuration and hardening'}),
  Object.freeze({id: 'A06', title: 'Vulnerable and Outdated Components', short: 'Dependencies and advisories'}),
  Object.freeze({id: 'A07', title: 'Identification and Authentication Failures', short: 'Sessions and identity'}),
  Object.freeze({id: 'A08', title: 'Software and Data Integrity Failures', short: 'Build and release integrity'}),
  Object.freeze({id: 'A09', title: 'Security Logging and Monitoring Failures', short: 'Detection and telemetry'}),
  Object.freeze({id: 'A10', title: 'Server-Side Request Forgery', short: 'Outbound request boundaries'})
]);

const CATEGORY_BY_ID = new Map(OWASP_CATALOG.map(item => [item.id, item]));
const clean = (value, max = 700) => String(value ?? '').replace(/[\u0000-\u001f\u007f]/g, ' ').trim().slice(0, max);
const severity = value => Object.hasOwn(SEVERITY_ORDER, String(value || '').toLowerCase()) ? String(value).toLowerCase() : 'info';
const severityCounts = findings => findings.reduce((acc, finding) => {
  const key = severity(finding.severity);
  acc[key] = (acc[key] || 0) + 1;
  return acc;
}, {});

const mapping = Object.freeze({
  'LS-SAST-001': ['A02', 'A05'],
  'LS-SAST-002': ['A03'],
  'LS-SAST-003': ['A03', 'A05'],
  'LS-SAST-004': ['A03'],
  'LS-SAST-005': ['A02', 'A05'],
  'LS-SAST-006': ['A03']
});

export function categoriesForFinding(agentId, ruleId, supplied = []) {
  const explicit = Array.isArray(supplied) ? supplied.map(value => String(value).toUpperCase()).filter(id => CATEGORY_BY_ID.has(id)) : [];
  if (explicit.length) return [...new Set(explicit)].slice(0, 4);
  if (mapping[ruleId]) return mapping[ruleId];
  if (agentId === 'pipeline-sca') return ['A06'];
  if (agentId === 'pipeline-threat-model') return ['A04'];
  if (agentId === 'pipeline-rasp') return ['A09'];
  return ['A05'];
}

function defaultFix(agentId, finding, categories) {
  const recommendation = clean(finding?.recommendation || finding?.message || 'Revise o achado no contexto da aplicação e registre a decisão de tratamento.');
  const verification = agentId === 'pipeline-sca'
    ? 'Atualize ou isole o componente, gere novamente o SBOM e repita a análise com um snapshot de advisories.'
    : agentId === 'pipeline-threat-model'
      ? 'Atualize o modelo, registre owner e controle, depois repita a revisão antes da release.'
      : agentId === 'pipeline-rasp'
        ? 'Redija a telemetria no adapter, valide a fronteira do tenant e repita o contrato de eventos.'
        : 'Corrija a causa no código, adicione um teste de regressão e execute novamente a pipeline no mesmo commit.';
  return {action: recommendation, verify: verification, categories};
}

function normalizeFinding(agentId, item, index) {
  const ruleId = clean(item?.ruleId || item?.id || `${agentId}-finding-${index}`, 180);
  const categories = categoriesForFinding(agentId, ruleId, item?.owasp || item?.owaspCategories);
  const resource = Array.isArray(item?.resource) ? item.resource.join(', ') : item?.resource || item?.file || item?.path || item?.package || '-';
  const fix = item?.fix && typeof item.fix === 'object' ? item.fix : defaultFix(agentId, item, categories);
  const normalized = {
    id: clean(item?.id || item?.fingerprint || `${ruleId}-${index}`, 180),
    ruleId,
    severity: severity(item?.severity),
    title: clean(item?.title || item?.message || `${agentId} finding`, 240),
    source: clean(item?.source || agentId, 120),
    resource: clean(resource, 420),
    location: clean(item?.file || item?.path || item?.location || '', 420),
    line: Number.isFinite(Number(item?.line)) ? Math.max(1, Math.min(10_000_000, Number(item.line))) : null,
    package: clean(item?.package || '', 220),
    owasp: categories,
    recommendation: clean(fix.action || fix.recommendation || item?.recommendation || '', 700),
    verification: clean(fix.verify || fix.verification || '', 700),
    framework: agentId === 'pipeline-threat-model' ? 'OWASP Threat Modeling' : agentId === 'pipeline-rasp' ? 'OWASP ASVS' : 'OWASP Top 10',
    fingerprint: clean(item?.fingerprint || '', 80)
  };
  // Never let source snippets, secrets or arbitrary connector payloads leak into
  // the portable artifact. Fix Studio carries location and remediation only.
  return normalized;
}

export function buildFixStudio(result = {}, metadata = {}) {
  const agentId = clean(result?.agentId || metadata.agentId || '', 120) || 'pipeline-agent';
  const source = Array.isArray(result?.findings) ? result.findings : Array.isArray(result?.issues) ? result.issues : [];
  const findings = source.slice(0, 1000).map((item, index) => normalizeFinding(agentId, item, index));
  const byCategory = new Map(OWASP_CATALOG.map(category => [category.id, {id: category.id, title: category.title, short: category.short, count: 0, severities: {}}]));
  for (const finding of findings) for (const category of finding.owasp) {
    const row = byCategory.get(category);
    if (!row) continue;
    row.count += 1;
    row.severities[finding.severity] = (row.severities[finding.severity] || 0) + 1;
  }
  const categories = [...byCategory.values()];
  const counts = severityCounts(findings);
  return {
    schemaVersion: STUDIO_SCHEMA_VERSION,
    studio: 'owasp-fix-studio',
    version: STUDIO_VERSION,
    generatedAt: clean(metadata.generatedAt || new Date().toISOString(), 48),
    origin: originFromMetadata(metadata),
    run: {
      agentId,
      release: clean(metadata.release || result.release, 160),
      repository: clean(metadata.repository || result.repository, 240),
      commit: clean(metadata.commit || result.commit, 160),
      branch: clean(metadata.branch || result.branch, 160)
    },
    summary: {findings: findings.length, categoriesWithFindings: categories.filter(item => item.count > 0).length, severities: counts},
    categories,
    findings
  };
}

export function withFixStudio(payload, result = {}, metadata = {}) {
  const studio = buildFixStudio({...result, agentId: payload?.agentId || result?.agentId}, metadata);
  return {...payload, fixStudio: studio};
}

const htmlEscape = value => String(value ?? '').replace(/[&<>"']/g, character => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[character]));
const safeJson = value => JSON.stringify(value).replace(/</g, '\\u003c').replace(/>/g, '\\u003e').replace(/&/g, '\\u0026');

export function renderFixStudioHtml(studio) {
  const title = htmlEscape(studio?.run?.repository ? `OWASP Fix Studio · ${studio.run.repository}` : 'OWASP Fix Studio');
  const data = safeJson(studio);
  return `<!doctype html><html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${title}</title><style>
:root{color-scheme:dark;--bg:#07111d;--panel:#0e1c2c;--line:#233a50;--ink:#f3f7fb;--muted:#9eb5c8;--accent:#79f2d0;--warn:#f5c86b;--danger:#ff857b}*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 80% -10%,#174350 0,#07111d 45%);color:var(--ink);font:15px/1.55 Inter,system-ui,sans-serif}main{max-width:1180px;margin:auto;padding:28px 20px 64px}h1{font-size:clamp(2rem,5vw,3.9rem);line-height:1.02;letter-spacing:-.05em;margin:.25rem 0 1rem}h2{margin:.2rem 0 .4rem}p{color:var(--muted)}.eyebrow{color:var(--accent);letter-spacing:.16em;text-transform:uppercase;font-size:.75rem;font-weight:700}.header{display:flex;justify-content:space-between;gap:18px;align-items:end;border-bottom:1px solid var(--line);padding-bottom:22px;margin-bottom:24px}.meta{font-size:.86rem;color:var(--muted)}.metric-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin:20px 0}.metric,.card{background:#0e1c2cee;border:1px solid var(--line);border-radius:16px;padding:16px}.metric strong{font-size:1.8rem;display:block}.metric span{color:var(--muted);font-size:.82rem}.controls{display:flex;gap:10px;flex-wrap:wrap;margin:20px 0}.controls label{display:grid;gap:5px;color:var(--muted);font-size:.82rem}.controls input,.controls select{background:#07111d;border:1px solid var(--line);border-radius:9px;padding:10px;color:var(--ink);min-width:190px}.categories{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:10px}.category{cursor:pointer;transition:transform .18s,border-color .18s}.category:hover,.category.active{transform:translateY(-2px);border-color:var(--accent)}.category strong{font-size:1.3rem}.category small{display:block;color:var(--muted);min-height:2.8em}.meter{height:7px;background:#07111d;border-radius:99px;overflow:hidden;margin-top:12px}.meter i{display:block;height:100%;background:linear-gradient(90deg,var(--accent),#43a8ba);border-radius:inherit}.findings{display:grid;gap:12px;margin-top:18px}.finding{display:grid;grid-template-columns:auto 1fr auto;gap:14px;align-items:start}.badge{display:inline-flex;border:1px solid var(--line);border-radius:99px;padding:3px 9px;font-size:.76rem;color:var(--accent)}.badge.critical,.badge.high{color:var(--danger);border-color:#713b43}.badge.medium{color:var(--warn);border-color:#6e582e}.path{font-family:ui-monospace,SFMono-Regular,monospace;color:#d4e4ef;font-size:.9rem;overflow-wrap:anywhere}.fix{border-left:2px solid var(--accent);padding-left:12px;margin-top:10px}.empty{color:var(--muted);padding:22px;border:1px dashed var(--line);border-radius:12px}@media(max-width:850px){.categories{grid-template-columns:repeat(2,minmax(0,1fr))}.metric-grid{grid-template-columns:repeat(2,minmax(0,1fr))}.finding{grid-template-columns:1fr}}@media(max-width:520px){.categories,.metric-grid{grid-template-columns:1fr}.header{display:block}}
</style></head><body><main><header class="header"><div><div class="eyebrow">Pipeline · resultado sanitizado</div><h1>OWASP Fix Studio</h1><p>Mapa visual de riscos e próximos passos. O código-fonte permanece na sua CI.</p></div><div class="meta" id="run-meta"></div></header><section class="metric-grid" id="metrics"></section><section class="card"><h2>Mapa OWASP</h2><p>Selecione uma categoria para filtrar os achados. Zero achados significa “não observado nesta execução”, não certificação.</p><div class="categories" id="categories"></div></section><section class="controls"><label>Categoria<select id="category"><option value="">Todas</option></select></label><label>Severidade<select id="severity"><option value="">Todas</option><option>critical</option><option>high</option><option>medium</option><option>low</option><option>info</option></select></label><label>Buscar<input id="search" type="search" placeholder="regra, arquivo ou correção"></label></section><section class="findings" id="findings"></section></main><script>const DATA=${data};const $=id=>document.getElementById(id);const esc=value=>String(value??'');const severities=['critical','high','medium','low','info'];const run=DATA.run||{};$("run-meta").textContent=[run.repository,run.branch,run.commit?'commit '+run.commit:'',run.origin?.label||''].filter(Boolean).join(' · ');const summary=DATA.summary||{};$("metrics").innerHTML=[['Findings',summary.findings||0],['Categorias',summary.categoriesWithFindings||0],['Critical/High',(summary.severities?.critical||0)+(summary.severities?.high||0)],['Origem',run.origin?.label||'não informada']].map(([label,value])=>'<div class="metric"><span>'+esc(label)+'</span><strong>'+esc(value)+'</strong></div>').join('');const categorySelect=$("category");for(const item of DATA.categories||[]){const option=document.createElement('option');option.value=item.id;option.textContent=item.id+' · '+item.title;categorySelect.append(option)}const categoryBox=$("categories");function renderCategories(selected){categoryBox.innerHTML='';for(const item of DATA.categories||[]){const card=document.createElement('article');card.className='card category'+(selected===item.id?' active':'');card.dataset.id=item.id;card.innerHTML='<span class="eyebrow">'+esc(item.id)+'</span><h3>'+esc(item.title)+'</h3><small>'+esc(item.short)+'</small><strong>'+esc(item.count)+'</strong><div class="meter"><i style="width:'+Math.min(100,Math.round((item.count/Math.max(1,summary.findings))*100))+'%"></i></div>';card.onclick=()=>{categorySelect.value=selected===item.id?'':item.id;render()};categoryBox.append(card)}}function render(){const category=categorySelect.value,severity=$("severity").value,search=$("search").value.toLowerCase();renderCategories(category);const rows=(DATA.findings||[]).filter(item=>(!category||item.owasp?.includes(category))&&(!severity||item.severity===severity)&&(!search||[item.ruleId,item.title,item.location,item.package,item.recommendation].join(' ').toLowerCase().includes(search)));$("findings").innerHTML=rows.length?rows.map(item=>'<article class="card finding"><div><span class="badge '+esc(item.severity)+'">'+esc(item.severity)+'</span></div><div><h2>'+esc(item.title)+'</h2><p class="meta">'+esc(item.ruleId)+' · '+esc(item.framework)+' · OWASP '+esc((item.owasp||[]).join(', '))+'</p><p class="path">'+esc(item.location||item.package||item.resource||'escopo não informado')+(item.line?' · linha '+esc(item.line):'')+'</p><div class="fix"><strong>Correção sugerida</strong><p>'+esc(item.recommendation)+'</p><strong>Como validar</strong><p>'+esc(item.verification)+'</p></div></div><div class="meta">'+esc(item.source)+'</div></article>').join(''):'<div class="empty">Nenhum achado corresponde aos filtros desta execução.</div>'}categorySelect.onchange=render;$("severity").onchange=render;$("search").oninput=render;render();</script></body></html>`;
}

export async function writeFixStudioArtifacts(outDirectory, result, metadata = {}) {
  const out = path.resolve(outDirectory);
  await mkdir(out, {recursive: true});
  const studio = buildFixStudio(result, metadata);
  await writeFile(path.join(out, 'owasp-fix-studio.json'), JSON.stringify(studio, null, 2) + '\n');
  await writeFile(path.join(out, 'owasp-fix-studio.html'), renderFixStudioHtml(studio));
  return studio;
}
