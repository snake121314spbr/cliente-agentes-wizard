import {createHash} from 'node:crypto';

export const SCANNER_VERSION = '1.0.0';
export const SCHEMA_VERSION = '1.0';
const ORDER = Object.freeze({critical: 4, high: 3, medium: 2, low: 1, info: 0});
const severity = value => {
  const key = String(value || '').toLowerCase();
  return Object.hasOwn(ORDER, key) ? key : 'medium';
};
const rank = value => ORDER[severity(value)] ?? 2;
const hash = values => createHash('sha256').update(values.join('|')).digest('hex').slice(0, 32);
const text = value => String(value ?? '').trim().slice(0, 500);

function issue(issues, id, title, message, level, path, recommendation) {
  issues.push({id, ruleId: id, title, message, severity: severity(level), path, recommendation, fingerprint: hash([id, path, message])});
}

export function reviewModel(model) {
  const issues = [];
  const value = model && typeof model === 'object' ? model : {};
  const arrays = [['assets', 'TM-001', 'No assets are defined in the threat model'], ['trustBoundaries', 'TM-002', 'No trust boundary is defined'], ['dataFlows', 'TM-003', 'No data flow is defined'], ['threats', 'TM-004', 'No threat is recorded']];
  for (const [field, id, message] of arrays) if (!Array.isArray(value[field]) || !value[field].length) issue(issues, id, 'Incomplete threat model', message, 'high', field, `Define ${field} before treating the model as reviewed.`);
  const ids = new Set();
  for (const [index, item] of (Array.isArray(value.assets) ? value.assets : []).entries()) {
    if (!item || !text(item.id || item.name)) issue(issues, 'TM-010', 'Asset without identifier', 'Every asset needs a stable id or name.', 'medium', `assets[${index}]`, 'Add a stable identifier and owner for the asset.');
  }
  for (const [index, flow] of (Array.isArray(value.dataFlows) ? value.dataFlows : []).entries()) {
    const missing = ['source', 'destination', 'data'].filter(field => !text(flow?.[field]));
    if (missing.length) issue(issues, 'TM-011', 'Data flow is incomplete', `Missing: ${missing.join(', ')}`, 'high', `dataFlows[${index}]`, 'Describe the source, destination and data crossing the flow.');
    if (!text(flow?.trustBoundary)) issue(issues, 'TM-012', 'Data flow has no trust boundary', 'The flow does not state which boundary it crosses.', 'medium', `dataFlows[${index}]`, 'Map the flow to an explicit trust boundary.');
  }
  for (const [index, threat] of (Array.isArray(value.threats) ? value.threats : []).entries()) {
    const id = text(threat?.id || threat?.name);
    const location = `threats[${index}]`;
    if (!id) issue(issues, 'TM-020', 'Threat without identifier', 'Each threat needs a stable id.', 'high', location, 'Give the threat a stable identifier to deduplicate reviews.');
    else if (ids.has(id)) issue(issues, 'TM-021', 'Duplicate threat identifier', `Threat id ${id} is repeated.`, 'medium', location, 'Use one stable id per threat and update the existing record.');
    else ids.add(id);
    for (const field of ['title', 'asset', 'owner', 'status']) if (!text(threat?.[field])) issue(issues, 'TM-022', 'Threat review metadata is missing', `Missing ${field}.`, 'medium', location, 'Record an owner, affected asset, status and clear title.');
    if (!Array.isArray(threat?.controls) || !threat.controls.length) issue(issues, 'TM-023', 'Threat has no control or decision', 'No mitigation, acceptance or transfer decision is recorded.', 'high', location, 'Record a control, acceptance rationale or transfer decision and its owner.');
  }
  const threshold = severity('high');
  const blocking = issues.filter(item => rank(item.severity) >= rank(threshold));
  return {
    schemaVersion: SCHEMA_VERSION,
    scanner: {name: 'Lima e Silva Threat Modeling Review', version: SCANNER_VERSION},
    status: 'completed',
    policy: {failOn: threshold, passed: blocking.length === 0},
    counts: issues.reduce((acc, item) => { acc[item.severity] = (acc[item.severity] || 0) + 1; return acc; }, {}),
    stats: {assets: Array.isArray(value.assets) ? value.assets.length : 0, trustBoundaries: Array.isArray(value.trustBoundaries) ? value.trustBoundaries.length : 0, dataFlows: Array.isArray(value.dataFlows) ? value.dataFlows.length : 0, threats: Array.isArray(value.threats) ? value.threats.length : 0, gaps: issues.length},
    issues,
    limitations: ['This is a structured review of the supplied model, not automatic architecture discovery or proof that a threat is exploitable.']
  };
}

export function toMarkdown(result) {
  const rows = (result.issues || []).map(item => `- **${item.severity} · ${item.ruleId}** ${item.title} (${item.path}) — ${item.recommendation}`).join('\n');
  return `# Threat model review\n\nStatus: ${result.policy.passed ? 'passed' : 'needs review'}\n\n${rows || 'No model gaps were found by this structural review.'}\n\n> This report validates model completeness; it is not a penetration test or an approval of production design.\n`;
}

const xmlEscape = value => String(value ?? '').replace(/[<>&"']/g, character => ({'<': '&lt;', '>': '&gt;', '&': '&amp;', '"': '&quot;', "'": '&apos;'}[character]));
export function toJunit(result) {
  const failures = (result.issues || []).map(item => `<testcase classname="threat-model" name="${xmlEscape(item.path)}"><failure type="${xmlEscape(item.severity)}">${xmlEscape(item.message)} ${xmlEscape(item.recommendation)}</failure></testcase>`).join('');
  return `<?xml version="1.0" encoding="UTF-8"?><testsuite name="Lima e Silva Threat Modeling" tests="${Math.max(result.stats.threats, 1)}" failures="${(result.issues || []).length}">${failures || '<testcase classname="threat-model" name="model"/>'}</testsuite>`;
}

export function normalizeForUpload(result, metadata = {}) {
  return {schemaVersion: SCHEMA_VERSION, agentId: 'pipeline-threat-model', scanner: result.scanner, release: text(metadata.release), repository: text(metadata.repository), commit: text(metadata.commit), branch: text(metadata.branch), policy: result.policy, stats: result.stats, issues: (result.issues || []).slice(0, 1000).map(item => ({id: item.id, ruleId: item.ruleId, title: item.title, severity: item.severity, path: item.path, recommendation: item.recommendation, fingerprint: item.fingerprint}))};
}
