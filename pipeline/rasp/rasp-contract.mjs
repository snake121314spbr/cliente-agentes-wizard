import {readFile} from 'node:fs/promises';

export const SCANNER_VERSION = '1.0.0';
const SECRET_KEYS = /(?:password|passwd|secret|token|authorization|private.?key|cookie)/i;
const SECRET_VALUES = /(?:sk-[A-Za-z0-9_-]{16,}|re_[A-Za-z0-9]{16,}|AKIA[0-9A-Z]{16}|-----BEGIN [^-]+ PRIVATE KEY-----)/;
const text = value => String(value ?? '').trim().slice(0, 240);

function issue(issues, id, title, message, severity, path, recommendation) {
  issues.push({id, ruleId: id, title, message, severity, path, recommendation});
}

function inspectObject(value, path, issues) {
  if (!value || typeof value !== 'object') return;
  if (Array.isArray(value)) { value.slice(0, 100).forEach((item, index) => inspectObject(item, `${path}[${index}]`, issues)); return; }
  for (const [key, item] of Object.entries(value)) {
    const current = `${path}.${key}`;
    if (SECRET_KEYS.test(key)) issue(issues, 'RASP-001', 'Sensitive field in runtime event', 'Runtime telemetry contains a field that must be redacted before collection.', 'high', current, 'Redact the field at the adapter and emit only a boolean or bounded category.');
    if (typeof item === 'string' && SECRET_VALUES.test(item)) issue(issues, 'RASP-002', 'Secret-like value in runtime event', 'Runtime telemetry appears to contain a secret-shaped value.', 'critical', current, 'Drop and rotate the value; never send credentials to the telemetry contract.');
    if (typeof item === 'object') inspectObject(item, current, issues);
  }
}

export function validateEvents(events, options = {}) {
  const issues = [];
  const expectedTenant = text(options.tenantId);
  const required = ['eventId', 'tenantId', 'application', 'environment', 'type', 'timestamp', 'severity', 'action', 'redacted'];
  for (const [index, event] of (Array.isArray(events) ? events : []).entries()) {
    const location = `events[${index}]`;
    if (!event || typeof event !== 'object') { issue(issues, 'RASP-000', 'Invalid event', 'Event must be a JSON object.', 'high', location, 'Emit one JSON object per line from the approved runtime adapter.'); continue; }
    for (const key of required) if (event[key] === undefined || event[key] === null || event[key] === '') issue(issues, 'RASP-010', 'Required runtime field is missing', `Missing ${key}.`, 'medium', location, `Emit ${key} from the runtime adapter.`);
    if (expectedTenant && text(event.tenantId) !== expectedTenant) issue(issues, 'RASP-011', 'Tenant boundary mismatch', 'Event tenant does not match the approved validation scope.', 'critical', location, 'Drop the event and fix tenant binding before accepting telemetry.');
    if (event.redacted !== true) issue(issues, 'RASP-012', 'Event is not marked redacted', 'The contract accepts only explicitly redacted telemetry.', 'high', location, 'Redact payloads before sending and set redacted=true.');
    if (typeof event.severity === 'string' && !['critical', 'high', 'medium', 'low', 'info'].includes(event.severity.toLowerCase())) issue(issues, 'RASP-013', 'Invalid severity', 'Severity must be critical, high, medium, low or info.', 'low', location, 'Normalize severity in the adapter.');
    inspectObject(event, location, issues);
  }
  return {schemaVersion: '1.0', scanner: {name: 'Lima e Silva RASP Contract Validator', version: SCANNER_VERSION}, status: 'completed', policy: {failOn: 'high', passed: !issues.some(item => ['critical', 'high'].includes(item.severity))}, stats: {events: Array.isArray(events) ? events.length : 0, issues: issues.length}, issues, limitations: ['This validates a redacted runtime telemetry contract. It is not a RASP engine and does not instrument or block an application by itself.']};
}

const xmlEscape = value => String(value ?? '').replace(/[<>&"']/g, character => ({'<': '&lt;', '>': '&gt;', '&': '&amp;', '"': '&quot;', "'": '&apos;'}[character]));
export function toJunit(result) {
  const failures = (result.issues || []).map(item => `<testcase classname="rasp" name="${xmlEscape(item.path)}"><failure type="${xmlEscape(item.severity)}">${xmlEscape(item.message)} ${xmlEscape(item.recommendation)}</failure></testcase>`).join('');
  return `<?xml version="1.0" encoding="UTF-8"?><testsuite name="Lima e Silva RASP contract" tests="${Math.max(result.stats.events, 1)}" failures="${(result.issues || []).length}">${failures || '<testcase classname="rasp" name="contract"/>'}</testsuite>`;
}

export async function readEvents(filename) {
  const raw = await readFile(filename, 'utf8');
  const parsed = JSON.parse(raw);
  if (Array.isArray(parsed)) return parsed;
  if (Array.isArray(parsed?.events)) return parsed.events;
  return raw.split(/\r?\n/).filter(Boolean).map(line => JSON.parse(line));
}

// Only the bounded validation summary leaves the runner. Runtime events and
// their payloads never belong in the Console upload.
export function normalizeForUpload(result, metadata = {}) {
  return {
    schemaVersion: '1.0',
    agentId: 'pipeline-rasp',
    scanner: result.scanner,
    release: text(metadata.release),
    repository: text(metadata.repository),
    commit: text(metadata.commit),
    branch: text(metadata.branch),
    policy: result.policy,
    stats: result.stats,
    issues: (result.issues || []).slice(0, 1000).map(item => ({
      id: text(item.id || item.ruleId),
      ruleId: text(item.ruleId || item.id),
      title: text(item.title),
      severity: text(item.severity),
      path: text(item.path),
      recommendation: text(item.recommendation)
    }))
  };
}
