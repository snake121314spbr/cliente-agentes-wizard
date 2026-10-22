import {createHash} from 'node:crypto';
import {lstat, readdir, readFile} from 'node:fs/promises';
import path from 'node:path';
import {originFromMetadata} from '../origin.mjs';

/**
 * Small, deterministic SAST baseline for CI pipelines.
 *
 * The scanner is intentionally local-only: it reads the checked-out workspace,
 * never executes the target code. Its optional AI layer separately requires
 * explicit consent before sending bounded, redacted source excerpts. Teams
 * can keep using a specialist SAST engine alongside this policy/evidence layer.
 */
export const SCANNER_VERSION = '1.1.0';
export const SCHEMA_VERSION = '1.0';
export const DEFAULT_LIMITS = Object.freeze({
  maxFiles: 5000,
  maxFileBytes: 1024 * 1024,
  maxTotalBytes: 20 * 1024 * 1024
});

const SEVERITY_ORDER = Object.freeze({critical: 4, high: 3, medium: 2, low: 1, info: 0});
const TEXT_EXTENSIONS = new Set([
  '.c', '.cc', '.cpp', '.cs', '.css', '.go', '.h', '.hpp', '.html', '.java',
  '.js', '.jsx', '.json', '.kt', '.mjs', '.php', '.py', '.rb', '.rs', '.sh',
  '.sql', '.swift', '.ts', '.tsx', '.vue', '.xml', '.yaml', '.yml'
]);
const SKIP_DIRS = new Set(['.git', '.hg', '.svn', 'node_modules', 'vendor', 'coverage',
  '.next', '.nuxt', 'dist', 'build', 'target', 'out', '.venv', 'venv']);

// Rules are deliberately explicit and evidence-producing. They are not a
// replacement for language-aware data-flow analysis; every result is a review
// signal and the recommendation says what to validate before blocking a release.
export const RULES = Object.freeze([
  Object.freeze({
    id: 'LS-SAST-001',
    name: 'Embedded credential or private key',
    severity: 'critical',
    message: 'Possible credential or private key literal in source',
    recommendation: 'Remove the value, rotate it if it was real, and load secrets from the CI secret store or a managed identity.',
    pattern: /(?:-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|(?:AKIA|ASIA)[0-9A-Z]{16}|(?:api[_-]?key|secret|token|password)\s*[:=]\s*["'][^"']{12,}["'])/i
  }),
  Object.freeze({
    id: 'LS-SAST-002',
    name: 'Dynamic code evaluation',
    severity: 'high',
    message: 'Dynamic code evaluation can execute untrusted input',
    recommendation: 'Avoid eval/new Function and use a typed, allow-listed operation instead. If unavoidable, prove the input boundary and add a review exception.',
    pattern: /\b(?:eval|Function)\s*\(/g
  }),
  Object.freeze({
    id: 'LS-SAST-003',
    name: 'Shell command built from interpolation',
    severity: 'high',
    message: 'Shell execution appears to use an interpolated or concatenated command',
    recommendation: 'Use an argument array and an allow-list; do not concatenate request or repository data into shell commands.',
    pattern: /\b(?:exec|execSync|spawn|spawnSync)\s*\(\s*(?:`[^`]*\$\{|[^,\n)]*\+[^,\n)]*)/g
  }),
  Object.freeze({
    id: 'LS-SAST-004',
    name: 'Unsafe HTML sink',
    severity: 'medium',
    message: 'Assignment to an HTML sink can create a DOM injection boundary',
    recommendation: 'Prefer textContent or a trusted templating API and encode untrusted values at the sink.',
    pattern: /\.(?:innerHTML|outerHTML|insertAdjacentHTML)\s*(?:=|\()/g
  }),
  Object.freeze({
    id: 'LS-SAST-005',
    name: 'TLS verification disabled',
    severity: 'high',
    message: 'TLS certificate verification appears to be disabled',
    recommendation: 'Keep certificate verification enabled. Use a managed trust store or a narrowly scoped test certificate only in isolated tests.',
    pattern: /(?:rejectUnauthorized|verify|ssl_verify|verify_ssl)\s*[:=]\s*(?:false|0)|\bCERT_NONE\b/gi
  }),
  Object.freeze({
    id: 'LS-SAST-006',
    name: 'SQL assembled with string interpolation',
    severity: 'medium',
    message: 'SQL text appears to be assembled with interpolation or concatenation',
    recommendation: 'Use parameterized queries or a query builder and keep identifiers on an explicit allow-list.',
    pattern: /\b(?:SELECT|INSERT|UPDATE|DELETE)\b[^\n;]*(?:\$\{|\+\s*[A-Za-z_][A-Za-z0-9_.]*)/gi
  })
]);

const normalizeSeverity = value => {
  const key = String(value || '').trim().toLowerCase();
  return Object.hasOwn(SEVERITY_ORDER, key) ? key : 'info';
};
const severityRank = value => SEVERITY_ORDER[normalizeSeverity(value)] ?? 0;
const safeRelative = (root, filename) => {
  const relative = path.relative(root, filename).split(path.sep).join('/');
  return relative && !relative.startsWith('../') && relative !== '..' ? relative : null;
};
const isTextCandidate = filename => TEXT_EXTENSIONS.has(path.extname(filename).toLowerCase()) || !path.extname(filename);
const lineOf = (text, index) => text.slice(0, index).split('\n').length;
const columnOf = (text, index) => {
  const start = text.lastIndexOf('\n', index - 1);
  return index - (start < 0 ? 0 : start + 1) + 1;
};
const lineText = (text, line) => String(text.split('\n')[line - 1] || '').trim().slice(0, 500);
const fingerprint = values => createHash('sha256').update(values.join('|')).digest('hex').slice(0, 32);

async function listFiles(root, limits) {
  const files = [];
  let totalBytes = 0;
  let truncated = false;
  async function walk(directory) {
    if (truncated) return;
    const entries = await readdir(directory, {withFileTypes: true});
    for (const entry of entries.sort((a, b) => a.name.localeCompare(b.name))) {
      if (truncated) return;
      if (entry.name.startsWith('.') && SKIP_DIRS.has(entry.name)) continue;
      const absolute = path.join(directory, entry.name);
      if (entry.isDirectory()) {
        if (!SKIP_DIRS.has(entry.name)) await walk(absolute);
        continue;
      }
      if (!entry.isFile() || !isTextCandidate(absolute)) continue;
      const info = await lstat(absolute);
      if (!info.isFile()) continue;
      if (files.length >= limits.maxFiles || totalBytes + info.size > limits.maxTotalBytes) {
        truncated = true;
        return;
      }
      if (info.size > limits.maxFileBytes) continue;
      files.push({absolute, relative: safeRelative(root, absolute), bytes: info.size});
      totalBytes += info.size;
    }
  }
  await walk(root);
  return {files, totalBytes, truncated};
}

function ruleMatches(rule, text) {
  const flags = rule.pattern.flags.includes('g') ? rule.pattern.flags : rule.pattern.flags + 'g';
  const pattern = new RegExp(rule.pattern.source, flags);
  return [...text.matchAll(pattern)].slice(0, 40);
}

export async function scanProject(root, options = {}) {
  const absoluteRoot = path.resolve(root || '.');
  const limits = {...DEFAULT_LIMITS, ...(options.limits || {})};
  const selectedRules = Array.isArray(options.ruleIds) && options.ruleIds.length
    ? RULES.filter(rule => options.ruleIds.includes(rule.id))
    : RULES;
  const startedAt = new Date().toISOString();
  const listing = await listFiles(absoluteRoot, limits);
  const findings = [];
  for (const file of listing.files) {
    let source;
    try {
      source = await readFile(file.absolute, 'utf8');
    } catch {
      continue;
    }
    for (const rule of selectedRules) {
      for (const match of ruleMatches(rule, source)) {
        const index = Number(match.index || 0);
        const line = lineOf(source, index);
        const column = columnOf(source, index);
        const evidence = lineText(source, line);
        findings.push({
          id: `${rule.id}:${file.relative}:${line}`,
          ruleId: rule.id,
          ruleName: rule.name,
          severity: rule.severity,
          title: rule.message,
          message: rule.message,
          recommendation: rule.recommendation,
          file: file.relative,
          line,
          column,
          evidence,
          fingerprint: fingerprint([rule.id, file.relative, String(line), evidence])
        });
      }
    }
  }
  const finishedAt = new Date().toISOString();
  const counts = findings.reduce((acc, finding) => {
    acc[finding.severity] = (acc[finding.severity] || 0) + 1;
    return acc;
  }, {});
  const threshold = normalizeSeverity(options.failOn || 'high');
  const blocking = findings.filter(finding => severityRank(finding.severity) >= severityRank(threshold));
  return {
    schemaVersion: SCHEMA_VERSION,
    scanner: {name: 'Lima e Silva Pipeline SAST', version: SCANNER_VERSION},
    root: absoluteRoot,
    startedAt,
    finishedAt,
    status: listing.truncated ? 'partial' : 'completed',
    policy: {failOn: threshold, passed: blocking.length === 0},
    stats: {files: listing.files.length, bytes: listing.totalBytes, truncated: listing.truncated},
    counts,
    findings,
    formats: ['sarif', 'gitlab-sast', 'junit', 'checkstyle', 'json']
  };
}

export function normalizeForUpload(result, metadata = {}) {
  const origin = originFromMetadata(metadata);
  const findings = (Array.isArray(result?.findings) ? result.findings : []).slice(0, 1000).map(finding => ({
    id: String(finding.id || finding.fingerprint || '').slice(0, 180),
    ruleId: String(finding.ruleId || '').slice(0, 80),
    title: String(finding.title || finding.message || 'SAST finding').slice(0, 240),
    severity: normalizeSeverity(finding.severity),
    file: String(finding.file || '').replaceAll('\\', '/').slice(0, 400),
    line: Math.max(1, Math.min(10_000_000, Number(finding.line) || 1)),
    recommendation: String(finding.recommendation || '').slice(0, 700),
    fingerprint: String(finding.fingerprint || '').slice(0, 80),
    ...(finding.source==='ai'?{source:'ai',confidence:finding.confidence,reviewRequired:true}: {})
  }));
  return {
    schemaVersion: SCHEMA_VERSION,
    agentId: 'pipeline-sast',
    scanner: result?.scanner || {name: 'Lima e Silva Pipeline SAST', version: SCANNER_VERSION},
    release: String(metadata.release || metadata.releaseId || '').slice(0, 160),
    repository: String(metadata.repository || '').slice(0, 240),
    commit: String(metadata.commit || metadata.sha || '').slice(0, 160),
    branch: String(metadata.branch || '').slice(0, 160),
    origin,
    policy: {failOn: normalizeSeverity(result?.policy?.failOn || metadata.failOn || 'high'), passed: result?.policy?.passed === true},
    status: result?.status === 'partial' ? 'partial' : 'completed',
    startedAt: String(result?.startedAt || '').slice(0, 48),
    finishedAt: String(result?.finishedAt || '').slice(0, 48),
    stats: result?.stats || {},
    counts: result?.counts || {},
    ...(result?.aiReview?{aiReview:result.aiReview}: {}),
    findings
  };
}

const xmlEscape = value => String(value ?? '').replace(/[<>&"']/g, character => ({'<': '&lt;', '>': '&gt;', '&': '&amp;', '"': '&quot;', "'": '&apos;'}[character]));
const sarifLevel = severity => severity === 'critical' || severity === 'high' ? 'error' : severity === 'medium' ? 'warning' : 'note';
const sarifRule = rule => ({id: rule.id, name: rule.name, shortDescription: {text: rule.message}, fullDescription: {text: rule.recommendation}, help: {text: rule.recommendation}});

export function toSarif(result, metadata = {}) {
  const rules = new Map(RULES.map(rule => [rule.id, rule]));
  if(result.findings.some(f=>f.source==='ai'))rules.set('LS-SAST-AI',{id:'LS-SAST-AI',name:'AI-assisted source review',message:'Evidence-grounded AI review candidate',recommendation:'Validate the code context and the proposed remediation before changing the application.'});
  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: {driver: {name: result.scanner.name, version: result.scanner.version, informationUri: 'https://agentes.limaesilvatecnologia.com.br/recursos/sast-pipeline/', rules: [...rules.values()].map(sarifRule)}},
      invocations: [{executionSuccessful: result.status !== 'failed', commandLine: 'lima-silva-sast', startTimeUtc: result.startedAt, endTimeUtc: result.finishedAt, properties: {release: metadata.release || '', commit: metadata.commit || ''}}],
      artifacts: [...new Set(result.findings.map(finding => finding.file))].map(uri => ({location: {uri}})),
      results: result.findings.map(finding => ({
        ruleId: finding.ruleId,
        level: sarifLevel(finding.severity),
        message: {text: `${finding.message}. ${finding.recommendation}`},
        locations: [{physicalLocation: {artifactLocation: {uri: finding.file}, region: {startLine: finding.line, startColumn: finding.column || 1}}}],
        partialFingerprints: {primaryLocationLineHash: finding.fingerprint},
        properties: {severity: finding.severity,...(finding.source==='ai'?{source:'ai',confidence:finding.confidence,reviewRequired:true}:{})}
      }))
    }]
  };
}

export function toGitlabSast(result, metadata = {}) {
  const scanner = {id: 'lima-silva-sast', name: result.scanner.name, version: result.scanner.version, vendor: {name: 'Lima e Silva Tecnologia'}};
  const vulnerabilities = result.findings.map(finding => ({
    id: finding.fingerprint,
    category: 'sast',
    message: finding.message,
    description: finding.recommendation,
    severity: finding.severity === 'critical' ? 'Critical' : finding.severity[0].toUpperCase() + finding.severity.slice(1),
    confidence: finding.source==='ai'?'Medium':'High',
    scanner,
    identifiers: [{type: 'sast', name: finding.ruleId, value: finding.ruleId}],
    location: {file: finding.file, start_line: finding.line, end_line: finding.line},
    solution: finding.recommendation,
    details: {release: metadata.release || '', commit: metadata.commit || ''}
  }));
  return {version: '15.0.0', scan: {scanner, analyzer: scanner, type: 'sast', start_time: result.startedAt, end_time: result.finishedAt, status: result.status === 'completed' ? 'success' : 'failure', primary_identifiers: RULES.map(rule => rule.id)}, vulnerabilities};
}

export function toJunit(result) {
  const failures = result.findings.filter(finding => severityRank(finding.severity) >= severityRank(result.policy.failOn));
  const cases = result.findings.map(finding => `<testcase classname="${xmlEscape(finding.file)}" name="${xmlEscape(finding.ruleId + ':' + finding.line)}">${failures.includes(finding) ? `<failure type="${xmlEscape(finding.severity)}" message="${xmlEscape(finding.message)}">${xmlEscape(finding.recommendation)}</failure>` : `<system-out>${xmlEscape(finding.message + ' — ' + finding.recommendation)}</system-out>`}</testcase>`).join('');
  const empty = result.findings.length ? '' : '<testcase classname="lima-silva-sast" name="no-findings" />';
  return `<?xml version="1.0" encoding="UTF-8"?><testsuites name="Lima e Silva Pipeline SAST" tests="${result.findings.length || 1}" failures="${failures.length}" errors="0" time="0"><testsuite name="SAST" tests="${result.findings.length || 1}" failures="${failures.length}" errors="0">${cases || empty}</testsuite></testsuites>`;
}

export function toCheckstyle(result) {
  const grouped = new Map();
  for (const finding of result.findings) {
    if (!grouped.has(finding.file)) grouped.set(finding.file, []);
    grouped.get(finding.file).push(finding);
  }
  const files = [...grouped.entries()].map(([file, findings]) => `<file name="${xmlEscape(file)}">${findings.map(finding => `<error line="${finding.line}" column="${finding.column || 1}" severity="${xmlEscape(finding.severity)}" message="${xmlEscape(finding.message)}" source="${xmlEscape(finding.ruleId)}" />`).join('')}</file>`).join('');
  return `<?xml version="1.0" encoding="UTF-8"?><checkstyle version="10.12">${files}</checkstyle>`;
}
