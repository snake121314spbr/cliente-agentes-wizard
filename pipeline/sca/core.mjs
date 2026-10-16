import {createHash} from 'node:crypto';
import {readFile} from 'node:fs/promises';
import path from 'node:path';

/**
 * Deterministic dependency inventory for CI.
 *
 * The collector is deliberately offline: it reads lockfiles/package manifests
 * and an optional advisory snapshot supplied by the team. It never resolves
 * packages, executes install scripts or calls an advisory service. Findings
 * are only emitted when the caller supplies a matching, reviewable snapshot.
 */
export const SCANNER_VERSION = '1.0.0';
export const SCHEMA_VERSION = '1.0';
const SEVERITY_ORDER = Object.freeze({critical: 4, high: 3, medium: 2, low: 1, info: 0});
const normalizeSeverity = value => {
  const key = String(value || '').trim().toLowerCase();
  return Object.hasOwn(SEVERITY_ORDER, key) ? key : 'info';
};
const severityRank = value => SEVERITY_ORDER[normalizeSeverity(value)] ?? 0;
const fingerprint = values => createHash('sha256').update(values.join('|')).digest('hex').slice(0, 32);
const clean = value => String(value ?? '').trim().slice(0, 300);

function add(inventory, name, version, source, dependencyType = 'unknown') {
  const packageName = clean(name);
  const packageVersion = clean(version) || '*';
  if (!packageName || packageName.length > 220) return;
  inventory.push({name: packageName, version: packageVersion, source, dependencyType});
}

function parsePackageLock(raw, source) {
  const data = JSON.parse(raw);
  const inventory = [];
  if (data.packages && typeof data.packages === 'object') {
    for (const [location, item] of Object.entries(data.packages)) {
      if (!location || !item || typeof item !== 'object') continue;
      const name = item.name || location.replace(/^node_modules\//, '').split('node_modules/').at(-1);
      add(inventory, name, item.version, source, item.dev ? 'dev' : item.optional ? 'optional' : 'runtime');
    }
  }
  if (!inventory.length && data.dependencies && typeof data.dependencies === 'object') {
    const walk = (deps, prefix = '') => {
      for (const [name, item] of Object.entries(deps || {})) {
        if (!item || typeof item !== 'object') continue;
        add(inventory, name, item.version, source, item.dev ? 'dev' : 'runtime');
        walk(item.dependencies, `${prefix}${name}/`);
      }
    };
    walk(data.dependencies);
  }
  return inventory;
}

function parsePackageManifest(raw, source) {
  const data = JSON.parse(raw);
  const inventory = [];
  for (const [field, dependencyType] of [['dependencies', 'runtime'], ['optionalDependencies', 'optional'], ['devDependencies', 'dev'], ['peerDependencies', 'peer']]) {
    for (const [name, version] of Object.entries(data[field] || {})) add(inventory, name, version, source, dependencyType);
  }
  return inventory;
}

function parseRequirements(raw, source) {
  const inventory = [];
  for (const line of raw.split(/\r?\n/)) {
    const match = /^\s*([A-Za-z0-9_.-]+)\s*(?:===|==|~=|>=|<=|>|<)?\s*([A-Za-z0-9_.!*+:-]+)?/.exec(line.split('#', 1)[0]);
    if (match?.[1]) add(inventory, match[1], match[2] || '*', source, 'runtime');
  }
  return inventory;
}

function parseGoSum(raw, source) {
  const inventory = [];
  for (const line of raw.split(/\r?\n/)) {
    const parts = line.trim().split(/\s+/);
    if (parts.length >= 2 && parts[0] && parts[1] && !parts[1].endsWith('/go.mod')) add(inventory, parts[0], parts[1], source, 'runtime');
  }
  return inventory;
}

function parseCargoLock(raw, source) {
  const inventory = [];
  let current = {};
  const flush = () => {
    if (current.name && current.version) add(inventory, current.name, current.version, source, 'runtime');
    current = {};
  };
  for (const line of raw.split(/\r?\n/)) {
    if (line.trim() === '[[package]]') { flush(); continue; }
    const match = /^\s*(name|version)\s*=\s*["']([^"']+)["']/.exec(line);
    if (match) current[match[1]] = match[2];
  }
  flush();
  return inventory;
}

function parseLockText(raw, source) {
  const inventory = [];
  let currentName = '';
  for (const line of raw.split(/\r?\n/)) {
    const header = /^\s*["']?(@?[^"'@\s]+(?:\/[^"'@\s]+)?)@[^:]+:["']?\s*$/.exec(line);
    if (header) { currentName = header[1]; continue; }
    const version = /^\s*version\s+["']([^"']+)["']/.exec(line);
    if (currentName && version) add(inventory, currentName, version[1], source, 'runtime');
  }
  return inventory;
}

export async function collectInventory(root) {
  const files = [
    ['package-lock.json', parsePackageLock],
    ['npm-shrinkwrap.json', parsePackageLock],
    ['package.json', parsePackageManifest],
    ['requirements.txt', parseRequirements],
    ['requirements-prod.txt', parseRequirements],
    ['go.sum', parseGoSum],
    ['Cargo.lock', parseCargoLock],
    ['yarn.lock', parseLockText],
  ];
  const inventory = [];
  const sources = [];
  for (const [filename, parser] of files) {
    try {
      const sourcePath = path.join(root, filename);
      const raw = await readFile(sourcePath, 'utf8');
      const parsed = parser(raw, filename);
      inventory.push(...parsed);
      sources.push({file: filename, entries: parsed.length});
      // A lockfile is authoritative for its ecosystem; do not double-count
      // package.json when its lockfile was found.
      if (filename === 'package-lock.json' || filename === 'npm-shrinkwrap.json') break;
    } catch (error) {
      if (error?.code !== 'ENOENT') sources.push({file: filename, error: 'unreadable'});
    }
  }
  const unique = new Map();
  for (const item of inventory) unique.set(`${item.name}\0${item.version}`, item);
  return {inventory: [...unique.values()].sort((a, b) => `${a.name}@${a.version}`.localeCompare(`${b.name}@${b.version}`)), sources};
}

function matches(advisory, item) {
  const packageName = advisory.package || advisory.name || advisory.packageName;
  const packageVersion = advisory.version || advisory.packageVersion || '*';
  return String(packageName || '') === item.name && (packageVersion === '*' || String(packageVersion) === item.version);
}

export function normalizeAdvisories(input) {
  const values = Array.isArray(input) ? input : input?.advisories;
  return Array.isArray(values) ? values.filter(item => item && typeof item === 'object') : [];
}

export function scanInventory(inventoryResult, options = {}) {
  const advisories = normalizeAdvisories(options.advisories);
  const findings = [];
  for (const item of inventoryResult.inventory || []) {
    for (const advisory of advisories) {
      if (!matches(advisory, item)) continue;
      const severity = normalizeSeverity(advisory.severity || 'medium');
      const id = clean(advisory.id || advisory.cve || advisory.ghsa || 'LS-SCA-ADVISORY');
      findings.push({
        id: `${id}:${item.name}@${item.version}`,
        ruleId: id,
        title: clean(advisory.title || `Advisory for ${item.name}`),
        message: clean(advisory.message || advisory.title || 'Dependency matched a supplied advisory snapshot'),
        recommendation: clean(advisory.recommendation || 'Review the advisory and upgrade, pin or isolate the dependency.'),
        severity,
        package: item.name,
        version: item.version,
        source: item.source,
        fingerprint: fingerprint([id, item.name, item.version])
      });
    }
  }
  const counts = findings.reduce((acc, item) => { acc[item.severity] = (acc[item.severity] || 0) + 1; return acc; }, {});
  const threshold = normalizeSeverity(options.failOn || 'high');
  const blocking = findings.filter(item => severityRank(item.severity) >= severityRank(threshold));
  return {
    schemaVersion: SCHEMA_VERSION,
    scanner: {name: 'Lima e Silva Pipeline SCA', version: SCANNER_VERSION},
    status: 'completed',
    advisoryMode: advisories.length ? 'snapshot' : 'inventory-only',
    policy: {failOn: threshold, passed: blocking.length === 0},
    inventory: inventoryResult.inventory || [],
    sources: inventoryResult.sources || [],
    stats: {packages: (inventoryResult.inventory || []).length, advisories: advisories.length, findings: findings.length},
    counts,
    findings,
    limitations: advisories.length ? ['Only the supplied advisory snapshot was evaluated.'] : ['No advisory database was consulted; inventory/SBOM output is not a vulnerability verdict.']
  };
}

export function toCycloneDx(result) {
  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    serialNumber: `urn:uuid:${createHash('sha256').update(JSON.stringify(result.inventory || [])).digest('hex').slice(0, 32)}`,
    version: 1,
    metadata: {tools: [{vendor: 'Lima e Silva Tecnologia', name: result.scanner.name, version: result.scanner.version}]},
    components: (result.inventory || []).map(item => ({type: 'library', name: item.name, version: item.version, purl: `pkg:generic/${encodeURIComponent(item.name)}@${encodeURIComponent(item.version)}`, properties: [{name: 'dependencyType', value: item.dependencyType}, {name: 'source', value: item.source}]}))
  };
}

const xmlEscape = value => String(value ?? '').replace(/[<>&"']/g, character => ({'<': '&lt;', '>': '&gt;', '&': '&amp;', '"': '&quot;', "'": '&apos;'}[character]));
export function toJunit(result) {
  const failures = (result.findings || []).map(item => `<testcase classname="sca" name="${xmlEscape(item.package + '@' + item.version)}"><failure type="${xmlEscape(item.severity)}">${xmlEscape(item.message)} ${xmlEscape(item.recommendation)}</failure></testcase>`).join('');
  const cases = Math.max((result.inventory || []).length, 1);
  return `<?xml version="1.0" encoding="UTF-8"?><testsuite name="Lima e Silva SCA" tests="${cases}" failures="${(result.findings || []).length}">${failures || '<testcase classname="sca" name="inventory"/>'}</testsuite>`;
}

export function normalizeForUpload(result, metadata = {}) {
  return {
    schemaVersion: SCHEMA_VERSION,
    agentId: 'pipeline-sca',
    scanner: result.scanner,
    release: clean(metadata.release),
    repository: clean(metadata.repository),
    commit: clean(metadata.commit),
    branch: clean(metadata.branch),
    advisoryMode: result.advisoryMode,
    policy: result.policy,
    stats: result.stats,
    findings: (result.findings || []).slice(0, 1000).map(item => ({id: item.id, ruleId: item.ruleId, title: item.title, severity: item.severity, package: item.package, version: item.version, recommendation: item.recommendation, fingerprint: item.fingerprint}))
  };
}
