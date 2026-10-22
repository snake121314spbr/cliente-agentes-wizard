import {createHash} from 'node:crypto';
import {mkdir, readFile, writeFile} from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';

const BASE_URL = 'https://agentes.limaesilvatecnologia.com.br/downloads/devsecops-toolkit/1.1.0/';
const args = process.argv.slice(2);
let destination = '.';
let offline = false;
for (let i = 0; i < args.length; i += 1) {
  if (args[i] === '--dest' && args[i + 1]) destination = args[++i];
  else if (args[i] === '--offline') offline = true;
  else if (args[i] === '--help' || args[i] === '-h') {
    console.log('Uso: node install.mjs [--dest <checkout>] [--offline]');
    process.exit(0);
  } else if (args[i].startsWith('-')) throw new Error(`Opção desconhecida: ${args[i]}`);
}
if (!BASE_URL.startsWith('https://agentes.limaesilvatecnologia.com.br/')) throw new Error('Origem oficial inválida');
const root = path.resolve(destination);
const manifestText = offline ? await readFile(path.join(root, 'manifest.json'), 'utf8') : null;
const manifest = manifestText ? JSON.parse(manifestText) : await (async () => {
  const response = await fetch(`${BASE_URL}manifest.json`, {redirect: 'error'});
  if (!response.ok) throw new Error(`Manifesto indisponível: HTTP ${response.status}`);
  return response.json();
})();
if (manifest.version !== '1.1.0' || !Array.isArray(manifest.files)) throw new Error('Manifesto incompatível');
for (const entry of manifest.files) {
  if (!entry || typeof entry.path !== 'string' || !/^[A-Za-z0-9._/-]+$/.test(entry.path) || entry.path.includes('..') || entry.path.startsWith('/')) throw new Error('Caminho recusado no manifesto');
  const target = path.resolve(root, entry.path);
  if (!target.startsWith(`${root}${path.sep}`)) throw new Error('Destino fora do checkout');
  let data;
  if (offline) {
    data = await readFile(target);
  } else {
    const fileResponse = await fetch(`${BASE_URL}${entry.path}`, {redirect: 'error'});
    if (!fileResponse.ok) throw new Error(`Arquivo indisponível: ${entry.path} (HTTP ${fileResponse.status})`);
    data = Buffer.from(await fileResponse.arrayBuffer());
  }
  const digest = createHash('sha256').update(data).digest('hex');
  if (digest !== entry.sha256) throw new Error(`SHA-256 divergente: ${entry.path}`);
  if (!offline) {
    await mkdir(path.dirname(target), {recursive: true});
    await writeFile(target, data);
  }
}
if (!offline) await writeFile(path.join(root, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n');
console.log(`Toolkit Lima e Silva ${manifest.version} ${offline ? 'verificado offline em' : 'instalado em'} ${root} (${manifest.files.length} arquivos verificados).`);
