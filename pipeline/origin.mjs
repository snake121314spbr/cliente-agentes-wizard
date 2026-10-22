// Stable, non-secret provenance for every pipeline result. The origin is a
// repository/workspace identifier, never a token, URL credential or source
// file. The Console stores it as a tenant-scoped filter dimension.
const clean = (value, max = 240) => String(value || '').trim().replace(/[\u0000-\u001f\u007f]/g, '').slice(0, max);

export function originFromMetadata(metadata = {}) {
  const repository = clean(metadata.repository);
  const supplied = metadata.origin && typeof metadata.origin === 'object' ? metadata.origin : {};
  const key = clean(supplied.key || supplied.id || metadata.originId || process.env.PIPELINE_ORIGIN_ID || process.env.PIPELINE_SOURCE_ID || repository || 'local');
  const label = clean(supplied.label || metadata.originLabel || process.env.PIPELINE_ORIGIN_LABEL || repository || key);
  return {type: 'repository', key: key || 'local', label: label || key || 'local'};
}
