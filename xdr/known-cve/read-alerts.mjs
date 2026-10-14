import { readFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';

function safe(value) {
  if (typeof value !== 'string') return null;
  return value.slice(0, 1000)
    .replace(/Bearer\s+\S+|(?:token|password|secret|api[_-]?key)\s*[:=]\s*\S+/gi, '[REDACTED]')
    .replace(/\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g, '[REDACTED]')
    .replace(/-----BEGIN[\s\S]*?PRIVATE KEY-----[\s\S]*/g, '[REDACTED]')
    .replace(/[\r\n\x00-\x1f]/g, ' ');
}
export async function readAlerts() {
  const fixture = JSON.parse(await readFile(new URL('../fixtures/known-cve.json', import.meta.url), 'utf8'));
  if (!Array.isArray(fixture.alerts)) throw Error('INVALID_ALERTS_FORMAT');
  return fixture.alerts.map(alert => ({ timestamp: safe(alert.timestamp), srcip: safe(alert.data?.srcip),
    account: safe(alert.data?.srcuser), level: Number.isFinite(alert.rule?.level) ? alert.rule.level : null,
    description: safe(alert.rule?.description) }));
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const rows = await readAlerts();
  console.log(`경보 ${rows.length}건 · 추출 ${rows.length}줄`);
}
