import { readFile, writeFile, appendFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
import { isIP } from 'node:net';
import { decide } from './decide.mjs';

export function buildResponse(alerts, now = Date.now()) {
  const rules = [], notifications = [];
  for (const alert of alerts) {
    const decision = decide(alert);
    const id = alert?.id;
    if (typeof id !== 'string' || !/^[a-zA-Z0-9_.-]{1,80}$/.test(id)) continue;
    const ip = alert?.data?.srcip;
    const block = decision.action === 'block' && typeof ip === 'string' && isIP(ip) !== 0;
    if (block) rules.push({ ruleId: `xdr.known-cve.${id}`, sourceIp: ip, action: 'deny',
      evidenceAlertId: id, expiresAt: new Date(now + 15 * 60 * 1000).toISOString(), reason: decision.reason });
    if (decision.action !== 'record') notifications.push({ moduleKey: 'known-cve', alertId: id,
      action: block ? 'block' : 'alert', reason: decision.reason, timestamp: new Date(now).toISOString() });
  }
  return { schema: 'aleph.xdr.deny-rules.v1', rules, notifications };
}

// Extra gate: the caller supplies a verified transport IP outside the decision
// contract. Never read client-created request.geo/request.identity or IP headers.
export function applyDenyRules({ request, decision, verifiedSourceIp, trustedTransport = false, rules, now = Date.now() }) {
  if (!trustedTransport || typeof verifiedSourceIp !== 'string' || !isIP(verifiedSourceIp)
      || decision?.decision !== 'allow' || decision.requestId !== request?.requestId) return decision;
  const matched = rules?.some(rule => rule.action === 'deny' && rule.sourceIp === verifiedSourceIp
    && rule.reason === 'log4shell.remote-jndi' && Date.parse(rule.expiresAt) > now
    && Date.parse(rule.expiresAt) <= now + 15 * 60 * 1000);
  return matched ? { schema: 'aleph.decision.v1', requestId: request.requestId,
    decision: 'deny', reasonCode: 'resource_access_denied', ruleIds: ['resource_access'] } : decision;
}

export async function respond() {
  const fixture = JSON.parse(await readFile(new URL('../fixtures/known-cve.json', import.meta.url), 'utf8'));
  const response = buildResponse(fixture.alerts);
  await writeFile(new URL('./deny-rules.json', import.meta.url), JSON.stringify({ schema: response.schema, rules: response.rules }, null, 2) + '\n');
  if (response.notifications.length) await appendFile(new URL('../alerts.log', import.meta.url), response.notifications.map(row => JSON.stringify(row)).join('\n') + '\n');
  return { denyRules: response.rules.length, notifications: response.notifications.length };
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) console.log(await respond());
