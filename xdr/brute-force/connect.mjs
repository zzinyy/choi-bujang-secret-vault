
import { readFile, writeFile, appendFile } from 'node:fs/promises';

const resultPath = new URL('./result.json', import.meta.url);
const fixturePath = new URL('../fixtures/brute-force.json', import.meta.url);
const rulesPath = new URL('./deny-rules.json', import.meta.url);
const logPath = new URL('../alerts.log', import.meta.url);

export async function connect() {
  const result = JSON.parse(await readFile(resultPath, 'utf8'));
  const fixture = JSON.parse(await readFile(fixturePath, 'utf8'));

  const byId = new Map(fixture.alerts.map(alert => [alert.id, alert]));
  const rules = [];
  const notifications = [];

  for (const decision of result.decisions) {
    const alert = byId.get(decision.alertId);
    if (!alert) continue;

    if (decision.action === 'block') {
      const ip = alert.data?.srcip;
      if (typeof ip !== 'string' || !ip.trim()) {
        notifications.push({
          alertId: decision.alertId,
          action: 'alert',
          reason: 'missing-source-ip'
        });
        continue;
      }

      const detectedAt = Date.parse(alert.timestamp);
      if (!Number.isFinite(detectedAt)) continue;

      const expiresAt = new Date(Date.now() + 15 * 60 * 1000).toISOString();

      rules.push({
        ruleId: `xdr.brute-force.${decision.alertId}`,
        sourceIp: ip,
        evidenceAlertId: decision.alertId,
        expiresAt,
        reason: decision.reason
      });
    } else if (decision.action === 'alert') {
      notifications.push({
        alertId: decision.alertId,
        action: 'alert',
        reason: decision.reason
      });
    }
  }

  await writeFile(
    rulesPath,
    JSON.stringify({ schema: 'aleph.xdr.deny-rules.v1', rules }, null, 2) + '\n'
  );

  if (notifications.length > 0) {
    await appendFile(
      logPath,
      notifications.map(n => JSON.stringify(n)).join('\n') + '\n'
    );
  }

  return {
    denyRules: rules.length,
    notifications: notifications.length
  };
}

if (process.argv[1]?.endsWith('connect.mjs')) {
  console.log(await connect());
}
