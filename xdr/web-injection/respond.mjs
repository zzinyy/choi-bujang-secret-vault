
import { readFile, writeFile, appendFile } from 'node:fs/promises';

const resultPath = new URL('./result.json', import.meta.url);
const fixturePath = new URL('../fixtures/web-injection.json', import.meta.url);
const rulesPath = new URL('./deny-rules.json', import.meta.url);
const logPath = new URL('../alerts.log', import.meta.url);

const MIN_REPEAT = 5;
const MIN_LEVEL = 8;
const BLOCK_TTL_MS = 15 * 60 * 1000;

export async function respond() {
  const result = JSON.parse(await readFile(resultPath, 'utf8'));
  const fixture = JSON.parse(await readFile(fixturePath, 'utf8'));

  const byId = new Map(
    fixture.alerts.map(alert => [alert.id, alert])
  );

  const rules = [];
  const notifications = [];
  const now = Date.now();

  for (const decision of result.decisions) {
    const alert = byId.get(decision.alertId);
    if (!alert) continue;

    const count = Number(alert.data?.count ?? 1);
    const level = Number(alert.rule?.level ?? 0);
    const ip = alert.data?.srcip;

    const repeated =
      Number.isFinite(count) &&
      count >= MIN_REPEAT &&
      level >= MIN_LEVEL;

    const validIp =
      typeof ip === 'string' &&
      /^(?:\d{1,3}\.){3}\d{1,3}$/.test(ip) &&
      ip.split('.').every(part => Number(part) <= 255);

    const confirmedBlock =
      decision.action === 'block' &&
      decision.confidence >= 0.85 &&
      repeated &&
      validIp;

    if (confirmedBlock) {
      rules.push({
        ruleId: `xdr.web-injection.${decision.alertId}`,
        sourceIp: ip,
        action: 'deny',
        evidenceAlertId: decision.alertId,
        expiresAt: new Date(now + BLOCK_TTL_MS).toISOString(),
        reason: decision.reason
      });
    }

    if (decision.action === 'block' || decision.action === 'alert') {
      notifications.push({
        moduleKey: 'web-injection',
        alertId: decision.alertId,
        action: confirmedBlock ? 'block' : 'alert',
        reason: decision.reason,
        timestamp: new Date(now).toISOString()
      });
    }
  }

  await writeFile(
    rulesPath,
    JSON.stringify(
      {
        schema: 'aleph.xdr.deny-rules.v1',
        rules
      },
      null,
      2
    ) + '\n'
  );

  if (notifications.length > 0) {
    await appendFile(
      logPath,
      notifications.map(item => JSON.stringify(item)).join('\n') + '\n'
    );
  }

  return {
    denyRules: rules.length,
    notifications: notifications.length
  };
}

if (process.argv[1]?.endsWith('respond.mjs')) {
  console.log(await respond());
}
