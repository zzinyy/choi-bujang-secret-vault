
import { readFileSync } from 'node:fs';

const fixtureUrl = new URL('../fixtures/brute-force.json', import.meta.url);

export function readAlerts() {
  const fixture = JSON.parse(readFileSync(fixtureUrl, 'utf8'));

  if (!Array.isArray(fixture.alerts)) {
    throw new Error('INVALID_ALERTS_FORMAT');
  }

  return fixture.alerts.map((alert) => ({
    timestamp: alert.timestamp ?? null,
    srcip: alert.data?.srcip ?? null,
    account: alert.data?.srcuser ?? null,
    level: alert.rule?.level ?? null,
    description: alert.rule?.description ?? null
  }));
}

if (process.argv[1] && import.meta.url === new URL(`file:///${process.argv[1].replaceAll('\\', '/')}`).href) {
  const alerts = readAlerts();

  console.log(`원본 경보: ${alerts.length}건`);
  console.log(`추출된 경보: ${alerts.length}줄`);
  console.log(`건수 일치: ${alerts.length === 28 ? '확인' : '재확인 필요'}`);
}
