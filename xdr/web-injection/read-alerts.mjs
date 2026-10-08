
import { readFileSync } from 'node:fs';

const fixturePath = new URL('../fixtures/web-injection.json', import.meta.url);
const fixture = JSON.parse(readFileSync(fixturePath, 'utf8'));

const alerts = Array.isArray(fixture)
  ? fixture
  : Array.isArray(fixture.alerts)
    ? fixture.alerts
    : [];

const extracted = alerts.map((alert) => ({
  timestamp: alert.timestamp ?? null,
  srcip: alert.data?.srcip ?? null,
  account: alert.data?.srcuser ?? null,
  level: alert.rule?.level ?? null,
  description: alert.rule?.description ?? null
}));

console.log('원본 경보:', alerts.length);
console.log('추출한 줄:', extracted.length);
console.log('건수 일치:', alerts.length === extracted.length);
