import assert from 'node:assert/strict';
import { test } from 'node:test';
import { probeAnonymous } from '../public/operations-evidence.js';
import { runAttackChecks } from '../src/attack-check.mjs';
test('stage 12 never promotes student probes to official execution', async () => {
  const rows = await runAttackChecks({ step: 12 });
  assert.equal(rows.length, 2);
  assert.ok(rows.every(row => row.observed === 'not_run'));
});
test('probes omit credentials, preserve real response ID and redact note content', async () => {
  const rows = await probeAnonymous('https://student.vercel.app', async (url, options) => {
    assert.equal(options.credentials, 'omit');
    assert.deepEqual(options.headers, { Accept: 'application/json' });
    return new Response(JSON.stringify({ notes: [{ body: 'PRIVATE_TEST_BODY' }] }), {
      status: url.pathname === '/data.json' ? 200 : 401,
      headers: { 'x-vercel-id': 'real-platform-id' },
    });
  });
  assert.equal(rows[0].observed, 'exposed');
  assert.equal(rows[1].observed, 'denied');
  assert.equal(rows[0].requestId, 'real-platform-id');
  assert.ok(!JSON.stringify(rows).includes('PRIVATE_TEST_BODY'));
});
test('missing or malformed responses never become success', async () => {
  const malformed = await probeAnonymous('https://student.vercel.app', async () => new Response('<html>', { status: 200 }));
  assert.ok(malformed.every(row => row.observed === 'inconclusive' && row.requestId === null));
  const failed = await probeAnonymous('https://student.vercel.app', async () => { throw Error('network'); });
  assert.ok(failed.every(row => row.observed === 'not_run' && row.httpStatus === null));
});
