
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { deploymentIdentity } from '../scripts/deployment-identity.mjs';
import { runAttackChecks } from '../src/attack-check.mjs';

const config = {
  step: 8,
  judgeIssuer: 'https://aleph-judge-production.up.railway.app/defense/judge',
  sampleMarker: 'SAMPLE_NOTE_1',
  publicAppUrl: 'https://student-defense.vercel.app',
  allowedRoutes: [
    'GET /api/notes',
    'POST /api/notes',
    'GET /api/notes/:id',
    'PUT /api/notes/:id',
    'DELETE /api/notes/:id',
    'GET /api/announcements',
    'POST /api/announcements',
    'GET /api/announcements/:id',
    'PUT /api/announcements/:id',
    'DELETE /api/announcements/:id'
  ],
  originalApiUrl: 'https://example.supabase.co/rest/v1/notes'
};

const env = {
  VERCEL_GIT_PROVIDER: 'github',
  VERCEL_GIT_REPO_OWNER: 'Student-A',
  VERCEL_GIT_REPO_SLUG: 'aleph-defense',
  VERCEL_GIT_COMMIT_SHA: 'a'.repeat(40),
  VERCEL_URL: 'student-defense-123.vercel.app',
};

test('build identity uses Vercel Git and deployment metadata', () => {
  assert.deepEqual(deploymentIdentity(env, config), {
    schema: 'aleph.defense.deployment.v1',
    step: 8,
    repoUrl: 'https://github.com/student-a/aleph-defense',
    commit: 'a'.repeat(40),
    publicAppUrl: 'https://student-defense-123.vercel.app',
    judgeIssuer: config.judgeIssuer,
    sampleMarker: config.sampleMarker,
    allowedRoutes: config.allowedRoutes,
    originalApiUrl: config.originalApiUrl,
  });

  assert.throws(
    () => deploymentIdentity(
      { ...env, VERCEL_GIT_PROVIDER: undefined },
      config
    )
  );

  assert.throws(
    () => deploymentIdentity(
      { ...env, VERCEL_GIT_COMMIT_SHA: 'short' },
      config
    )
  );
});

test('first attack check reads public data.json without credentials', async () => {
  const originalFetch = globalThis.fetch;
  let requestUrl;
  let options;

  try {
    globalThis.fetch = async (url, init) => {
      requestUrl = String(url);
      options = init;

      return new Response(
        JSON.stringify({
          sampleMarker: 'SAMPLE_NOTE_1',
          notes: [{ title: '가상' }]
        }),
        {
          status: 200,
          headers: { 'content-type': 'application/json' },
        }
      );
    };

    const results = await runAttackChecks(config);
    const staticResult = results.find(
      result => result.attackId === 'anonymous_static_note_read'
    );

    assert.equal(
      requestUrl,
      'https://student-defense.vercel.app/api/notes'
    );
    assert.equal(options.redirect, 'error');
    assert.match(staticResult.observed, /가상 메모가 남아 있음/u);

    globalThis.fetch = async () =>
      new Response('<html>not the data</html>', { status: 200 });

    const failedResults = await runAttackChecks(config);
    const failedStaticResult = failedResults.find(
      result => result.attackId === 'anonymous_static_note_read'
    );

    assert.match(failedStaticResult.observed, /확인되지 않음/u);
  } finally {
    globalThis.fetch = originalFetch;
  }
});
