
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { registerHooks } from 'node:module';

const USER_A = '550e8400-e29b-41d4-a716-446655440001';
const USER_B = '550e8400-e29b-41d4-a716-446655440002';

const NOTE_A = {
  id: '550e8400-e29b-41d4-a716-446655440000',
  owner_id: USER_A,
  title: 'A의 메모',
  content: 'A만 볼 수 있는 내용'
};

registerHooks({
  resolve(specifier, context, nextResolve) {
    if (specifier === '@supabase/supabase-js') {
      return { url: 'mock:supabase', shortCircuit: true };
    }

    if (specifier.endsWith('/src/verify-login.mjs')) {
      return { url: 'mock:login', shortCircuit: true };
    }

if (specifier.endsWith('/src/authorize-device.mjs')) {
  return { url: 'mock:device', shortCircuit: true };
}

    return nextResolve(specifier, context);
  },

  load(url, context, nextLoad) {
if (url === 'mock:device') {
  return {
    format: 'module',
    shortCircuit: true,
    source: `
      export async function authorizeDevice() {
        return { ok: true, deviceId: 'test-approved-device' };
      }
    `
  };
}
    if (url === 'mock:login') {
      return {
        format: 'module',
        shortCircuit: true,
        source: `
          export function createLoginVerifier({ config }) {
            if (!config.judgeIssuer || !config.identityProvider || config.api) {
              throw new Error('Wrong login verifier config');
            }
            return async (authorization) => {
              if (!authorization) return null;
              return {
                kind: 'student',
                userId: globalThis.__listTestUserId
              };
            };
          }
        `
      };
    }

    if (url === 'mock:supabase') {
      return {
        format: 'module',
        shortCircuit: true,
        source: `
          export function createClient() {
            return {
              from(table) {
                if (table !== 'notes') {
                  throw new Error('Unexpected table');
                }

                const filters = {};

                const query = {
                  select() {
                    return query;
                  },

                  eq(column, value) {
                    filters[column] = value;
                    return query;
                  },

                  async order() {
                    globalThis.__listTestFilters = { ...filters };

                    const notes = globalThis.__listTestNotes.filter(
                      (note) =>
                        Object.entries(filters).every(
                          ([key, value]) => note[key] === value
                        )
                    );

                    return { data: notes, error: null };
                  }
                };

                return query;
              }
            };
          }
        `
      };
    }

    return nextLoad(url, context);
  }
});

process.env.SUPABASE_URL = 'https://example.supabase.co';
process.env.SUPABASE_SECRET_KEY = 'test-only-placeholder';

const { default: handler } = await import('../api/notes.js');

async function requestAs(userId, authorized = true) {
  globalThis.__listTestUserId = userId;
  globalThis.__listTestNotes = [NOTE_A];
  globalThis.__listTestFilters = {};

  const request = {
    method: 'GET',
    headers: {
      authorization: authorized ? 'Bearer test-token' : undefined
    }
  };

  const response = {
    statusCode: 200,

    setHeader() {
      return this;
    },

    status(code) {
      this.statusCode = code;
      return this;
    },

    json(body) {
      this.body = body;
      return this;
    }
  };

  await handler(request, response);

  return {
    status: response.statusCode,
    body: response.body,
    filters: globalThis.__listTestFilters
  };
}

test('A는 자신의 메모 목록을 조회할 수 있다', async () => {
  const result = await requestAs(USER_A);

  assert.equal(result.status, 200);
  assert.equal(result.body.notes.length, 1);
  assert.equal(result.body.notes[0].id, NOTE_A.id);
  assert.deepEqual(result.filters, { owner_id: USER_A });
});

test('B의 메모 목록에는 A의 메모가 나타나지 않는다', async () => {
  const result = await requestAs(USER_B);

  assert.equal(result.status, 200);
  assert.deepEqual(result.body.notes, []);
  assert.deepEqual(result.filters, { owner_id: USER_B });
});

test('비로그인 사용자는 메모 목록을 조회할 수 없다', async () => {
  const result = await requestAs(USER_B, false);

  assert.equal(result.status, 401);
  assert.equal(result.body.error, 'UNAUTHORIZED');
});
