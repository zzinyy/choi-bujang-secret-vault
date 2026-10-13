import assert from 'node:assert/strict';
import { test } from 'node:test';
import { registerHooks } from 'node:module';

const NOTE_ID = '550e8400-e29b-41d4-a716-446655440000';
const USER_A = '550e8400-e29b-41d4-a716-446655440001';
const USER_B = '550e8400-e29b-41d4-a716-446655440002';

const state = {
  userId: USER_A,
  note: {
    id: NOTE_ID,
    owner_id: USER_A,
    title: 'A의 메모',
    content: '비공개 내용'
  },
  filters: {}
};

// Replace external dependencies before importing the API.
registerHooks({
  resolve(specifier, context, nextResolve) {
    if (specifier === '@supabase/supabase-js') {
      return {
        url: 'mock:supabase',
        shortCircuit: true
      };
    }

    if (specifier.endsWith('/src/verify-login.mjs')) {
      return {
        url: 'mock:login',
        shortCircuit: true
      };
    }

    return nextResolve(specifier, context);
  },

  load(url, context, nextLoad) {
    if (url === 'mock:login') {
      return {
        format: 'module',
        shortCircuit: true,
        source: `
          export function createLoginVerifier() {
            return async (authorization) => {
              if (!authorization) return null;
              return {
                kind: 'student',
                userId: globalThis.__testUserId
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

                  async maybeSingle() {
                    globalThis.__testFilters = { ...filters };

                    const note = globalThis.__testNote;

                    const matches =
                      note &&
                      Object.entries(filters).every(
                        ([key, value]) => note[key] === value
                      );

                    return {
                      data: matches ? note : null,
                      error: null
                    };
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

const { default: handler } = await import('../api/notes/[id].js');

async function requestAs(userId, authorized = true) {
  globalThis.__testUserId = userId;
  globalThis.__testNote = state.note;
  globalThis.__testFilters = {};

  const request = {
    method: 'GET',
    headers: {
      authorization: authorized ? 'Bearer test-token' : undefined
    },
    query: {
      id: NOTE_ID
    }
  };

  const response = {
    statusCode: 200,
    headers: {},

    setHeader(name, value) {
      this.headers[name] = value;
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
    filters: globalThis.__testFilters
  };
}

test('A는 자신의 메모를 조회할 수 있다', async () => {
  const result = await requestAs(USER_A);

  assert.equal(result.status, 200);
  assert.equal(result.body.id, NOTE_ID);
  assert.equal(result.body.body, '비공개 내용');

  assert.deepEqual(result.filters, {
    id: NOTE_ID,
    owner_id: USER_A
  });
});

test('B는 A의 메모를 조회할 수 없다', async () => {
  const result = await requestAs(USER_B);

  assert.equal(result.status, 404);
  assert.equal(result.body.error, 'NOTE_NOT_FOUND');

  assert.deepEqual(result.filters, {
    id: NOTE_ID,
    owner_id: USER_B
  });
});

test('로그인하지 않으면 메모를 조회할 수 없다', async () => {
  const result = await requestAs(USER_B, false);

  assert.equal(result.status, 401);
  assert.equal(result.body.error, 'UNAUTHORIZED');
});