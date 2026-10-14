
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { test } from 'node:test';
import { registerHooks } from 'node:module';

const NOTE_ID = '24411b3f-699d-4159-9e23-f8deed7861cc';
const USER_B = '1cbb98f4-1707-437d-8d17-290f98a8c98c';
const USER_A = '1bd36a03-5981-4a41-b667-b7616b95ca3b';

const content = 'B 계정의 백업된 테스트 메모';
const hash = value =>
  createHash('sha256').update(value, 'utf8').digest('hex');

const initialBackup = () => ({
  id: 1,
  note_id: NOTE_ID,
  owner_id: USER_B,
  title: 'B 계정 시험 메모 수정',
  content,
  content_sha256: hash(content)
});

let state;

registerHooks({
  resolve(specifier, context, nextResolve) {
    if (specifier === '@supabase/supabase-js') {
      return { url: 'mock:restore-supabase', shortCircuit: true };
    }

    if (specifier.endsWith('/src/verify-login.mjs')) {
      return { url: 'mock:restore-login', shortCircuit: true };
    }

    return nextResolve(specifier, context);
  },

  load(url, context, nextLoad) {
    if (url === 'mock:restore-login') {
      return {
        format: 'module',
        shortCircuit: true,
        source: `
          export function createLoginVerifier() {
            return async authorization => {
              if (authorization !== 'Bearer test-token') return null;
              return {
                kind: 'student',
                userId: globalThis.__restoreTestUserId
              };
            };
          }
        `
      };
    }

    if (url === 'mock:restore-supabase') {
      return {
        format: 'module',
        shortCircuit: true,
        source: `
          export function createClient() {
            return {
              from(table) {
                if (table === 'stage10_note_backups') {
                  const filters = {};

                  const query = {
                    select() { return query; },
                    eq(column, value) {
                      filters[column] = value;
                      return query;
                    },
                    order() { return query; },
                    limit() { return query; },
                    async maybeSingle() {
                      const backup = globalThis.__restoreTestBackup;
                      const matches = backup &&
                        Object.entries(filters).every(
                          ([key, value]) => backup[key] === value
                        );
                      return {
                        data: matches ? { ...backup } : null,
                        error: null
                      };
                    }
                  };

                  return query;
                }

                if (table === 'notes') {
                  const filters = {};
                  let operation = 'select';
                  let payload = null;

                  const query = {
                    select() { return query; },
                    eq(column, value) {
                      filters[column] = value;
                      return query;
                    },
                    update(value) {
                      operation = 'update';
                      payload = value;
                      return query;
                    },
                    insert(value) {
                      operation = 'insert';
                      payload = value;
                      return query;
                    },
                    async maybeSingle() {
                      const current = globalThis.__restoreTestNote;
                      const matches = current &&
                        Object.entries(filters).every(
                          ([key, value]) => current[key] === value
                        );

                      if (operation === 'select') {
                        return {
                          data: matches
                            ? { id: current.id, owner_id: current.owner_id }
                            : null,
                          error: null
                        };
                      }

                      if (operation === 'update') {
                        if (!matches) return { data: null, error: null };

                        Object.assign(current, payload);
                        return { data: { ...current }, error: null };
                      }

                      if (operation === 'insert') {
                        if (current) {
                          return {
                            data: null,
                            error: { code: '23505' }
                          };
                        }

                        globalThis.__restoreTestNote = { ...payload };
                        return {
                          data: { ...payload },
                          error: null
                        };
                      }

                      return { data: null, error: null };
                    }
                  };

                  return query;
                }

                if (table === 'stage10_policy_audit') {
                  return {
                    async insert(record) {
                      globalThis.__restoreTestAudit.push(record);
                      return { error: null };
                    }
                  };
                }

                throw new Error('Unexpected table: ' + table);
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

const { default: handler } = await import('../api/notes/[id]/restore.js');

function setup({
  userId = USER_B,
  authorized = true,
  backup = initialBackup(),
  note = null
} = {}) {
  state = { userId, authorized, backup, note };

  globalThis.__restoreTestUserId = userId;
  globalThis.__restoreTestBackup = backup;
  globalThis.__restoreTestNote = note;
  globalThis.__restoreTestAudit = [];
}

async function requestRestore({ method = 'POST', id = NOTE_ID } = {}) {
  const response = {
    statusCode: 200,
    headers: {},
    setHeader(name, value) {
      this.headers[name] = value;
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

  await handler({
    method,
    headers: {
      authorization: state.authorized ? 'Bearer test-token' : undefined
    },
    query: { id }
  }, response);

  return response;
}

test('비로그인 복원 요청은 거부된다', async () => {
  setup({ authorized: false });

  const response = await requestRestore();

  assert.equal(response.statusCode, 401);
  assert.equal(response.body.error, 'UNAUTHORIZED');
  assert.equal(state.note, null);
});

test('다른 사용자의 백업은 조회할 수 없다', async () => {
  setup({ userId: USER_A });

  const response = await requestRestore();

  assert.equal(response.statusCode, 404);
  assert.equal(response.body.error, 'VERIFIED_NOTE_BACKUP_NOT_FOUND');
  assert.equal(state.note, null);
});

test('내용 해시가 일치하지 않는 백업은 복원되지 않는다', async () => {
  const backup = initialBackup();
  backup.content = '변조된 내용';

  setup({ backup });

  const response = await requestRestore();

  assert.equal(response.statusCode, 409);
  assert.equal(response.body.error, 'NOTE_BACKUP_VERIFICATION_FAILED');
  assert.equal(state.note, null);
  assert.ok(
    globalThis.__restoreTestAudit.some(
      item => item.outcome === 'fail'
    )
  );
});

test('기존 메모의 소유자가 다르면 덮어쓰지 않는다', async () => {
  setup({
    note: {
      id: NOTE_ID,
      owner_id: USER_A,
      title: 'A의 메모',
      content: 'A만 볼 수 있는 내용'
    }
  });

  const response = await requestRestore();

  assert.equal(response.statusCode, 409);
  assert.equal(response.body.error, 'NOTE_OWNER_MISMATCH');
  assert.equal(globalThis.__restoreTestNote.owner_id, USER_A);
  assert.equal(globalThis.__restoreTestNote.content, 'A만 볼 수 있는 내용');
});

test('유효한 백업은 해당 사용자의 메모 한 건만 복원한다', async () => {
  setup({
    note: {
      id: NOTE_ID,
      owner_id: USER_B,
      title: '변조된 제목',
      content: '변조된 내용'
    }
  });

  const response = await requestRestore();

  assert.equal(response.statusCode, 200);
  assert.equal(response.body.restored, true);
  assert.equal(response.body.id, NOTE_ID);
  assert.equal(response.body.owner_id, USER_B);
  assert.equal(response.body.content_sha256, hash(content));
  assert.equal(globalThis.__restoreTestNote.content, content);
  assert.ok(
    globalThis.__restoreTestAudit.some(
      item => item.outcome === 'pass'
    )
  );
});

test('복원 경로는 POST만 허용한다', async () => {
  setup();

  const response = await requestRestore({ method: 'GET' });

  assert.equal(response.statusCode, 405);
  assert.equal(response.body.error, 'METHOD_NOT_ALLOWED');
  assert.equal(state.note, null);
});
