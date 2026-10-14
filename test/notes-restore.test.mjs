
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { test } from 'node:test';
import { registerHooks } from 'node:module';

const NOTE_ID = '24411b3f-699d-4159-9e23-f8deed7861cc';
const USER_B = '1cbb98f4-1707-437d-8d17-290f98a8c98c';
const USER_A = '1bd36a03-5981-4a41-b667-b7616b95ca3b';

const content = 'B account backup test note';
const hash = value =>
  createHash('sha256').update(value, 'utf8').digest('hex');

const initialBackup = () => {
  const title = 'Original backup title';

  return {
    id: 2,
    note_id: NOTE_ID,
    owner_id: USER_B,
    title,
    content,
    content_sha256: hash(content),
    snapshot_sha256: hash(`${title}\n${content}`),
    created_at: '2026-10-13T10:00:00.000Z'
  };
};

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
                      const readNumber =
                        ++globalThis.__restoreTestBackupReads;

                      let backup = globalThis.__restoreTestBackup;

                      if (readNumber === 2) {
                        const second =
                          globalThis.__restoreTestSecondBackup;

                        if (second !== undefined) {
                          backup = second;
                        }
                      }

                      if (
                        readNumber === 2
                        && globalThis.__restoreTestSecondReadError
                      ) {
                        return {
                          data: null,
                          error: { message: 'Mock backup read failure' }
                        };
                      }

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
                          data: matches ? { ...current } : null,
                          error: null
                        };
                      }

                      if (operation === 'update') {
                        globalThis.__restoreTestNoteWrites++;

                        if (!matches) {
                          return { data: null, error: null };
                        }

                        Object.assign(current, payload);
                        return { data: { ...current }, error: null };
                      }

                      if (operation === 'insert') {
                        globalThis.__restoreTestNoteWrites++;

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
  secondBackup = undefined,
  secondReadError = false,
  note = null
} = {}) {
  state = { userId, authorized };

  globalThis.__restoreTestUserId = userId;
  globalThis.__restoreTestBackup = backup;
  globalThis.__restoreTestSecondBackup = secondBackup;
  globalThis.__restoreTestSecondReadError = secondReadError;
  globalThis.__restoreTestBackupReads = 0;
  globalThis.__restoreTestNote = note;
  globalThis.__restoreTestNoteWrites = 0;
  globalThis.__restoreTestAudit = [];
}

async function requestRestore({
  method = 'POST',
  id = NOTE_ID,
  body = undefined
} = {}) {
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
    json(value) {
      this.body = value;
      return this;
    }
  };

  await handler({
    method,
    headers: {
      authorization: state.authorized
        ? 'Bearer test-token'
        : undefined
    },
    query: { id },
    body
  }, response);

  return response;
}

// Existing restore behavior

test('rejects unauthenticated restore requests', async () => {
  setup({ authorized: false });

  const response = await requestRestore();

  assert.equal(response.statusCode, 401);
  assert.equal(response.body.error, 'UNAUTHORIZED');
  assert.equal(globalThis.__restoreTestNote, null);
});

test('does not read another user backup', async () => {
  setup({ userId: USER_A });

  const response = await requestRestore();

  assert.equal(response.statusCode, 404);
  assert.equal(
    response.body.error,
    'VERIFIED_NOTE_BACKUP_NOT_FOUND'
  );
  assert.equal(globalThis.__restoreTestNote, null);
});

test('rejects corrupted backup content', async () => {
  const backup = initialBackup();
  backup.content = 'Tampered content';

  setup({ backup });

  const response = await requestRestore();

  assert.equal(response.statusCode, 409);
  assert.equal(
    response.body.error,
    'NOTE_BACKUP_VERIFICATION_FAILED'
  );
  assert.equal(globalThis.__restoreTestNoteWrites, 0);
  assert.ok(
    globalThis.__restoreTestAudit.some(
      item => item.outcome === 'fail'
    )
  );
});

test('rejects restoring over another user note', async () => {
  setup({
    note: {
      id: NOTE_ID,
      owner_id: USER_A,
      title: 'User A title',
      content: 'User A private content'
    }
  });

  const response = await requestRestore();

  assert.equal(response.statusCode, 409);
  assert.equal(response.body.error, 'NOTE_OWNER_MISMATCH');
  assert.equal(globalThis.__restoreTestNote.owner_id, USER_A);
  assert.equal(
    globalThis.__restoreTestNote.content,
    'User A private content'
  );
  assert.equal(globalThis.__restoreTestNoteWrites, 0);
});

test('restores only the authenticated user note', async () => {
  setup({
    note: {
      id: NOTE_ID,
      owner_id: USER_B,
      title: 'Tampered title',
      content: 'Tampered content'
    }
  });

  const response = await requestRestore();

  assert.equal(response.statusCode, 200);
  assert.equal(response.body.restored, true);
  assert.equal(response.body.id, NOTE_ID);
  assert.equal(response.body.owner_id, USER_B);
  assert.equal(response.body.content_sha256, hash(content));
  assert.equal(globalThis.__restoreTestNote.content, content);
  assert.equal(globalThis.__restoreTestNoteWrites, 1);
  assert.equal(globalThis.__restoreTestBackupReads, 2);
  assert.ok(
    globalThis.__restoreTestAudit.some(
      item => item.outcome === 'pass'
    )
  );
});

test('allows POST only', async () => {
  setup();

  const response = await requestRestore({ method: 'GET' });

  assert.equal(response.statusCode, 405);
  assert.equal(response.body.error, 'METHOD_NOT_ALLOWED');
  assert.equal(globalThis.__restoreTestNoteWrites, 0);
});

// Stage 10 backup verification regression tests

test('re-reads the backup before restoring', async () => {
  setup({
    note: {
      id: NOTE_ID,
      owner_id: USER_B,
      title: 'Changed title',
      content: 'Changed content'
    }
  });

  const response = await requestRestore();

  assert.equal(response.statusCode, 200);
  assert.equal(globalThis.__restoreTestBackupReads, 2);
  assert.equal(globalThis.__restoreTestNoteWrites, 1);
});

test('stops restoration if backup disappears on re-read', async () => {
  setup({
    secondBackup: null,
    note: {
      id: NOTE_ID,
      owner_id: USER_B,
      title: 'Changed title',
      content: 'Changed content'
    }
  });

  const response = await requestRestore();

  assert.equal(response.statusCode, 404);
  assert.equal(
    response.body.error,
    'VERIFIED_NOTE_BACKUP_NOT_FOUND'
  );
  assert.equal(globalThis.__restoreTestBackupReads, 2);
  assert.equal(globalThis.__restoreTestNoteWrites, 0);
  assert.equal(
    globalThis.__restoreTestNote.content,
    'Changed content'
  );
});

test('stops restoration if backup version changes', async () => {
  const changedBackup = initialBackup();
  changedBackup.created_at = '2026-10-13T11:00:00.000Z';

  setup({
    secondBackup: changedBackup,
    note: {
      id: NOTE_ID,
      owner_id: USER_B,
      title: 'Changed title',
      content: 'Changed content'
    }
  });

  const response = await requestRestore();

  assert.equal(response.statusCode, 409);
  assert.equal(
    response.body.error,
    'NOTE_BACKUP_VERIFICATION_FAILED'
  );
  assert.equal(globalThis.__restoreTestNoteWrites, 0);
});

test('stops restoration if backup hash changes on re-read', async () => {
  const changedBackup = initialBackup();
  changedBackup.content = 'Changed backup without hash update';

  setup({
    secondBackup: changedBackup,
    note: {
      id: NOTE_ID,
      owner_id: USER_B,
      title: 'Changed title',
      content: 'Changed content'
    }
  });

  const response = await requestRestore();

  assert.equal(response.statusCode, 409);
  assert.equal(
    response.body.error,
    'NOTE_BACKUP_VERIFICATION_FAILED'
  );
  assert.equal(globalThis.__restoreTestNoteWrites, 0);
});

test('stops restoration if the second backup read fails', async () => {
  setup({
    secondReadError: true,
    note: {
      id: NOTE_ID,
      owner_id: USER_B,
      title: 'Changed title',
      content: 'Changed content'
    }
  });

  const response = await requestRestore();

  assert.equal(response.statusCode, 500);
  assert.equal(response.body.error, 'NOTE_BACKUP_READ_FAILED');
  assert.equal(globalThis.__restoreTestNoteWrites, 0);
});

test('preview shows backup version and changes without restoring', async () => {
  setup({
    note: {
      id: NOTE_ID,
      owner_id: USER_B,
      title: 'Changed title',
      content: 'Changed content'
    }
  });

  const response = await requestRestore({
    body: { preview: true }
  });

  assert.equal(response.statusCode, 200);
  assert.equal(response.body.preview, true);
  assert.equal(response.body.verified, true);
  assert.equal(response.body.id, NOTE_ID);
  assert.equal(response.body.owner_id, USER_B);
  assert.equal(
    response.body.backup_version,
    '2026-10-13T10:00:00.000Z'
  );
  assert.equal(response.body.plan.changes.title, true);
  assert.equal(response.body.plan.changes.content, true);
  assert.equal(globalThis.__restoreTestBackupReads, 2);
  assert.equal(globalThis.__restoreTestNoteWrites, 0);
  assert.equal(
    globalThis.__restoreTestNote.content,
    'Changed content'
  );
});
