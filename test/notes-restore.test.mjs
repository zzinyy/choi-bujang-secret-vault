
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { test } from 'node:test';
import { registerHooks } from 'node:module';

const NOTE_ID = '24411b3f-699d-4159-9e23-f8deed7861cc';
const USER_B = '1cbb98f4-1707-437d-8d17-290f98a8c98c';
const USER_A = '1bd36a03-5981-4a41-b667-b7616b95ca3b';

const TITLE = 'Original backup title';
const CONTENT = 'B account backup test note';
const VERSION = '2026-10-13T10:00:00.000Z';

const hash = value =>
  createHash('sha256').update(value, 'utf8').digest('hex');

function initialBackup() {
  return {
    id: 2,
    note_id: NOTE_ID,
    owner_id: USER_B,
    title: TITLE,
    content: CONTENT,
    content_sha256: hash(CONTENT),
    snapshot_sha256: hash(`${TITLE}\n${CONTENT}`),
    created_at: VERSION
  };
}

let state;

registerHooks({
  resolve(specifier, context, nextResolve) {
    if (specifier === '@supabase/supabase-js') {
      return {
        url: 'mock:restore-supabase',
        shortCircuit: true
      };
    }

    if (specifier.endsWith('/src/verify-login.mjs')) {
      return {
        url: 'mock:restore-login',
        shortCircuit: true
      };
    }
    if (specifier.endsWith('/src/authorize-device.mjs')) {
      return {
        url: 'mock:restore-device',
        shortCircuit: true
      };
    }

    return nextResolve(specifier, context);
  },

  load(url, context, nextLoad) {
    if (url === 'mock:restore-device') {
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
              async rpc(name, args) {
                if (name !== 'stage10_restore_note_atomic') {
                  throw new Error('Unexpected RPC: ' + name);
                }

                globalThis.__restoreTestRpcCalls++;
                globalThis.__restoreTestRpcArgs = args;

                if (globalThis.__restoreTestRpcError) {
                  return {
                    data: null,
                    error: { message: 'Mock RPC failure' }
                  };
                }

                const id = args.p_note_id;
                const ownerId = args.p_owner_id;
                const preview = args.p_preview === true;

                const first = globalThis.__restoreTestBackup;
                globalThis.__restoreTestBackupReads++;

                const fail = (error, reason, backupId = null) => {
                  globalThis.__restoreTestAudit.push({
                    action: 'note_restore',
                    outcome: 'fail',
                    details: {
                      note_id: id,
                      owner_id: ownerId,
                      backup_id: backupId,
                      reason
                    }
                  });

                  return {
                    data: { restored: false, error },
                    error: null
                  };
                };

                if (
                  !first
                  || first.note_id !== id
                  || first.owner_id !== ownerId
                ) {
                  return fail(
                    'VERIFIED_NOTE_BACKUP_NOT_FOUND',
                    'backup_not_found'
                  );
                }

                const valid = backup => {
                  if (!backup) return false;
                  return (
                    backup.note_id === id
                    && backup.owner_id === ownerId
                    && typeof backup.title === 'string'
                    && typeof backup.content === 'string'
                    && globalThis.__restoreTestHash(backup.content)
                      === backup.content_sha256
                    && globalThis.__restoreTestHash(
                      backup.title + '\\n' + backup.content
                    ) === backup.snapshot_sha256
                  );
                };

                if (globalThis.__restoreTestSecondReadError) {
                  globalThis.__restoreTestBackupReads++;
                  return {
                    data: null,
                    error: { message: 'Mock backup read failure' }
                  };
                }

                globalThis.__restoreTestBackupReads++;

                const second =
                  globalThis.__restoreTestSecondBackup === undefined
                    ? first
                    : globalThis.__restoreTestSecondBackup;

                if (!second) {
                  return fail(
                    'VERIFIED_NOTE_BACKUP_NOT_FOUND',
                    'backup_missing_on_reread',
                    first.id
                  );
                }

                if (
                  !valid(second)
                  || second.id !== first.id
                  || second.created_at !== first.created_at
                  || second.title !== first.title
                  || second.content !== first.content
                  || second.content_sha256 !== first.content_sha256
                  || second.snapshot_sha256 !== first.snapshot_sha256
                ) {
                  return fail(
                    'NOTE_BACKUP_VERIFICATION_FAILED',
                    'backup_verification_failed',
                    first.id
                  );
                }

                const current = globalThis.__restoreTestNote;

                if (current && current.owner_id !== ownerId) {
                  return fail(
                    'NOTE_OWNER_MISMATCH',
                    'current_owner_mismatch',
                    second.id
                  );
                }

                const plan = {
                  backup_id: second.id,
                  backup_version: second.created_at,
                  current_exists: Boolean(current),
                  changes: {
                    recreate: !current,
                    title: !current || current.title !== second.title,
                    content: !current || current.content !== second.content
                  }
                };

                if (preview) {
                  return {
                    data: {
                      preview: true,
                      verified: true,
                      backup_id: second.id,
                      backup_version: second.created_at,
                      plan
                    },
                    error: null
                  };
                }

                if (globalThis.__restoreTestAuditError) {
                  return {
                    data: null,
                    error: { message: 'Mock audit failure' }
                  };
                }

                globalThis.__restoreTestAudit.push({
                  action: 'note_restore',
                  outcome: 'started',
                  details: { note_id: id, owner_id: ownerId }
                });

                globalThis.__restoreTestNote = {
                  id,
                  owner_id: ownerId,
                  title: second.title,
                  content: second.content
                };

                globalThis.__restoreTestNoteWrites++;

                globalThis.__restoreTestAudit.push({
                  action: 'note_restore',
                  outcome: 'pass',
                  details: {
                    note_id: id,
                    owner_id: ownerId,
                    backup_id: second.id
                  }
                });

                return {
                  data: {
                    restored: true,
                    id,
                    owner_id: ownerId,
                    content_sha256: second.content_sha256,
                    backup_id: second.id,
                    backup_version: second.created_at,
                    plan
                  },
                  error: null
                };
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

globalThis.__restoreTestHash = hash;

const { default: handler } =
  await import('../api/notes/[id]/restore.js');

function setup({
  userId = USER_B,
  authorized = true,
  backup = initialBackup(),
  secondBackup = undefined,
  secondReadError = false,
  note = null,
  rpcError = false,
  auditError = false
} = {}) {
  state = { userId, authorized };

  globalThis.__restoreTestUserId = userId;
  globalThis.__restoreTestBackup = backup;
  globalThis.__restoreTestSecondBackup = secondBackup;
  globalThis.__restoreTestSecondReadError = secondReadError;
  globalThis.__restoreTestNote = note;
  globalThis.__restoreTestRpcError = rpcError;
  globalThis.__restoreTestAuditError = auditError;

  globalThis.__restoreTestBackupReads = 0;
  globalThis.__restoreTestNoteWrites = 0;
  globalThis.__restoreTestRpcCalls = 0;
  globalThis.__restoreTestRpcArgs = null;
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
  const rawBody = body === undefined
    ? ''
    : JSON.stringify(body);

  const request = {
    method,
    url: `/api/notes/${id}/restore`,
    headers: {
      authorization: state.authorized
        ? 'Bearer test-token'
        : undefined
    },
    query: { id },
    body,

    async *[Symbol.asyncIterator]() {
      if (rawBody) {
        yield Buffer.from(rawBody, 'utf8');
      }
    }
  };

  await handler(request, response);

  return response;
}

test('rejects unauthenticated restore requests', async () => {
  setup({ authorized: false });

  const response = await requestRestore();

  assert.equal(response.statusCode, 401);
  assert.equal(globalThis.__restoreTestRpcCalls, 0);
});

test('does not read another user backup', async () => {
  setup({ userId: USER_A });

  const response = await requestRestore();

  assert.equal(response.statusCode, 404);
  assert.equal(
    response.body.error,
    'VERIFIED_NOTE_BACKUP_NOT_FOUND'
  );
  assert.equal(globalThis.__restoreTestNoteWrites, 0);
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
  assert.equal(response.body.content_sha256, hash(CONTENT));
  assert.equal(globalThis.__restoreTestNote.content, CONTENT);
  assert.equal(globalThis.__restoreTestNoteWrites, 1);
  assert.equal(globalThis.__restoreTestBackupReads, 2);
  assert.deepEqual(
    globalThis.__restoreTestAudit.map(item => item.outcome),
    ['started', 'pass']
  );
});

test('allows POST only', async () => {
  setup();

  const response = await requestRestore({ method: 'GET' });

  assert.equal(response.statusCode, 405);
  assert.equal(globalThis.__restoreTestRpcCalls, 0);
});

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
  assert.equal(globalThis.__restoreTestNoteWrites, 0);
  assert.equal(
    globalThis.__restoreTestNote.content,
    'Changed content'
  );
});

test('stops restoration if backup version changes', async () => {
  const changedBackup = initialBackup();
  changedBackup.created_at = '2026-10-13T11:00:00.000Z';

  setup({ secondBackup: changedBackup });

  const response = await requestRestore();

  assert.equal(response.statusCode, 409);
  assert.equal(globalThis.__restoreTestNoteWrites, 0);
});

test('stops restoration if backup hash changes on re-read', async () => {
  const changedBackup = initialBackup();
  changedBackup.content = 'Changed backup without hash update';

  setup({ secondBackup: changedBackup });

  const response = await requestRestore();

  assert.equal(response.statusCode, 409);
  assert.equal(globalThis.__restoreTestNoteWrites, 0);
});

test('stops restoration if the second backup read fails', async () => {
  setup({ secondReadError: true });

  const response = await requestRestore();

  assert.equal(response.statusCode, 500);
  assert.equal(response.body.error, 'NOTE_RESTORE_FAILED');
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
  assert.equal(response.body.backup_version, VERSION);
  assert.equal(response.body.plan.changes.title, true);
  assert.equal(response.body.plan.changes.content, true);
  assert.equal(globalThis.__restoreTestNoteWrites, 0);
});

test('does not restore if RPC fails', async () => {
  setup({ rpcError: true });

  const response = await requestRestore();

  assert.equal(response.statusCode, 500);
  assert.equal(globalThis.__restoreTestNoteWrites, 0);
});

test('does not restore if audit insertion fails', async () => {
  setup({
    auditError: true,
    note: {
      id: NOTE_ID,
      owner_id: USER_B,
      title: 'Changed title',
      content: 'Changed content'
    }
  });

  const response = await requestRestore();

  assert.equal(response.statusCode, 500);
  assert.equal(globalThis.__restoreTestNoteWrites, 0);
  assert.equal(
    globalThis.__restoreTestNote.content,
    'Changed content'
  );
});

test('passes authenticated identity to RPC', async () => {
  setup();

  await requestRestore({ body: { preview: true } });

  assert.deepEqual(globalThis.__restoreTestRpcArgs, {
    p_note_id: NOTE_ID,
    p_owner_id: USER_B,
    p_preview: true
  });
});
