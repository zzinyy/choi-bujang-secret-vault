
import { createHash } from 'node:crypto';
import { createClient } from '@supabase/supabase-js';
import { createLoginVerifier } from '../../../src/verify-login.mjs';
import config from '../../../aleph.config.json' with { type: 'json' };

let verifyLogin;

function getVerifier(supabaseSecretKey) {
  if (!verifyLogin) {
    verifyLogin = createLoginVerifier({
      config,
      supabaseSecretKey
    });
  }
  return verifyLogin;
}

function makeClient(url, key) {
  return createClient(url, key, {
    auth: {
      persistSession: false,
      autoRefreshToken: false,
      detectSessionInUrl: false
    }
  });
}

function isUuid(value) {
  return typeof value === 'string'
    && /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu.test(value);
}

function sha256(value) {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

function respond(response, status, body) {
  return response.status(status).json(body);
}

async function writeAudit(supabase, action, outcome, details) {
  const { error } = await supabase
    .from('stage10_policy_audit')
    .insert({ action, outcome, details });

  if (error) {
    throw new Error('NOTE_RESTORE_AUDIT_FAILED');
  }
}

async function tryAudit(supabase, outcome, details) {
  try {
    await supabase
      .from('stage10_policy_audit')
      .insert({ action: 'note_restore', outcome, details });
  } catch {
    // Diagnostic only.
  }
}

function validBackup(backup, id, ownerId) {
  return Boolean(
    backup
    && backup.note_id === id
    && backup.owner_id === ownerId
    && typeof backup.title === 'string'
    && typeof backup.content === 'string'
    && typeof backup.content_sha256 === 'string'
    && sha256(backup.content) === backup.content_sha256
    && typeof backup.snapshot_sha256 === 'string'
    && sha256(`${backup.title}\n${backup.content}`) === backup.snapshot_sha256
  );
}

async function readBackup(supabase, id, ownerId) {
  return supabase
    .from('stage10_note_backups')
    .select('id, note_id, owner_id, title, content, content_sha256, snapshot_sha256, created_at')
    .eq('note_id', id)
    .eq('owner_id', ownerId)
    .order('created_at', { ascending: false })
    .limit(1)
    .maybeSingle();
}

function makePlan(backup, current) {
  return {
    backup_id: backup.id,
    backup_version: backup.created_at ?? null,
    backup_title_sha256: sha256(backup.title),
    backup_content_sha256: backup.content_sha256,
    current_exists: Boolean(current),
    current_title_sha256: current ? sha256(current.title ?? '') : null,
    current_content_sha256: current ? sha256(current.content ?? '') : null,
    changes: {
      recreate: !current,
      title: !current || current.title !== backup.title,
      content: !current || current.content !== backup.content
    }
  };
}

export default async function handler(request, response) {
  response.setHeader('Cache-Control', 'no-store');

  if (request.method !== 'POST') {
    response.setHeader('Allow', 'POST');
    return respond(response, 405, {
      error: 'METHOD_NOT_ALLOWED'
    });
  }

  const supabaseUrl = process.env.SUPABASE_URL;
  const supabaseSecretKey = process.env.SUPABASE_SECRET_KEY;

  if (!supabaseUrl || !supabaseSecretKey) {
    return respond(response, 500, {
      error: 'SUPABASE_SERVER_CONFIG_MISSING'
    });
  }

  const auditClient = makeClient(supabaseUrl, supabaseSecretKey);
  let login;

  try {
    login = await getVerifier(supabaseSecretKey)(
      request.headers.authorization
    );
  } catch {
    await tryAudit(auditClient, 'fail', {
      reason: 'login_exception',
      has_auth_header: Boolean(request.headers.authorization),
      note_id: request.query?.id ?? null
    });
    return respond(response, 401, { error: 'UNAUTHORIZED' });
  }

  if (!login || !['student', 'judge'].includes(login.kind)) {
    await tryAudit(auditClient, 'fail', {
      reason: 'login_rejected',
      has_auth_header: Boolean(request.headers.authorization),
      note_id: request.query?.id ?? null
    });
    return respond(response, 401, { error: 'UNAUTHORIZED' });
  }

  const id = Array.isArray(request.query?.id)
    ? request.query.id[0]
    : request.query?.id;

  if (!isUuid(id)) {
    await tryAudit(auditClient, 'fail', {
      reason: 'invalid_note_id',
      kind: login.kind,
      raw_id: typeof id === 'string' ? id.slice(0, 64) : null
    });
    return respond(response, 400, { error: 'INVALID_NOTE_ID' });
  }

  const supabase = makeClient(supabaseUrl, supabaseSecretKey);
  const preview = request.body?.preview === true;

  try {
    // 1. Read and verify the stored backup.
    const { data: firstBackup, error: firstError } =
      await readBackup(supabase, id, login.userId);

    if (firstError) {
      return respond(response, 500, {
        error: 'NOTE_BACKUP_READ_FAILED'
      });
    }

    if (!firstBackup) {
      await tryAudit(supabase, 'fail', {
        note_id: id,
        owner_id: login.userId,
        kind: login.kind,
        identity: login.identity ?? null,
        reason: 'backup_not_found'
      });
      return respond(response, 404, {
        error: 'VERIFIED_NOTE_BACKUP_NOT_FOUND'
      });
    }

    if (!validBackup(firstBackup, id, login.userId)) {
      await writeAudit(supabase, 'note_restore', 'fail', {
        note_id: id,
        owner_id: login.userId,
        backup_id: firstBackup.id,
        reason: 'backup_verification_failed'
      });
      return respond(response, 409, {
        error: 'NOTE_BACKUP_VERIFICATION_FAILED'
      });
    }

    const { data: current, error: currentError } = await supabase
      .from('notes')
      .select('id, owner_id, title, content')
      .eq('id', id)
      .maybeSingle();

    if (currentError) {
      return respond(response, 500, {
        error: 'NOTE_STATE_READ_FAILED'
      });
    }

    if (current && current.owner_id !== login.userId) {
      await writeAudit(supabase, 'note_restore', 'fail', {
        note_id: id,
        owner_id: login.userId,
        backup_id: firstBackup.id,
        reason: 'current_owner_mismatch'
      });
      return respond(response, 409, {
        error: 'NOTE_OWNER_MISMATCH'
      });
    }

    // 2. Re-read the backup immediately before restoration.
    const { data: backup, error: rereadError } =
      await readBackup(supabase, id, login.userId);

    if (rereadError) {
      return respond(response, 500, {
        error: 'NOTE_BACKUP_READ_FAILED'
      });
    }

    if (!backup) {
      await tryAudit(supabase, 'fail', {
        note_id: id,
        owner_id: login.userId,
        reason: 'backup_missing_on_reread'
      });
      return respond(response, 404, {
        error: 'VERIFIED_NOTE_BACKUP_NOT_FOUND'
      });
    }

    const sameVersion =
      backup.id === firstBackup.id
      && backup.created_at === firstBackup.created_at
      && backup.snapshot_sha256 === firstBackup.snapshot_sha256
      && backup.content_sha256 === firstBackup.content_sha256;

    if (!validBackup(backup, id, login.userId) || !sameVersion) {
      await writeAudit(supabase, 'note_restore', 'fail', {
        note_id: id,
        owner_id: login.userId,
        backup_id: backup.id,
        reason: 'backup_reread_verification_failed'
      });
      return respond(response, 409, {
        error: 'NOTE_BACKUP_VERIFICATION_FAILED'
      });
    }

    const plan = makePlan(backup, current);

    // Preview the backup version and changed fields without modifying notes.
    if (preview) {
      return respond(response, 200, {
        preview: true,
        verified: true,
        id,
        owner_id: login.userId,
        backup_id: backup.id,
        backup_version: backup.created_at ?? null,
        plan
      });
    }

    await writeAudit(supabase, 'note_restore', 'started', {
      note_id: id,
      owner_id: login.userId,
      backup_id: backup.id,
      backup_version: backup.created_at ?? null,
      content_sha256: backup.content_sha256,
      plan
    });

    let restored;
    let restoreError;

    if (current) {
      const result = await supabase
        .from('notes')
        .update({
          title: backup.title,
          content: backup.content
        })
        .eq('id', id)
        .eq('owner_id', login.userId)
        .select('id, owner_id, title, content')
        .maybeSingle();

      restored = result.data;
      restoreError = result.error;
    } else {
      const result = await supabase
        .from('notes')
        .insert({
          id,
          owner_id: login.userId,
          title: backup.title,
          content: backup.content
        })
        .select('id, owner_id, title, content')
        .maybeSingle();

      restored = result.data;
      restoreError = result.error;
    }

    if (restoreError || !restored) {
      await writeAudit(supabase, 'note_restore', 'fail', {
        note_id: id,
        owner_id: login.userId,
        backup_id: backup.id,
        reason: restoreError
          ? 'database_restore_failed'
          : 'note_owner_changed'
      });
      return respond(response, 409, {
        error: 'NOTE_RESTORE_FAILED'
      });
    }

    const restoredHash = sha256(restored.content);

    if (
      restored.id !== id
      || restored.owner_id !== login.userId
      || restored.title !== backup.title
      || restoredHash !== backup.content_sha256
    ) {
      await writeAudit(supabase, 'note_restore', 'fail', {
        note_id: id,
        owner_id: login.userId,
        backup_id: backup.id,
        reason: 'post_restore_verification_failed'
      });
      return respond(response, 500, {
        error: 'NOTE_RESTORE_VERIFICATION_FAILED'
      });
    }

    await writeAudit(supabase, 'note_restore', 'pass', {
      note_id: id,
      owner_id: login.userId,
      backup_id: backup.id,
      content_sha256: restoredHash
    });

    return respond(response, 200, {
      restored: true,
      id: restored.id,
      owner_id: restored.owner_id,
      content_sha256: restoredHash,
      backup_id: backup.id,
      backup_version: backup.created_at ?? null,
      plan
    });
  } catch (error) {
    if (error.message === 'NOTE_RESTORE_AUDIT_FAILED') {
      return respond(response, 500, {
        error: 'NOTE_RESTORE_AUDIT_FAILED'
      });
    }
    return respond(response, 500, {
      error: 'NOTE_RESTORE_FAILED'
    });
  }
}
