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
    // Diagnostic only. Never change the response because of it.
  }
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

  let login;

  try {
    login = await getVerifier(supabaseSecretKey)(
      request.headers.authorization
    );
  } catch {
    return respond(response, 401, {
      error: 'UNAUTHORIZED'
    });
  }

  if (!login || !['student', 'judge'].includes(login.kind)) {
    return respond(response, 401, {
      error: 'UNAUTHORIZED'
    });
  }

  const id = Array.isArray(request.query?.id)
    ? request.query.id[0]
    : request.query?.id;

  if (!isUuid(id)) {
    return respond(response, 400, {
      error: 'INVALID_NOTE_ID'
    });
  }

  const supabase = createClient(
    supabaseUrl,
    supabaseSecretKey,
    {
      auth: {
        persistSession: false,
        autoRefreshToken: false,
        detectSessionInUrl: false
      }
    }
  );

  try {
    const { data: backup, error: backupError } = await supabase
      .from('stage10_note_backups')
      .select('id, note_id, owner_id, title, content, content_sha256, snapshot_sha256')
      .eq('note_id', id)
      .eq('owner_id', login.userId)
      .order('created_at', { ascending: false })
      .limit(1)
      .maybeSingle();

    if (backupError) {
      return respond(response, 500, {
        error: 'NOTE_BACKUP_READ_FAILED'
      });
    }

    if (!backup) {
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

    if (
      backup.note_id !== id
      || backup.owner_id !== login.userId
      || typeof backup.title !== 'string'
      || typeof backup.content !== 'string'
      || sha256(backup.content) !== backup.content_sha256
      || typeof backup.snapshot_sha256 !== 'string'
      || sha256(`${backup.title}\n${backup.content}`) !== backup.snapshot_sha256
    ) {
      await writeAudit(supabase, 'note_restore', 'fail', {
        note_id: id,
        owner_id: login.userId,
        backup_id: backup.id,
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
        backup_id: backup.id,
        reason: 'current_owner_mismatch'
      });

      return respond(response, 409, {
        error: 'NOTE_OWNER_MISMATCH'
      });
    }

    const plan = {
      backup_id: backup.id,
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

    await writeAudit(supabase, 'note_restore', 'started', {
      note_id: id,
      owner_id: login.userId,
      backup_id: backup.id,
      content_sha256: backup.content_sha256,
      plan
    });

    let restored;
    let restoreError;

    if (current) {
      // Update only if the row still belongs to the authenticated user.
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
      // A concurrent insert with the same ID will fail rather than overwrite.
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
        reason: restoreError ? 'database_restore_failed' : 'note_owner_changed'
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