
import { createClient } from '@supabase/supabase-js';
import { createLoginVerifier } from '../../../src/verify-login.mjs';
import { authorizeDevice } from '../../../src/authorize-device.mjs';
import { readRequestBody } from '../../../src/read-request-body.mjs';
import alephConfig from '../../../aleph.config.json' with { type: 'json' };

let verifyLogin;

function getVerifier(supabaseSecretKey) {
  if (!verifyLogin) {
    verifyLogin = createLoginVerifier({
      config: alephConfig,
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

function respond(response, status, body) {
  return response.status(status).json(body);
}

// Disable automatic body parsing to preserve signed request bytes.
export const config = {
  api: {
    bodyParser: false
  }
};

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

  const supabase = makeClient(supabaseUrl, supabaseSecretKey);

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

  if (!isUuid(login.userId)) {
    return respond(response, 401, {
      error: 'UNAUTHORIZED'
    });
  }

  let body = request.body ?? {};
  let rawBody = '';

  // Stage 11: Student requests require an approved device
  // and a valid signature over the original request body.
  if (login.kind === 'student') {
    try {
      ({ body, rawBody } = await readRequestBody(request));
    } catch (error) {
      return respond(response, error.statusCode ?? 400, {
        error: error.message ?? 'INVALID_REQUEST_BODY'
      });
    }

    const deviceAuth = await authorizeDevice({
      request,
      supabase,
      login,
      rawBody
    });

    if (!deviceAuth.ok) {
      return respond(response, 403, {
        error: deviceAuth.reason
      });
    }
  }

  // Preserve the existing authenticated judge restore flow.
  const preview = body?.preview === true;

  try {
    const { data, error } = await supabase.rpc(
      'stage10_restore_note_atomic',
      {
        p_note_id: id,
        p_owner_id: login.userId,
        p_preview: preview
      }
    );

    if (error) {
      return respond(response, 500, {
        error: 'NOTE_RESTORE_FAILED'
      });
    }

    if (!data || typeof data !== 'object') {
      return respond(response, 500, {
        error: 'NOTE_RESTORE_INVALID_RESULT'
      });
    }

    if (data.error) {
      const statusByError = {
        VERIFIED_NOTE_BACKUP_NOT_FOUND: 404,
        NOTE_BACKUP_VERIFICATION_FAILED: 409,
        NOTE_OWNER_MISMATCH: 409
      };

      return respond(
        response,
        statusByError[data.error] ?? 500,
        data
      );
    }

    if (preview) {
      if (data.preview !== true || data.verified !== true) {
        return respond(response, 500, {
          error: 'NOTE_RESTORE_INVALID_PREVIEW'
        });
      }

      return respond(response, 200, data);
    }

    if (data.restored !== true || data.id !== id) {
      return respond(response, 500, {
        error: 'NOTE_RESTORE_INVALID_RESULT'
      });
    }

    return respond(response, 200, data);
  } catch {
    return respond(response, 500, {
      error: 'NOTE_RESTORE_FAILED'
    });
  }
}
