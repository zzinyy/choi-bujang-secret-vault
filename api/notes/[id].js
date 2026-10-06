import { createClient } from '@supabase/supabase-js';
import { createLoginVerifier } from '../../src/verify-login.mjs';
import config from '../../aleph.config.json' with { type: 'json' };

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

export default async function handler(request, response) {
  response.setHeader('Cache-Control', 'no-store');

  if (!['GET', 'PUT', 'DELETE'].includes(request.method)) {
    response.setHeader('Allow', 'GET, PUT, DELETE');

    return response.status(405).json({
      error: 'METHOD_NOT_ALLOWED'
    });
  }

  const supabaseUrl = process.env.SUPABASE_URL;
  const supabaseSecretKey = process.env.SUPABASE_SECRET_KEY;

  if (!supabaseUrl || !supabaseSecretKey) {
    return response.status(500).json({
      error: 'SUPABASE_SERVER_CONFIG_MISSING'
    });
  }

  let login;

  try {
    login = await getVerifier(supabaseSecretKey)(
      request.headers.authorization
    );
  } catch {
    return response.status(401).json({
      error: 'UNAUTHORIZED'
    });
  }

  if (!login) {
    return response.status(401).json({
      error: 'UNAUTHORIZED'
    });
  }

  const id = Array.isArray(request.query.id)
    ? request.query.id[0]
    : request.query.id;

  if (!isUuid(id)) {
    return response.status(400).json({
      error: 'INVALID_NOTE_ID'
    });
  }

  const supabase = createClient(
    supabaseUrl,
    supabaseSecretKey,
    {
      auth: {
        persistSession: false,
        autoRefreshToken: false
      }
    }
  );

  if (request.method === 'GET') {
    const { data, error } = await supabase
      .from('notes')
      .select('id, title, content')
      .eq('id', id)
      .maybeSingle();

    if (error) {
      return response.status(500).json({
        error: 'NOTE_READ_FAILED'
      });
    }

    if (!data) {
      return response.status(404).json({
        error: 'NOTE_NOT_FOUND'
      });
    }

    return response.status(200).json({
      id: data.id,
      title: data.title,
      body: data.content
    });
  }

  if (request.method === 'PUT') {
    const body = request.body ?? {};

    if (
      typeof body.title !== 'string'
      || typeof body.body !== 'string'
      || !body.title.trim()
      || !body.body.trim()
    ) {
      return response.status(400).json({
        error: 'INVALID_NOTE'
      });
    }

    const { data, error } = await supabase
      .from('notes')
      .update({
        title: body.title.trim(),
        content: body.body.trim()
      })
      .eq('id', id)
      .select('id')
      .maybeSingle();

    if (error) {
      return response.status(500).json({
        error: 'NOTE_UPDATE_FAILED'
      });
    }

    if (!data) {
      return response.status(404).json({
        error: 'NOTE_NOT_FOUND'
      });
    }

    return response.status(200).json({
      id: data.id
    });
  }

  const { data, error } = await supabase
    .from('notes')
    .delete()
    .eq('id', id)
    .select('id')
    .maybeSingle();

  if (error) {
    return response.status(500).json({
      error: 'NOTE_DELETE_FAILED'
    });
  }

  if (!data) {
    return response.status(404).json({
      error: 'NOTE_NOT_FOUND'
    });
  }

  return response.status(200).json({
    id: data.id
  });
}