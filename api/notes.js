import { randomUUID } from 'node:crypto';
import { createClient } from '@supabase/supabase-js';
import { createLoginVerifier } from '../src/verify-login.mjs';
import config from '../aleph.config.json' with { type: 'json' };

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

  if (!['GET', 'POST'].includes(request.method)) {
    response.setHeader('Allow', 'GET, POST');

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
      .eq('owner_id', login.userId)
      .order('created_at', { ascending: true });

    if (error) {
      return response.status(500).json({
        error: 'NOTES_READ_FAILED'
      });
    }

    return response.status(200).json({
      notes: data.map((note) => ({
        id: note.id,
        title: note.title,
        body: note.content
      }))
    });
  }

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

  if (body.id !== undefined && !isUuid(body.id)) {
    return response.status(400).json({
      error: 'INVALID_NOTE_ID'
    });
  }

  const id = body.id ?? randomUUID();

  const { error } = await supabase
    .from('notes')
    .insert({
      id,
      owner_id: login.userId,
      title: body.title.trim(),
      content: body.body.trim()
    });

  if (error) {
    if (error.code === '23505') {
      return response.status(409).json({
        error: 'NOTE_ID_CONFLICT'
      });
    }

    return response.status(500).json({
      error: 'NOTE_CREATE_FAILED'
    });
  }

  return response.status(201).json({
    id
  });
}