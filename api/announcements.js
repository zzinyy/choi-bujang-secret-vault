
import { createClient } from '@supabase/supabase-js';
import { createLoginVerifier } from '../src/verify-login.mjs';
import { verifyInstructor } from '../src/verify-instructor.mjs';
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

export default async function handler(request, response) {
  response.setHeader('Cache-Control', 'no-store');

  // Only GET and POST are supported.
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

  // Verify the login token on the server.
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

  // Use the server-side Supabase client.
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

  // GET: List announcements.
  if (request.method === 'GET') {
    const { data, error } = await supabase
      .from('announcements')
      .select('id, title, content, created_at')
      .order('created_at', { ascending: false });

    if (error) {
      return response.status(500).json({
        error: 'ANNOUNCEMENTS_READ_FAILED'
      });
    }

    return response.status(200).json({
      announcements: data.map((item) => ({
        id: item.id,
        title: item.title,
        body: item.content,
        createdAt: item.created_at
      }))
    });
  }

  // POST: Only verified instructors may create announcements.
  const isInstructor = await verifyInstructor(supabase, login);

  if (!isInstructor) {
    return response.status(403).json({
      error: 'INSTRUCTOR_REQUIRED'
    });
  }

  const body = request.body ?? {};

  if (
    typeof body.title !== 'string' ||
    typeof body.body !== 'string' ||
    !body.title.trim() ||
    !body.body.trim()
  ) {
    return response.status(400).json({
      error: 'INVALID_ANNOUNCEMENT'
    });
  }

  // The server chooses the author.
  // Ignore role and created_by from request.body.
  const { data, error } = await supabase
    .from('announcements')
    .insert({
      title: body.title.trim(),
      content: body.body.trim(),
      created_by: login.userId
    })
    .select('id')
    .single();

  if (error) {
    return response.status(500).json({
      error: 'ANNOUNCEMENT_CREATE_FAILED'
    });
  }

  return response.status(201).json({
    id: data.id
  });
}
