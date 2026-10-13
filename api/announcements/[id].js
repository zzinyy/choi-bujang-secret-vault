
import { createClient } from '@supabase/supabase-js';
import { createLoginVerifier } from '../../src/verify-login.mjs';
import { verifyInstructor } from '../../src/verify-instructor.mjs';
import config from '../../aleph.config.json' with { type: 'json' };

const UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

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

  const allowedMethods = ['GET', 'PUT', 'DELETE'];

  if (!allowedMethods.includes(request.method)) {
    response.setHeader('Allow', allowedMethods.join(', '));

    return response.status(405).json({
      error: 'METHOD_NOT_ALLOWED'
    });
  }

  // Only one UUID resource ID is accepted.
  const id = request.query?.id;

  if (typeof id !== 'string' || !UUID.test(id)) {
    return response.status(404).json({
      error: 'ANNOUNCEMENT_NOT_FOUND'
    });
  }

  const supabaseUrl = process.env.SUPABASE_URL;
  const supabaseSecretKey = process.env.SUPABASE_SECRET_KEY;

  if (!supabaseUrl || !supabaseSecretKey) {
    return response.status(500).json({
      error: 'SUPABASE_SERVER_CONFIG_MISSING'
    });
  }

  // Authenticate the caller using the Authorization header.
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

  // The Supabase secret key must remain on the server.
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

  // GET: Authenticated users may read announcements.
  if (request.method === 'GET') {
    const { data, error } = await supabase
      .from('announcements')
      .select('id, title, content, created_at, updated_at')
      .eq('id', id)
      .maybeSingle();

    if (error) {
      return response.status(500).json({
        error: 'ANNOUNCEMENT_READ_FAILED'
      });
    }

    if (!data) {
      return response.status(404).json({
        error: 'ANNOUNCEMENT_NOT_FOUND'
      });
    }

    return response.status(200).json({
      announcement: {
        id: data.id,
        title: data.title,
        body: data.content,
        createdAt: data.created_at,
        updatedAt: data.updated_at
      }
    });
  }

  // PUT and DELETE require trusted instructor membership.
  const isInstructor = await verifyInstructor(supabase, login);

  if (!isInstructor) {
    return response.status(403).json({
      error: 'INSTRUCTOR_REQUIRED'
    });
  }

  if (request.method === 'PUT') {
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

    const { data, error } = await supabase
      .from('announcements')
      .update({
        title: body.title.trim(),
        content: body.body.trim(),
        updated_at: new Date().toISOString()
      })
      .eq('id', id)
      .select('id')
      .maybeSingle();

    if (error) {
      return response.status(500).json({
        error: 'ANNOUNCEMENT_UPDATE_FAILED'
      });
    }

    if (!data) {
      return response.status(404).json({
        error: 'ANNOUNCEMENT_NOT_FOUND'
      });
    }

    return response.status(200).json({
      id: data.id,
      updated: true
    });
  }

  // DELETE: Only instructors may delete announcements.
  const { data, error } = await supabase
    .from('announcements')
    .delete()
    .eq('id', id)
    .select('id')
    .maybeSingle();

  if (error) {
    return response.status(500).json({
      error: 'ANNOUNCEMENT_DELETE_FAILED'
    });
  }

  if (!data) {
    return response.status(404).json({
      error: 'ANNOUNCEMENT_NOT_FOUND'
    });
  }

  return response.status(200).json({
    id: data.id,
    deleted: true
  });
}
