import { createClient } from '@supabase/supabase-js';
import { createLoginVerifier } from '../../src/verify-login.mjs';
import config from '../../aleph.config.json' with { type: 'json' };

let verifyLogin;

export default async function handler(request, response) {
  response.setHeader('Cache-Control', 'no-store');
  response.setHeader('X-Content-Type-Options', 'nosniff');

  if (request.method !== 'POST') {
    response.setHeader('Allow', 'POST');
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
    verifyLogin ??= createLoginVerifier({
      config,
      supabaseSecretKey
    });

    login = await verifyLogin(request.headers.authorization);
  } catch {
    return response.status(401).json({
      error: 'UNAUTHORIZED'
    });
  }

  if (!login || login.kind !== 'student') {
    return response.status(401).json({
      error: 'UNAUTHORIZED'
    });
  }

  const body = request.body;

  if (
    !body ||
    typeof body !== 'object' ||
    Array.isArray(body) ||
    Object.keys(body).length !== 1 ||
    !body.publicKeyJwk ||
    typeof body.publicKeyJwk !== 'object' ||
    Array.isArray(body.publicKeyJwk)
  ) {
    return response.status(400).json({
      error: 'INVALID_DEVICE_REQUEST'
    });
  }

  const key = body.publicKeyJwk;

  if (
    key.kty !== 'EC' ||
    key.crv !== 'P-256' ||
    typeof key.x !== 'string' ||
    typeof key.y !== 'string' ||
    key.x.length !== 43 ||
    key.y.length !== 43 ||
    key.d !== undefined
  ) {
    return response.status(400).json({
      error: 'INVALID_PUBLIC_KEY'
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

  const { data, error } = await supabase
    .from('stage11_devices')
    .insert({
      owner_id: login.userId,
      public_key_jwk: key,
      status: 'pending'
    })
    .select('id')
    .single();

  if (error) {
    return response.status(500).json({
      error: 'DEVICE_REGISTRATION_FAILED'
    });
  }

  return response.status(202).json({
    approved: false,
    reason: 'approval_pending',
    deviceId: data.id
  });
}