
import { createClient } from '@supabase/supabase-js';
import { createLoginVerifier } from '../../src/verify-login.mjs';
import { authorizeDevice } from '../../src/authorize-device.mjs';
import config from '../../aleph.config.json' with { type: 'json' };

let verifyLogin;

export default async function handler(request, response) {
  response.setHeader('Cache-Control', 'no-store');
  response.setHeader('X-Content-Type-Options', 'nosniff');

  if (request.method !== 'GET') {
    response.setHeader('Allow', 'GET');

    return response.status(405).json({
      error: 'method_not_allowed'
    });
  }

  const supabaseUrl = process.env.SUPABASE_URL;
  const supabaseSecretKey = process.env.SUPABASE_SECRET_KEY;

  if (!supabaseUrl || !supabaseSecretKey) {
    return response.status(503).json({
      error: 'device_status_unavailable'
    });
  }

  const authorization = request.headers.authorization;

  if (!authorization?.startsWith('Bearer ')) {
    return response.status(401).json({
      error: 'login_required'
    });
  }

  let login;

  try {
    verifyLogin ??= createLoginVerifier({
      config,
      supabaseSecretKey
    });

    login = await verifyLogin(authorization);
  } catch {
    return response.status(401).json({
      error: 'login_required'
    });
  }

  if (!login) {
    return response.status(401).json({
      error: 'login_required'
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

  try {
    const result = await authorizeDevice({
      request,
      supabase,
      login,
      rawBody: ''
    });

    if (!result.ok) {
      return response.status(200).json({
        approved: false,
        reason: result.reason
      });
    }

    return response.status(200).json({
      approved: true,
      deviceId: result.deviceId
    });
  } catch {
    return response.status(503).json({
      error: 'device_status_unavailable'
    });
  }
}
