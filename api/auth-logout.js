export default async function handler(request, response) {
  response.setHeader('Cache-Control', 'no-store');

  if (request.method !== 'POST') {
    response.setHeader('Allow', 'POST');

    return response.status(405).json({
      error: 'METHOD_NOT_ALLOWED'
    });
  }

  const supabaseUrl = process.env.SUPABASE_URL;
  const publishableKey =
    process.env.SUPABASE_PUBLISHABLE_KEY;

  if (!supabaseUrl || !publishableKey) {
    return response.status(500).json({
      error: 'SUPABASE_AUTH_CONFIG_MISSING'
    });
  }

  const authorization =
    request.headers.authorization;

  if (
    typeof authorization !== 'string'
    || !authorization.startsWith('Bearer ')
  ) {
    return response.status(401).json({
      error: 'UNAUTHORIZED'
    });
  }

  try {
    const authResponse = await fetch(
      `${supabaseUrl}/auth/v1/logout`,
      {
        method: 'POST',
        headers: {
          apikey: publishableKey,
          Authorization: authorization
        }
      }
    );

    if (!authResponse.ok) {
      return response.status(401).json({
        error: 'LOGOUT_FAILED'
      });
    }

    return response.status(200).json({
      ok: true
    });
  } catch {
    return response.status(502).json({
      error: 'AUTH_SERVICE_UNAVAILABLE'
    });
  }
}