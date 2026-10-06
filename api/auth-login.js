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

  const body = request.body ?? {};

  if (
    typeof body.email !== 'string'
    || typeof body.password !== 'string'
    || !body.email.trim()
    || !body.password
  ) {
    return response.status(400).json({
      error: 'EMAIL_AND_PASSWORD_REQUIRED'
    });
  }

  try {
    const authResponse = await fetch(
      `${supabaseUrl}/auth/v1/token?grant_type=password`,
      {
        method: 'POST',
        headers: {
          apikey: publishableKey,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          email: body.email.trim(),
          password: body.password
        })
      }
    );

    const data = await authResponse.json();

    if (!authResponse.ok) {
      return response.status(401).json({
        error: 'LOGIN_FAILED'
      });
    }

    return response.status(200).json({
      session: {
        access_token: data.access_token,
        refresh_token: data.refresh_token,
        expires_in: data.expires_in,
        expires_at: data.expires_at,
        token_type: data.token_type,
        user: data.user
      }
    });
  } catch {
    return response.status(502).json({
      error: 'AUTH_SERVICE_UNAVAILABLE'
    });
  }
}