const MAX_BODY_BYTES = 1024 * 1024;

export async function readRequestBody(request) {
  const chunks = [];
  let size = 0;

  for await (const chunk of request) {
    const bytes = Buffer.isBuffer(chunk)
      ? chunk
      : Buffer.from(chunk);

    size += bytes.length;

    if (size > MAX_BODY_BYTES) {
      const error = new Error('REQUEST_BODY_TOO_LARGE');
      error.statusCode = 413;
      throw error;
    }

    chunks.push(bytes);
  }

  const rawBody = Buffer.concat(chunks).toString('utf8');

  if (!rawBody) {
    return {
      rawBody: '',
      body: {}
    };
  }

  let body;

  try {
    body = JSON.parse(rawBody);
  } catch {
    const error = new Error('INVALID_JSON');
    error.statusCode = 400;
    throw error;
  }

  if (
    !body ||
    typeof body !== 'object' ||
    Array.isArray(body)
  ) {
    const error = new Error('INVALID_JSON_BODY');
    error.statusCode = 400;
    throw error;
  }

  return {
    rawBody,
    body
  };
}