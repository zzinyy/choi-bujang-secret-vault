
let deviceKeyPair = null;
let deviceId = null;

function toBase64Url(bytes) {
  let binary = '';

  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

async function sha256Hex(value) {
  const bytes = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest('SHA-256', bytes);

  return Array.from(new Uint8Array(digest))
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('');
}

export async function createDeviceKey() {
  deviceKeyPair = await crypto.subtle.generateKey(
    {
      name: 'ECDSA',
      namedCurve: 'P-256'
    },
    false,
    ['sign', 'verify']
  );

  deviceId = null;

  return crypto.subtle.exportKey(
    'jwk',
    deviceKeyPair.publicKey
  );
}

export function setDeviceId(id) {
  if (
    typeof id !== 'string' ||
    !/^[0-9a-f-]{36}$/i.test(id)
  ) {
    throw new Error('INVALID_DEVICE_ID');
  }

  deviceId = id;
}

export function clearDevice() {
  deviceKeyPair = null;
  deviceId = null;
}

export async function createDeviceHeaders(method, path, body = '') {
  if (!deviceKeyPair?.privateKey || !deviceId) {
    throw new Error('DEVICE_NOT_REGISTERED');
  }

  const timestamp = String(Date.now());
  const nonce = toBase64Url(crypto.getRandomValues(new Uint8Array(16)));
  const bodyHash = await sha256Hex(body);

  const message = [
    method,
    path,
    bodyHash,
    timestamp,
    nonce
  ].join('\n');

  const signature = await crypto.subtle.sign(
    {
      name: 'ECDSA',
      hash: 'SHA-256'
    },
    deviceKeyPair.privateKey,
    new TextEncoder().encode(message)
  );

  return {
    'X-Device-Id': deviceId,
    'X-Device-Timestamp': timestamp,
    'X-Device-Nonce': nonce,
    'X-Device-Signature': toBase64Url(new Uint8Array(signature))
  };
}
