
import { verifyDeviceRequest } from './verify-device-request.mjs';

export async function authorizeDevice({
  request,
  supabase,
  login,
  rawBody = ''
}) {
  if (!login || login.kind !== 'student') {
    return { ok: false, reason: 'DEVICE_AUTH_REQUIRED' };
  }

  const deviceId = request.headers['x-device-id'];
  const timestamp = request.headers['x-device-timestamp'];
  const nonce = request.headers['x-device-nonce'];
  const signature = request.headers['x-device-signature'];

  if (
    typeof deviceId !== 'string' ||
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(deviceId)
  ) {
    return { ok: false, reason: 'DEVICE_ID_MISSING' };
  }

  const { data: device, error: deviceError } = await supabase
    .from('stage11_devices')
    .select('id, owner_id, public_key_jwk, status')
    .eq('id', deviceId)
    .eq('owner_id', login.userId)
    .maybeSingle();

  if (deviceError) {
    return { ok: false, reason: 'DEVICE_LOOKUP_FAILED' };
  }

  if (!device || device.status !== 'approved') {
    return { ok: false, reason: 'DEVICE_NOT_APPROVED' };
  }

  let path;

  try {
    const url = new URL(request.url, 'https://localhost');
    path = url.pathname + url.search;
  } catch {
    return { ok: false, reason: 'INVALID_REQUEST_PATH' };
  }

  const valid = verifyDeviceRequest({
    method: request.method,
    path,
    rawBody,
    timestamp,
    nonce,
    signature,
    publicKeyJwk: device.public_key_jwk
  });

  if (!valid) {
    return { ok: false, reason: 'INVALID_DEVICE_SIGNATURE' };
  }

  const { error: nonceError } = await supabase
    .from('stage11_device_nonces')
    .insert({
      device_id: device.id,
      nonce
    });

  if (nonceError) {
    return {
      ok: false,
      reason: nonceError.code === '23505'
        ? 'DEVICE_REQUEST_REPLAYED'
        : 'DEVICE_NONCE_SAVE_FAILED'
    };
  }

  return { ok: true, deviceId: device.id };
}
