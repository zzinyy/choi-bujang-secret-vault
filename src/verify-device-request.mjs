import { createHash } from 'node:crypto';
import { verifyDeviceSignature } from './verify-device.mjs';

export function createDeviceSigningMessage({
  method,
  path,
  body,
  timestamp,
  nonce
}) {
  const bodyHash = createHash('sha256')
    .update(body)
    .digest('hex');

  return [
    method,
    path,
    bodyHash,
    timestamp,
    nonce
  ].join('\n');
}

export function verifyDeviceRequest({
  method,
  path,
  rawBody,
  timestamp,
  nonce,
  signature,
  publicKeyJwk,
  now = Date.now()
}) {
  if (
    typeof method !== 'string' ||
    typeof path !== 'string' ||
    typeof rawBody !== 'string' ||
    typeof timestamp !== 'string' ||
    typeof nonce !== 'string' ||
    typeof signature !== 'string' ||
    !/^[A-Za-z0-9_-]{16,128}$/.test(nonce)
  ) {
    return false;
  }

  const signedAt = Number(timestamp);

  if (
    !Number.isSafeInteger(signedAt) ||
    Math.abs(now - signedAt) > 5 * 60 * 1000
  ) {
    return false;
  }

  const message = createDeviceSigningMessage({
    method,
    path,
    body: rawBody,
    timestamp,
    nonce
  });

  return verifyDeviceSignature({
    publicKeyJwk,
    signature,
    message
  });
}