import {
  createPublicKey,
  verify as verifySignature
} from 'node:crypto';

export function verifyDeviceSignature({
  publicKeyJwk,
  signature,
  message
}) {
  if (
    !publicKeyJwk ||
    publicKeyJwk.kty !== 'EC' ||
    publicKeyJwk.crv !== 'P-256' ||
    typeof signature !== 'string' ||
    typeof message !== 'string'
  ) {
    return false;
  }

  try {
    const publicKey = createPublicKey({
      key: publicKeyJwk,
      format: 'jwk'
    });

    const signatureBytes = Buffer.from(
      signature,
      'base64url'
    );

    if (signatureBytes.length !== 64) {
      return false;
    }

    return verifySignature(
      'sha256',
      Buffer.from(message, 'utf8'),
      {
        key: publicKey,
        dsaEncoding: 'ieee-p1363'
      },
      signatureBytes
    );
  } catch {
    return false;
  }
}