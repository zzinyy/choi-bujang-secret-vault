
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { generateKeyPairSync, sign } from 'node:crypto';

import {
  createDeviceSigningMessage,
  verifyDeviceRequest
} from '../src/verify-device-request.mjs';

const { privateKey, publicKey } = generateKeyPairSync('ec', {
  namedCurve: 'prime256v1'
});

const request = {
  method: 'PUT',
  path: '/api/notes/123',
  rawBody: JSON.stringify({
    title: 'test',
    body: 'original'
  }),
  timestamp: String(Date.now()),
  nonce: 'testnonce1234567890',
  publicKeyJwk: publicKey.export({ format: 'jwk' })
};

const message = createDeviceSigningMessage({
  ...request,
  body: request.rawBody
});

const signature = sign(
  'sha256',
  Buffer.from(message),
  {
    key: privateKey,
    dsaEncoding: 'ieee-p1363'
  }
).toString('base64url');

test('정상 서명 요청은 허용한다', () => {
  assert.equal(
    verifyDeviceRequest({ ...request, signature }),
    true
  );
});

test('서명이 없으면 거부한다', () => {
  assert.equal(
    verifyDeviceRequest({ ...request, signature: '' }),
    false
  );
});

test('서명 후 요청 경로를 변경하면 거부한다', () => {
  assert.equal(
    verifyDeviceRequest({
      ...request,
      signature,
      path: '/api/notes/456'
    }),
    false
  );
});

test('서명 후 수정 본문을 변경하면 거부한다', () => {
  assert.equal(
    verifyDeviceRequest({
      ...request,
      signature,
      rawBody: JSON.stringify({
        title: 'test',
        body: 'changed'
      })
    }),
    false
  );
});
