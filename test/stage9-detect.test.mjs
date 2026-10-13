
import test from 'node:test';
import assert from 'node:assert/strict';

import { detect } from '../src/detect.mjs';

const START = Date.UTC(2026, 9, 1, 0, 0, 0);
const subject = 'learner_fixture';
const deviceId = 'aaaaaaaaaaaaaaaa';

function reads(count, extra = {}, intervalSeconds = 2) {
  return Array.from({ length: count }, (_, index) => ({
    at: new Date(START + index * intervalSeconds * 1000).toISOString(),
    method: 'GET',
    identity: { sub: subject },
    ...extra,
  }));
}

test('정상 조회는 observe로 유지한다', () => {
  assert.deepEqual(detect(reads(30, {
    network: 'usual',
    deviceId,
  })), { action: 'observe' });
});

test('다량 조회와 낯선 네트워크가 함께 있으면 회수 제안을 낸다', () => {
  assert.deepEqual(detect(reads(121, {
    network: 'unusual',
    deviceId,
  })), {
    action: 'propose_revocation',
    reasonCode: 'compound_network_burst',
    subject,
    deviceId,
  });
});

test('다량 조회만으로 회수 제안을 내지 않는다', () => {
  assert.deepEqual(detect(reads(121)), { action: 'observe' });
});

test('기기 식별자가 없으면 회수 제안을 내지 않는다', () => {
  assert.deepEqual(detect(reads(121, {
    network: 'unusual',
  })), { action: 'observe' });
});

test('지역 정보만으로는 회수 제안을 내지 않는다', () => {
  assert.deepEqual(detect(reads(121, {
    region: 'foreign',
    deviceId,
  })), { action: 'observe' });
});

test('다른 사용자의 조회는 합산하지 않는다', () => {
  const events = [
    ...reads(100, { network: 'unusual', deviceId }),
    ...reads(100, {
      network: 'unusual',
      deviceId,
      identity: { sub: 'other_fixture' },
    }),
  ];

  assert.deepEqual(detect(events), { action: 'observe' });
});
