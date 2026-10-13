import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFileSync } from 'node:fs';

import { decide } from '../src/decider.mjs';
import {
  createResourceId,
  parseResourceId,
} from '../src/resource-id.mjs';

const UUID = '550e8400-e29b-41d4-a716-446655440000';

const baseRequest = {
  schema: 'aleph.decision.v1',
  requestId: 'stage8-local-test',
  deviceRegistered: true,
  service: 'notes',
  method: 'GET',
  path: '/notes/demo',
  route: 'GET /notes/:id',
  signals: {
    source: 'none',
  },
};

function makeRequest(changes = {}) {
  return {
    ...baseRequest,
    ...changes,
  };
}

test('메모와 강사 공지의 자원 ID를 구분한다', () => {
  const note = createResourceId('notes', UUID);
  const announcement = createResourceId('announcements', UUID);

  assert.notEqual(note, announcement);

  assert.deepEqual(parseResourceId(note), {
    type: 'notes',
    id: UUID,
  });

  assert.deepEqual(parseResourceId(announcement), {
    type: 'announcements',
    id: UUID,
  });

  assert.equal(parseResourceId(`unknown/${UUID}`), null);
  assert.equal(parseResourceId(`notes/${UUID}/export`), null);
});

test('등록된 기기의 정상 메모 조회를 허용한다', async () => {
  const result = await decide(makeRequest());

  assert.equal(result.decision, 'allow');
});

test('미등록 기기의 접근을 거부한다', async () => {
  const result = await decide(
    makeRequest({
      deviceRegistered: false,
    })
  );

  assert.equal(result.decision, 'deny');
  assert.equal(result.reasonCode, 'device_not_registered');
});

test('강사 공지 수정 요청을 거부한다', async () => {
  const result = await decide(
    makeRequest({
      service: 'announcements',
      method: 'PUT',
      path: '/announcements/demo',
      route: 'PUT /announcements/:id',
    })
  );

  assert.equal(result.decision, 'deny');
});

test('강사 공지 조회 경로를 구분한다', async () => {
  const result = await decide(
    makeRequest({
      service: 'announcements',
      method: 'GET',
      path: '/announcements/demo',
      route: 'GET /announcements/:id',
    })
  );

  assert.equal(result.decision, 'allow');
});

test('메모 export 우회 경로를 거부한다', async () => {
  const result = await decide(
    makeRequest({
      path: '/notes/demo/export',
    })
  );

  assert.equal(result.decision, 'deny');
});

test('알 수 없는 경로를 기본 거부한다', async () => {
  const result = await decide(
    makeRequest({
      path: '/unknown',
    })
  );

  assert.equal(result.decision, 'deny');
});

test('쿼리 문자열로 수정 권한을 얻을 수 없다', async () => {
  const result = await decide(
    makeRequest({
      service: 'announcements',
      method: 'PUT',
      path: '/announcements/demo',
      route: 'PUT /announcements/:id',
      queryLength: 11,
    })
  );

  assert.equal(result.decision, 'deny');
});

test('메모 조회 수정 삭제에 소유자 조건이 유지된다', () => {
  const source = readFileSync(
    new URL('../api/notes/[id].js', import.meta.url),
    'utf8'
  );

  for (const method of ['GET', 'PUT', 'DELETE']) {
        const start = method === 'DELETE'
      ? source.indexOf('    .delete()')
      : source.indexOf(`request.method === '${method}'`);

    assert.notEqual(
      start,
      -1,
      `${method} 처리 구간이 없습니다`
    );

    const section =
      method === 'GET'
        ? source.slice(start, source.indexOf("request.method === 'PUT'", start))
        : method === 'PUT'
          ? source.slice(start, source.indexOf("  const { data, error } = await supabase\n    .from('notes')\n    .delete()", start))
          : source.slice(source.indexOf("    .delete()", source.indexOf("request.method === 'PUT'")));

    assert.match(
      section,
      /\.eq\('owner_id',\s*login\.userId\)/,
      `${method}에서 소유자 조건이 필요합니다`
    );
  }
});

test('메모 생성 시 인증된 사용자를 소유자로 지정한다', () => {
  const source = readFileSync(
    new URL('../api/notes.js', import.meta.url),
    'utf8'
  );

  assert.match(source, /owner_id:\s*login\.userId/);
  assert.match(source, /if\s*\(error\)/);
  assert.match(source, /response\.status\(201\)/);
});

test('8단계: 다른 사용자 소유 메모 조회를 거부한다', async () => {
  const request = {
    ...baseRequest,
    requestId: 'stage8-other-owner-test',
    subjectId: 'user-a',
    resourceOwnerId: 'user-b',
    deviceRegistered: true,
    method: 'GET',
    path: '/notes/demo',
    route: 'GET /notes/:id'
  };

  const result = await decide(request);

  assert.equal(
    result.decision,
    'deny',
    '다른 사용자 소유 메모는 조회할 수 없어야 한다'
  );
});