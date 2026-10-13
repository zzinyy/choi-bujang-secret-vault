
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFileSync } from 'node:fs';

const API_SOURCE = readFileSync(
  new URL('../api/announcements/[id].js', import.meta.url),
  'utf8'
);

test('개별 공지 API는 로그인 검증을 사용한다', () => {
  assert.match(API_SOURCE, /createLoginVerifier/);
  assert.match(API_SOURCE, /getVerifier/);
  assert.match(API_SOURCE, /UNAUTHORIZED/);
});

test('개별 공지 API는 GET PUT DELETE만 허용한다', () => {
  assert.match(
    API_SOURCE,
    /\[['"]GET['"],\s*['"]PUT['"],\s*['"]DELETE['"]\]/
  );
  assert.match(API_SOURCE, /METHOD_NOT_ALLOWED/);
});

test('개별 공지 ID를 UUID 형식으로 검증한다', () => {
  assert.match(API_SOURCE, /UUID/);
  assert.match(API_SOURCE, /ANNOUNCEMENT_NOT_FOUND/);
});

test('공지 조회는 announcements 테이블에서 ID로 조회한다', () => {
  assert.match(API_SOURCE, /\.from\(['"]announcements['"]\)/);
  assert.match(API_SOURCE, /\.select\(/);
  assert.match(API_SOURCE, /\.eq\(['"]id['"],\s*id\)/);
});

test('공지 수정과 삭제 전에 강사 권한을 확인한다', () => {
  const permissionCheck = API_SOURCE.indexOf(
    'verifyInstructor(supabase, login)'
  );
  const updatePosition = API_SOURCE.indexOf(".update(");
  const deletePosition = API_SOURCE.indexOf(".delete()");

  assert.notEqual(permissionCheck, -1, '강사 권한 확인 코드가 없습니다');
  assert.notEqual(updatePosition, -1, '수정 코드가 없습니다');
  assert.notEqual(deletePosition, -1, '삭제 코드가 없습니다');
  assert.ok(permissionCheck < updatePosition);
  assert.ok(permissionCheck < deletePosition);
});

test('강사 권한이 없으면 수정과 삭제를 거부한다', () => {
  assert.match(API_SOURCE, /INSTRUCTOR_REQUIRED/);
  assert.match(API_SOURCE, /status\(403\)/);
});

test('요청 본문의 role을 권한 판단에 사용하지 않는다', () => {
  assert.doesNotMatch(
    API_SOURCE,
    /body\.role|request\.body\.role/
  );
});

test('공지 수정 시 제목과 내용을 검증한다', () => {
  assert.match(API_SOURCE, /INVALID_ANNOUNCEMENT/);
  assert.match(API_SOURCE, /body\.title\.trim\(\)/);
  assert.match(API_SOURCE, /body\.body\.trim\(\)/);
});

test('조회 수정 삭제 실패 시 오류를 처리한다', () => {
  assert.match(API_SOURCE, /ANNOUNCEMENT_READ_FAILED/);
  assert.match(API_SOURCE, /ANNOUNCEMENT_UPDATE_FAILED/);
  assert.match(API_SOURCE, /ANNOUNCEMENT_DELETE_FAILED/);
});

test('응답에 캐시 방지 헤더를 설정한다', () => {
  assert.match(API_SOURCE, /Cache-Control/);
  assert.match(API_SOURCE, /no-store/);
});
