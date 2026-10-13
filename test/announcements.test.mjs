
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFileSync } from 'node:fs';
import { verifyInstructor } from '../src/verify-instructor.mjs';

const API_SOURCE = readFileSync(
  new URL('../api/announcements.js', import.meta.url),
  'utf8'
);

const INSTRUCTOR_ID = '550e8400-e29b-41d4-a716-446655440000';
const STUDENT_ID = '550e8400-e29b-41d4-a716-446655440001';

function mockSupabase(memberId = null) {
  return {
    from(table) {
      assert.equal(table, 'instructor_roles');

      return {
        select(column) {
          assert.equal(column, 'user_id');

          return {
            eq(field, value) {
              assert.equal(field, 'user_id');

              return {
                async maybeSingle() {
                  return {
                    data:
                      memberId === value
                        ? { user_id: memberId }
                        : null,
                    error: null
                  };
                }
              };
            }
          };
        }
      };
    }
  };
}

test('공지 API는 서버 로그인 검증 함수를 사용한다', () => {
  assert.match(
    API_SOURCE,
    /createLoginVerifier/
  );

  assert.match(
    API_SOURCE,
    /request\.headers\.authorization/
  );
});

test('공지 생성 전에 강사 권한을 검증한다', () => {
  assert.match(
    API_SOURCE,
    /verifyInstructor\(supabase,\s*login\)/
  );

  assert.match(
    API_SOURCE,
    /INSTRUCTOR_REQUIRED/
  );
});

test('일반 학생은 강사 권한을 얻지 못한다', async () => {
  const supabase = mockSupabase(INSTRUCTOR_ID);

  const allowed = await verifyInstructor(supabase, {
    kind: 'student',
    userId: STUDENT_ID
  });

  assert.equal(allowed, false);
});

test('등록된 강사는 권한 검증을 통과한다', async () => {
  const supabase = mockSupabase(INSTRUCTOR_ID);

  const allowed = await verifyInstructor(supabase, {
    kind: 'student',
    userId: INSTRUCTOR_ID
  });

  assert.equal(allowed, true);
});

test('요청 본문의 강사 역할 조작은 무시한다', async () => {
  const supabase = mockSupabase();

  const allowed = await verifyInstructor(supabase, {
    kind: 'student',
    userId: STUDENT_ID,
    role: 'instructor',
    isInstructor: true
  });

  assert.equal(allowed, false);
});

test('공지 작성자는 인증된 사용자 ID로 지정한다', () => {
  assert.match(
    API_SOURCE,
    /created_by:\s*login\.userId/
  );

  assert.doesNotMatch(
    API_SOURCE,
    /created_by:\s*body\.created_by/
  );
});

test('공지 생성은 강사 권한 확인 이후에 수행한다', () => {
  const permissionCheck = API_SOURCE.indexOf(
    'verifyInstructor(supabase, login)'
  );

const insertOperation = API_SOURCE.search(
  /\.from\(['"]announcements['"]\)\s*\.insert\(/
);

  assert.ok(permissionCheck >= 0);
  assert.ok(insertOperation >= 0);
  assert.ok(permissionCheck < insertOperation);
});

test('공지 API는 허용하지 않은 HTTP 메서드를 거부한다', () => {
  assert.match(
    API_SOURCE,
    /METHOD_NOT_ALLOWED/
  );

  assert.match(
    API_SOURCE,
    /status\(405\)/
  );
});

test('공지 제목과 내용의 빈 문자열을 거부한다', () => {
  assert.match(
    API_SOURCE,
    /body\.title\.trim\(\)/
  );

  assert.match(
    API_SOURCE,
    /body\.body\.trim\(\)/
  );

  assert.match(
    API_SOURCE,
    /INVALID_ANNOUNCEMENT/
  );
});

test('공지 조회 응답에 작성자 권한 정보를 노출하지 않는다', () => {
  assert.match(
    API_SOURCE,
    /select\('id, title, content, created_at'\)/
  );

  assert.doesNotMatch(
    API_SOURCE,
    /select\('.*created_by.*'\)/
  );
});
