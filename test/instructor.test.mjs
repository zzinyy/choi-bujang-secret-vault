
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { verifyInstructor } from '../src/verify-instructor.mjs';

const INSTRUCTOR_ID = '550e8400-e29b-41d4-a716-446655440000';
const STUDENT_ID = '550e8400-e29b-41d4-a716-446655440001';

// Simulate the server-side Supabase client.
// No actual database connection is made.
function mockSupabase({ memberId = null, error = null } = {}) {
  return {
    from(table) {
      assert.equal(table, 'instructor_roles');

      return {
        select(columns) {
          assert.equal(columns, 'user_id');

          return {
            eq(column, value) {
              assert.equal(column, 'user_id');

              return {
                async maybeSingle() {
                  return {
                    data:
                      memberId === value
                        ? { user_id: memberId }
                        : null,
                    error,
                  };
                },
              };
            },
          };
        },
      };
    },
  };
}

test('등록된 강사 계정을 허용한다', async () => {
  const supabase = mockSupabase({
    memberId: INSTRUCTOR_ID,
  });

  const result = await verifyInstructor(supabase, {
    kind: 'student',
    userId: INSTRUCTOR_ID,
  });

  assert.equal(result, true);
});

test('일반 학생 계정을 거부한다', async () => {
  const supabase = mockSupabase({
    memberId: INSTRUCTOR_ID,
  });

  const result = await verifyInstructor(supabase, {
    kind: 'student',
    userId: STUDENT_ID,
  });

  assert.equal(result, false);
});

test('심판 테스트 계정을 강사로 인정하지 않는다', async () => {
  const supabase = mockSupabase({
    memberId: INSTRUCTOR_ID,
  });

  const result = await verifyInstructor(supabase, {
    kind: 'judge',
    userId: INSTRUCTOR_ID,
  });

  assert.equal(result, false);
});

test('로그인 정보가 없으면 거부한다', async () => {
  const supabase = mockSupabase({
    memberId: INSTRUCTOR_ID,
  });

  assert.equal(
    await verifyInstructor(supabase, null),
    false
  );
});

test('권한 테이블 조회 오류가 발생하면 거부한다', async () => {
  const supabase = mockSupabase({
    error: { message: 'Database unavailable' },
  });

  const result = await verifyInstructor(supabase, {
    kind: 'student',
    userId: INSTRUCTOR_ID,
  });

  assert.equal(result, false);
});

test('요청 본문의 role 값으로 강사 권한을 얻지 못한다', async () => {
  const supabase = mockSupabase();

  const result = await verifyInstructor(supabase, {
    kind: 'student',
    userId: STUDENT_ID,
    role: 'instructor',
    isInstructor: true,
  });

  assert.equal(result, false);
});

test('잘못된 사용자 ID는 거부한다', async () => {
  const supabase = mockSupabase();

  const result = await verifyInstructor(supabase, {
    kind: 'student',
    userId: 'invalid-user-id',
  });

  assert.equal(result, false);
});

test('Supabase 클라이언트가 없으면 거부한다', async () => {
  const result = await verifyInstructor(null, {
    kind: 'student',
    userId: INSTRUCTOR_ID,
  });

  assert.equal(result, false);
});
