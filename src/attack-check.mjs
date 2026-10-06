// The student changes this check as each stage adds an attack to the same app.
// Never return tokens, private keys, real names, or note bodies.
export async function runAttackChecks(config) {
  if (config.step !== 4) {
    throw new Error(
      '3단계 공격 점검에 맞게 aleph.config.json의 step을 확인해 주세요.'
    );
  }

  let app;

  try {
    app = new URL(config.publicAppUrl);
  } catch {
    throw new Error(
      'aleph.config.json에 실제 배포 주소를 넣어 주세요.'
    );
  }

  if (
    app.protocol !== 'https:'
    || app.username
    || app.password
    || app.search
    || app.hash
    || app.pathname !== '/'
    || app.hostname.endsWith('.example')
  ) {
    throw new Error(
      'aleph.config.json에 실제 배포 주소를 넣어 주세요.'
    );
  }

  if (
    typeof config.sampleMarker !== 'string'
    || !config.sampleMarker
  ) {
    throw new Error(
      '가상 메모 확인 표시를 넣어 주세요.'
    );
  }

  const staticResponse = await fetch(
    new URL('/data.json', app),
    {
      redirect: 'error',
      signal: AbortSignal.timeout(10000),
    }
  );

  let staticExposed = false;

  if (staticResponse.ok) {
    try {
      const data = await staticResponse.json();

      staticExposed =
        data?.sampleMarker === config.sampleMarker
        && Array.isArray(data.notes)
        && data.notes.length > 0;
    } catch {
      // A non-JSON response does not prove that note data is exposed.
    }
  }

  const apiResponse = await fetch(
    new URL('/api/notes', app),
    {
      method: 'GET',
      redirect: 'error',
      signal: AbortSignal.timeout(10000),
      headers: {
        Accept: 'application/json'
      }
    }
  );

  const anonymousApiDenied =
    apiResponse.status === 401
    || apiResponse.status === 403;

  return [
    {
      attackId: 'anonymous_static_note_read',
      expected:
        '비로그인 요청으로 공개 data.json에서 가상 메모 본문을 읽을 수 없어야 함',
      observed: staticExposed
        ? '공개 data.json에 가상 메모가 남아 있음'
        : `공개 data.json에서 가상 메모가 확인되지 않음 (HTTP ${staticResponse.status})`,
    },
    {
      attackId: 'anonymous_notes_api_read',
      expected:
        '인증 정보가 없는 GET /api/notes 요청은 401 또는 403으로 거부되어야 함',
      observed: anonymousApiDenied
        ? `비로그인 자료 API 접근이 거부됨 (HTTP ${apiResponse.status})`
        : `비로그인 자료 API 접근이 거부되지 않음 (HTTP ${apiResponse.status})`,
    },
  ];
}