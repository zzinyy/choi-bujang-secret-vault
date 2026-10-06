// The student changes this check as each stage adds an attack to the same app.
// Never return tokens, private keys, real names, or note bodies.
export async function runAttackChecks(config) {
  if (config.step !== 2) {
    throw new Error('2단계의 공격 점검을 src/attack-check.mjs에 구현해 주세요.');
  }

  let app;

  try {
    app = new URL(config.publicAppUrl);
  } catch {
    throw new Error('aleph.config.json에 실제 배포 주소를 먼저 넣어 주세요.');
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
    throw new Error('aleph.config.json에 실제 배포 주소를 먼저 넣어 주세요.');
  }

  if (typeof config.sampleMarker !== 'string' || !config.sampleMarker) {
    throw new Error('가상 메모의 확인 표시를 넣어 주세요.');
  }

  const response = await fetch(new URL('/data.json', app), {
    redirect: 'error',
    signal: AbortSignal.timeout(10000),
  });

  let exposed = false;

  if (response.ok) {
    try {
      const data = await response.json();

      exposed =
        data?.sampleMarker === config.sampleMarker
        && Array.isArray(data.notes)
        && data.notes.length > 0;
    } catch {
      // A non-JSON response does not prove that note data is exposed.
    }
  }

  return [
    {
      attackId: 'anonymous_static_note_read',
      expected: '비로그인 요청으로 공개 data.json에서 가상 메모 본문을 읽을 수 없어야 함',
      observed: exposed
        ? '공개 data.json에 가상 메모가 남아 있음'
        : `공개 data.json에서 가상 메모가 확인되지 않음 (HTTP ${response.status})`,
    },
  ];
}