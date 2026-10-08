
const PATTERN_NAMES = [
  'rapid-failures-single-ip',
  'password-spraying',
  'repeated-target-account'
];

function patternName(name) {
  return PATTERN_NAMES.includes(name) ? name : name;
}


function result(confidence, reason) {
  const action =
    confidence >= 0.85 ? 'block' :
    confidence >= 0.5 ? 'alert' : 'record';

  return { action, confidence, reason };
}

// 외부 Jev 연결이 없는 경우 사용하는 보수적인 판단.
// 실제 Jev 응답을 받은 것으로 표시하지 않는다.
async function askJev(alert) {
  return null;
}

export async function decide(alert) {
  const description = String(alert?.rule?.description ?? '');
  const count = Number(alert?.data?.count ?? 0);
  const ip = alert?.data?.srcip;
  const account = alert?.data?.srcuser;

  // 로그인 성공 및 일반적인 사용자 활동
  const normalEvent =
    /로그인이 성공|로그아웃|비밀번호 변경이 성공|세션 유지|자료실 화면|로그인 상태가 유지/.test(description) ||
    /로그인 실패 1건 뒤에 성공/.test(description);

  if (normalEvent) {
    return result(0.05, 'normal-authentication-event');
  }


  // 여러 계정에 대한 반복적인 로그인 실패 탐지
  const accountList = alert?.data?.accounts;
  const accountCount = Array.isArray(accountList)
    ? accountList.length
    : typeof accountList === 'string'
      ? accountList.split(',').filter(Boolean).length
      : 0;

  const multiAccountAttack =
    Boolean(ip) &&
    Number(alert?.rule?.level ?? 0) >= 10 &&
    (
      (accountCount >= 5 &&
        /여러 계정에 같은 비밀번호/.test(description)) ||
      (count >= 15 &&
        /계정 20개|서로 다른 계정 15개/.test(description))
    );

  if (multiAccountAttack) {
    return result(
      0.9,
      patternName('password-spraying')
    );
  }

  // 동일 주소 또는 계정에서 발생한 명확한 대량 실패
  const strongAttack =
    count >= 30 &&
    Boolean(ip || account) &&
    /로그인 실패|비밀번호.*실패|같은 비밀번호 실패/.test(description);

  if (strongAttack) {
    return result(
      0.95,
      patternName('rapid-failures-single-ip')
    );
  }

  // 여러 계정에 같은 비밀번호를 대입한 정황
  // 경보 설명만으로 확정 차단하지 않는다.
  if (/여러 계정에 같은 비밀번호/.test(description)) {
    return result(
      0.7,
      patternName('password-spraying')
    );
  }

  // 나머지 로그인 실패는 우선 알림 대상으로 분류
  if (/실패|잠금|평소와 다른 주소/.test(description)) {
    try {
      const jev = await askJev(alert);

      if (
        jev &&
        typeof jev.confidence === 'number' &&
        Number.isFinite(jev.confidence) &&
        jev.confidence >= 0 &&
        jev.confidence <= 1
      ) {
        return result(
          jev.confidence,
          patternName('repeated-target-account')
        );
      }
    } catch {
      // Jev 응답 실패 시 알림으로 처리
    }

    return result(
      0.6,
      patternName('repeated-target-account')
    );
  }

  return result(0.1, 'normal-authentication-event');
}
