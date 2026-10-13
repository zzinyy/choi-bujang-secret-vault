export const RULE_IDS = Object.freeze([
  'device_registered',
  'step_up_required',
]);

export async function decide(request) {
  const response = (decision, reasonCode, ruleId) => ({
    schema: 'aleph.decision.v1',
    requestId: request?.requestId,
    decision,
    reasonCode,
    ruleIds: [ruleId],
  });

  // 6단계: 등록되지 않은 기기는 접근 거부
  if (request?.deviceRegistered !== true) {
    return response('deny', 'device_not_registered', 'device_registered');
  }

  // 7단계: 엔진이 제공한 가상 테스트 신호만 평가
  // 출처가 없거나 불확실하면 정상 신호로 만들어 내지 않음
  const signals = request?.signals;
  const trustedFixture = signals?.source === 'judge_fixture';

  const unusualTime =
    Number.isInteger(signals?.hour) &&
    (signals.hour < 6 || signals.hour >= 23);

  const unfamiliarNetwork = signals?.network === 'unusual';

  const recentRiskActivity =
    Array.isArray(request?.recentEvents) &&
    request.recentEvents.some(
      (event) =>
        event?.kind === 'risk_signal' &&
        Number.isFinite(event.count) &&
        event.count >= 10 &&
        Number.isFinite(event.ageSeconds) &&
        event.ageSeconds >= 0 &&
        event.ageSeconds <= 300
    );

  const compoundAnomaly =
    trustedFixture &&
    unusualTime &&
    unfamiliarNetwork &&
    recentRiskActivity;

  if (compoundAnomaly) {
    // 엔진이 확인한 최근 추가 인증만 인정
    const recentlyVerified =
      request?.stepUp?.verified === true &&
      Number.isFinite(request.stepUp.authAgeSeconds) &&
      request.stepUp.authAgeSeconds >= 0 &&
      request.stepUp.authAgeSeconds <= 300;

    if (!recentlyVerified) {
      return response('step_up', 'step_up_required', 'step_up_required');
    }
  }

  return response('allow', 'approved', 'device_registered');
}