
export const RULE_IDS = Object.freeze([
  'starter.deny',
  'device_registered',
]);

export async function decide(request) {
  // 등록되지 않은 기기이거나 등록 여부가 없는 경우 거부
  if (request?.deviceRegistered !== true) {
    return {
      schema: 'aleph.decision.v1',
      requestId: request?.requestId,
      decision: 'deny',
      reasonCode: 'device_not_registered',
      ruleIds: ['device_registered'],
    };
  }

  // 등록된 기기는 이번 기기 등록 조건을 통과
  return {
    schema: 'aleph.decision.v1',
    requestId: request.requestId,
    decision: 'allow',
    reasonCode: 'approved',
    ruleIds: ['device_registered'],
  };
}
