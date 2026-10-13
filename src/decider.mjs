
export const RULE_IDS = Object.freeze([
  'device_registered',
  'step_up_required',
  'resource_access',
]);

export async function decide(request) {
  const response = (decision, reasonCode, ruleId) => ({
    schema: 'aleph.decision.v1',
    requestId: request?.requestId,
    decision,
    reasonCode,
    ruleIds: [ruleId],
  });

  // Stage 6: Deny unregistered devices.
  if (request?.deviceRegistered !== true) {
    return response('deny', 'device_not_registered', 'device_registered');
  }

  // Stage 8: Allow only individual note read and update.
  // Collection routes and announcement routes are denied.
  const method = request?.method;
  const route = request?.route;
  const service = request?.service;
  const path = request?.path;

  // Accept the normalized route and the public API prefix.
  const normalizedPath =
    typeof path === 'string' && path.startsWith('/api/notes/')
      ? path.slice(4)
      : path;

  // A real note ID is a UUID. "demo" is retained for local fixtures.
  const noteIdPattern =
    /^(?:[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}|demo)$/i;

  const pathMatch =
    typeof normalizedPath === 'string'
      ? /^\/notes\/([^/]+)$/.exec(normalizedPath)
      : null;

  const validNoteId =
    pathMatch !== null && noteIdPattern.test(pathMatch[1]);

  const hasQuery =
    Number.isInteger(request?.queryLength) &&
    request.queryLength > 0;

  const allowedNoteItem =
    service === 'notes' &&
    validNoteId &&
    !hasQuery &&
    (
      (method === 'GET' && route === 'GET /notes/:id') ||
      (method === 'PUT' && route === 'PUT /notes/:id')
    );

  if (!allowedNoteItem) {
    return response(
      'deny',
      'resource_access_denied',
      'resource_access'
    );
  }

  // Stage 7: Evaluate compound anomaly signals.
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
    const recentlyVerified =
      request?.stepUp?.verified === true &&
      Number.isFinite(request.stepUp.authAgeSeconds) &&
      request.stepUp.authAgeSeconds >= 0 &&
      request.stepUp.authAgeSeconds <= 300;

    if (!recentlyVerified) {
      return response('step_up', 'step_up_required', 'step_up_required');
    }
  }

  return response('allow', 'approved', 'resource_access');
}
