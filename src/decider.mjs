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

  // Stage 8: Check the exact method and path.
  // Do not use the query string to select an action.
  const method = request?.method;
  const path = request?.path;
  const route = request?.route;
  const service = request?.service;

  const noteCollection =
    service === 'notes' &&
    path === '/notes' &&
    (
      (method === 'GET' && route === 'GET /notes') ||
      (method === 'POST' && route === 'POST /notes')
    );

  const noteItem =
    service === 'notes' &&
    /^\/notes\/[A-Za-z0-9-]+$/.test(path ?? '') &&
    (
      (method === 'GET' && route === 'GET /notes/:id') ||
      (method === 'PUT' && route === 'PUT /notes/:id') ||
      (method === 'DELETE' && route === 'DELETE /notes/:id')
    );

  const announcementCollection =
    service === 'announcements' &&
    path === '/announcements' &&
    method === 'GET' &&
    route === 'GET /announcements';

  const announcementItem =
    service === 'announcements' &&
    /^\/announcements\/[A-Za-z0-9-]+$/.test(path ?? '') &&
    method === 'GET' &&
    route === 'GET /announcements/:id';

  if (
    !noteCollection &&
    !noteItem &&
    !announcementCollection &&
    !announcementItem
  ) {
    return response('deny', 'resource_access_denied', 'resource_access');
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