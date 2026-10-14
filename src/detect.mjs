
const WINDOW_MS = 10 * 60 * 1000;
const READ_THRESHOLD = 120;

function nonEmptyString(value) {
  return typeof value === 'string' && value.trim()
    ? value.trim()
    : null;
}

function readDeviceId(event) {
  return (
    nonEmptyString(event.deviceId) ??
    nonEmptyString(event.device?.id) ??
    nonEmptyString(event.identity?.deviceId) ??
    nonEmptyString(event.context?.deviceId) ??
    nonEmptyString(event.request?.deviceId)
  );
}

function parseEvent(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    return null;
  }

  const at = raw.at ?? raw.timestamp;

  const subject =
    raw.identity?.sub ??
    raw.subjectId ??
    raw.subject ??
    raw.pseudonym ??
    raw.userId ??
    raw.user?.id;

  const method =
    raw.method ??
    raw.request?.method ??
    raw.requestType ??
    raw.kind;

  if (
    typeof at !== 'string' ||
    !Number.isFinite(Date.parse(at)) ||
    typeof subject !== 'string' ||
    !subject.trim()
  ) {
    return null;
  }

  return {
    timestamp: Date.parse(at),
    subject: subject.trim(),
    method: typeof method === 'string'
      ? method.toUpperCase()
      : null,
    deviceId: readDeviceId(raw),
    network:
      nonEmptyString(raw.network) ??
      nonEmptyString(raw.context?.network)
  };
}

export function detect(events) {
  if (!Array.isArray(events)) {
    throw new TypeError('invalid_detection_events');
  }

  const bySubject = new Map();

  for (const raw of events) {
    const event = parseEvent(raw);
    if (!event) continue;

    const group = bySubject.get(event.subject) ?? [];
    group.push(event);
    bySubject.set(event.subject, group);
  }

  for (const [subject, subjectEvents] of bySubject) {
    subjectEvents.sort(
      (a, b) => a.timestamp - b.timestamp
    );

    const reads = subjectEvents.filter(
      event => event.method === 'GET'
    );

    const networkSignals = subjectEvents.filter(
      event =>
        event.network === 'unusual' &&
        event.deviceId !== null
    );

    for (let end = 0, start = 0; end < reads.length; end++) {
      while (
        start <= end &&
        reads[end].timestamp - reads[start].timestamp >= WINDOW_MS
      ) {
        start++;
      }

      if (end - start + 1 <= READ_THRESHOLD) {
        continue;
      }

      const firstRead = reads[start].timestamp;
      const lastRead = reads[end].timestamp;

      // GET 요청 전후의 10분 범위에서 같은 사용자의
      // 이상 네트워크 신호와 기기 식별자를 확인한다.
      const relatedSignals = networkSignals.filter(
        event =>
          event.timestamp >= lastRead - WINDOW_MS &&
          event.timestamp <= lastRead
      );

      const devices = new Set(
        relatedSignals.map(event => event.deviceId)
      );

      // 조회량만으로는 회수를 제안하지 않는다.
      if (
        relatedSignals.length === 0 ||
        devices.size !== 1
      ) {
        continue;
      }

      const deviceId = [...devices][0];

      // 신호가 조회 폭주 시간대와 연관되어 있는지 확인한다.
      const relatedToBurst = relatedSignals.some(
        event =>
          event.timestamp >= firstRead - WINDOW_MS &&
          event.timestamp <= lastRead &&
          event.deviceId === deviceId
      );

      if (!relatedToBurst) {
        continue;
      }

      return {
        action: 'propose_revocation',
        reasonCode: 'compound_network_burst',
        subject,
        deviceId
      };
    }
  }

  return { action: 'observe' };
}
