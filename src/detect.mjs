
const WINDOW_MS = 10 * 60 * 1000;
const READ_THRESHOLD = 120;

const UNUSUAL_NETWORK_VALUES = new Set([
  'unusual',
  'suspicious',
  'unknown',
  'untrusted',
  'new',
  'foreign',
  'anomalous',
  'risky',
]);

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

function unusualNetwork(event) {
  const network =
    event.signals?.network ??
    event.network ??
    event.context?.network ??
    event.request?.network;

  if (typeof network === 'boolean') {
    return network;
  }

  if (typeof network === 'string') {
    return UNUSUAL_NETWORK_VALUES.has(
      network.trim().toLowerCase()
    );
  }

  if (network && typeof network === 'object') {
    return (
      network.unusual === true ||
      network.suspicious === true ||
      network.isUnusual === true ||
      network.isNew === true ||
      UNUSUAL_NETWORK_VALUES.has(
        String(
          network.status ??
          network.risk ??
          network.type ??
          ''
        ).trim().toLowerCase()
      )
    );
  }

  return false;
}

function parseEvent(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    return null;
  }

  const at = raw.at ?? raw.timestamp;
  const subject =
  raw.identity?.sub ??
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
    unusual: unusualNetwork(raw),
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

  for (const [subject, eventsForSubject] of bySubject) {
    eventsForSubject.sort(
      (a, b) => a.timestamp - b.timestamp
    );

    const reads = eventsForSubject.filter(
      event => event.method === 'GET'
    );

    for (
      let end = 0, start = 0;
      end < reads.length;
      end++
    ) {
      while (
        reads[end].timestamp - reads[start].timestamp >= WINDOW_MS
      ) {
        start++;
      }

      if (end - start + 1 <= READ_THRESHOLD) {
        continue;
      }

      const lastTime = reads[end].timestamp;

      // GET 요청이 121건 이상인 10분 구간 전체를 검사한다.
      // 첫 GET 직전에 발생한 네트워크 이상도 포함한다.
      const windowStart = lastTime - WINDOW_MS;

      const suspiciousDevices = new Set();

      for (const event of eventsForSubject) {
        if (
          event.timestamp > windowStart &&
          event.timestamp <= lastTime &&
          event.unusual &&
          event.deviceId
        ) {
          suspiciousDevices.add(event.deviceId);
        }
      }

      // 회수 제안은 식별 가능한 가상 기기 한 개에만 한정한다.
      if (suspiciousDevices.size === 1) {
        return {
          action: 'propose_revocation',
          reasonCode: 'compound_network_burst',
          subject,
          deviceId: [...suspiciousDevices][0],
        };
      }
    }
  }

  return { action: 'observe' };
}
