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

      const devices = new Set();
      for (let i = start; i <= end; i++) {
        if (reads[i].deviceId) devices.add(reads[i].deviceId);
      }

      const result = {
        action: 'propose_revocation',
        reasonCode: 'burst_read',
        subject,
      };

      if (devices.size === 1) {
        result.deviceId = [...devices][0];
      }

      return result;
    }
  }

  return { action: 'observe' };
}