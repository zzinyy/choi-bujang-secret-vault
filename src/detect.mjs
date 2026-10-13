
const WINDOW_MS = 10 * 60 * 1000;
const READ_THRESHOLD = 120;

const ALLOWED_METHODS = new Set([
  'GET',
  'POST',
  'PUT',
  'PATCH',
  'DELETE',
]);

function readEvent(event) {
  if (!event || typeof event !== 'object' || Array.isArray(event)) {
    return null;
  }

  const at = event.at;
  const method = event.method;
  const sub = event.identity?.sub;

  if (
    typeof at !== 'string' ||
    !Number.isFinite(Date.parse(at)) ||
    typeof method !== 'string' ||
    !ALLOWED_METHODS.has(method) ||
    typeof sub !== 'string' ||
    sub.length === 0
  ) {
    return null;
  }

  // 기존 사건 계약의 필드만 기본으로 읽습니다.
  // 추가 필드는 실제 입력에 존재할 때만 선택적으로 읽습니다.
  const network =
    typeof event.network === 'string'
      ? event.network
      : typeof event.signals?.network === 'string'
        ? event.signals.network
        : null;

  const deviceId =
    typeof event.deviceId === 'string'
      ? event.deviceId
      : null;

  return {
    at,
    timestamp: Date.parse(at),
    method,
    subject: sub,
    network,
    deviceId,
  };
}

export function detect(events) {
  if (!Array.isArray(events)) {
    throw new TypeError('invalid_detection_events');
  }

  const safeEvents = events
    .map(readEvent)
    .filter((event) => event !== null);

  const readsBySubject = new Map();

  for (const event of safeEvents) {
    if (event.method !== 'GET') continue;

    const current = readsBySubject.get(event.subject) ?? [];
    current.push(event);
    readsBySubject.set(event.subject, current);
  }

  for (const [subject, reads] of readsBySubject) {
    reads.sort((a, b) => a.timestamp - b.timestamp);

    for (let start = 0; start < reads.length; start += 1) {
      const first = reads[start];
      const windowReads = [];

      for (let index = start; index < reads.length; index += 1) {
        if (reads[index].timestamp - first.timestamp >= WINDOW_MS) {
          break;
        }

        windowReads.push(reads[index]);
      }

      if (windowReads.length <= READ_THRESHOLD) continue;

      // 네트워크 이상이 명시적으로 관측된 사건만 인정합니다.
      const unusualNetworkRead = windowReads.find(
        (event) => event.network === 'unusual',
      );

      if (!unusualNetworkRead) continue;

      // 회수 대상 기기 ID가 실제 입력에 없으면 제안하지 않습니다.
      if (!unusualNetworkRead.deviceId) continue;

      return {
        action: 'propose_revocation',
        reasonCode: 'compound_network_burst',
        subject,
        deviceId: unusualNetworkRead.deviceId,
      };
    }
  }

  return { action: 'observe' };
}
