
const WINDOW_MS = 10 * 60 * 1000;
const READ_THRESHOLD = 120;

const ALLOWED_METHODS = new Set([
  'GET', 'POST', 'PUT', 'PATCH', 'DELETE',
]);

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
  return typeof value === 'string' && value.trim().length > 0
    ? value.trim()
    : null;
}

function readNetwork(event) {
  const network =
    event.signals?.network ??
    event.network ??
    event.context?.network ??
    event.request?.network;

  if (network === null || network === undefined) {
    return false;
  }

  if (typeof network === 'boolean') {
    return network;
  }

  if (typeof network === 'string') {
    return UNUSUAL_NETWORK_VALUES.has(
      network.trim().toLowerCase(),
    );
  }

  if (typeof network === 'object') {
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
          '',
        ).toLowerCase(),
      )
    );
  }

  return false;
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

function readEvent(event) {
  if (!event || typeof event !== 'object' || Array.isArray(event)) {
    return null;
  }

  const at = event.at;
  const method = event.method;
  const subject = event.identity?.sub;

  if (
    typeof at !== 'string' ||
    !Number.isFinite(Date.parse(at)) ||
    typeof method !== 'string' ||
    !ALLOWED_METHODS.has(method) ||
    typeof subject !== 'string' ||
    subject.length === 0
  ) {
    return null;
  }

  return {
    timestamp: Date.parse(at),
    method,
    subject,
    deviceId: readDeviceId(event),
    unusualNetwork: readNetwork(event),
  };
}

export function detect(events) {
  if (!Array.isArray(events)) {
    throw new TypeError('invalid_detection_events');
  }

  const readsByDevice = new Map();

  for (const rawEvent of events) {
    const event = readEvent(rawEvent);

    if (!event || event.method !== 'GET' || !event.deviceId) {
      continue;
    }

    const key = JSON.stringify([
      event.subject,
      event.deviceId,
    ]);

    const current = readsByDevice.get(key) ?? [];
    current.push(event);
    readsByDevice.set(key, current);
  }

  for (const reads of readsByDevice.values()) {
    reads.sort((a, b) => a.timestamp - b.timestamp);

    let start = 0;
    let unusualCount = 0;

    for (let end = 0; end < reads.length; end += 1) {
      if (reads[end].unusualNetwork) {
        unusualCount += 1;
      }

      while (
        reads[end].timestamp - reads[start].timestamp >= WINDOW_MS
      ) {
        if (reads[start].unusualNetwork) {
          unusualCount -= 1;
        }
        start += 1;
      }

      const count = end - start + 1;

      if (count > READ_THRESHOLD && unusualCount > 0) {
        return {
          action: 'propose_revocation',
          reasonCode: 'compound_network_burst',
          subject: reads[end].subject,
          deviceId: reads[end].deviceId,
        };
      }
    }
  }

  return { action: 'observe' };
}
