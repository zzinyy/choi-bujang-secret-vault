
const PATTERNS = Object.freeze([
  {
    name: 'sql-injection',
    condition: 'SQL syntax or documented SQL attack marker',
    evidence: 'MITRE ATT&CK T1190'
  },
  {
    name: 'script-injection',
    condition: 'Script syntax or documented script attack marker',
    evidence: 'MITRE ATT&CK T1190'
  },
  {
    name: 'path-traversal',
    condition: 'Repeated parent directory traversal',
    evidence: 'MITRE ATT&CK T1190'
  }
]);

function makeResult(confidence, reason) {
  return {
    action: confidence >= 0.85
      ? 'block'
      : confidence >= 0.5
        ? 'alert'
        : 'record',
    confidence,
    reason
  };
}

function decodeSafely(value) {
  let text = String(value ?? '');

  for (let i = 0; i < 2; i++) {
    try {
      const next = decodeURIComponent(text.replace(/\+/g, ' '));
      if (next === text) break;
      text = next;
    } catch {
      break;
    }
  }

  return text;
}

export async function decide(alert) {
  const data = alert?.data ?? {};
  const rule = alert?.rule ?? {};

  const level = Number(rule.level ?? 0);
  const count = Number(data.count ?? 1);

  const url = decodeSafely(data.url ?? '');
  const description = String(rule.description ?? '');

  // 모의 경보의 URL에서 쿼리 입력값만 추출한다.
  const query = url.includes('?')
    ? url.slice(url.indexOf('?') + 1)
    : url;

  const values = query
    .split('&')
    .map(part => {
      const pos = part.indexOf('=');
      return pos >= 0 ? part.slice(pos + 1) : part;
    })
    .map(decodeSafely)
    .join(' ');

  const sql =
    /doc-sql-(?:chain|or|select-chain)/i.test(values) ||
    /\bunion\s+(?:all\s+)?select\b/i.test(values) ||
    /(?:'|")\s*or\s+\d+\s*=\s*\d+/i.test(values);

  const script =
    /doc-script-marker/i.test(values) ||
    /<script\b/i.test(values) ||
    /\bon(?:error|load)\s*=/i.test(values);

  const traversal =
    /doc-up-repeat/i.test(values) ||
    (values.match(/\.\.[/\\]/g) ?? []).length >= 2;

  const mixed =
    /doc-mixed-marker/i.test(values);

  const separator =
    /doc-cmd-separator/i.test(values) ||
    /;\s*(?:select|drop|update|delete)\b/i.test(values);

  let pattern = null;

  if (sql || separator) {
    pattern = PATTERNS[0].name;
  } else if (script || mixed) {
    pattern = PATTERNS[1].name;
  } else if (traversal) {
    pattern = PATTERNS[2].name;
  }

  // 명확한 공격 표식 + 반복 요청 + 높은 경보 수준
  if (pattern && count >= 5 && level >= 8) {
    return makeResult(0.95, pattern);
  }

  // 공격 표식은 있지만 반복 여부가 충분하지 않은 경우
  if (pattern) {
    return makeResult(0.65, pattern);
  }

  // Wazuh가 주입 가능성을 보고한 단발성 경보
    // 공격 여부가 확실하지 않은 단발성 웹 경보
  // 차단하지 않고 알림으로 남긴다.
  if (
    count >= 1 &&
    level >= 5
  ) {
    return makeResult(0.6, 'ambiguous-web-request');
  }

  // 위험 수준이 낮은 정상 웹 요청
  return makeResult(0.1, 'normal-web-request');
}
