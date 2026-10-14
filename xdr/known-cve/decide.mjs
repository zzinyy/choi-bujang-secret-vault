// Standalone offline classifier. No I/O, imports, identity, or fixture-ID rules.
const PATTERNS = Object.freeze([
  { name: 'log4shell.remote-jndi', confidence: 0.97,
    condition: 'Complete remote JNDI lookup in HTTP request fields',
    evidence: 'Apache CVE-2021-44228: attacker-controlled JNDI endpoints', },
  { name: 'log4shell.lookup-fragment', confidence: 0.65,
    condition: 'Incomplete lookup or scanner signal without complete remote lookup',
    evidence: 'T1190 exploit attempts require investigation; fragments alone do not prove exploitation', },
  { name: 'log4shell.weak-indicator', confidence: 0.55,
    condition: 'CVE/JNDI/scanner indicator with a moderate-severity related alert',
    evidence: 'CVE identifiers, tool names and rule levels alone do not prove exploitation', },
]);

function text(value) {
  return typeof value === 'string' ? value.slice(0, 16384) : '';
}
function normalize(value) {
  let out = text(value);
  for (let i = 0; i < 2; i++) {
    try { const next = decodeURIComponent(out); if (next === out) break; out = next; }
    catch { break; }
  }
  return out.toLowerCase();
}

export function decide(alert) {
  const data = alert?.data ?? {};
  const requestText = [data.url, data.useragent, data.query, data.request,
    data.payload, data.body, data.http_headers,
    ...Object.values(data.headers && typeof data.headers === 'object' ? data.headers : {}),
  ].map(normalize).join('\n');
  // A lookup must be complete and contain a network target. Words in rule
  // descriptions never become a confirmed attack payload.
  const remote = /\$\{\s*jndi\s*:\s*(?:ldaps?|rmi|dns|iiop|http|https)\s*:\/\/[^\s{}\/]+(?:\/[^\s{}]*)?\s*\}/i.test(requestText);
  let pattern;
  if (remote) pattern = PATTERNS[0];
  else if (/\$\{\s*jndi\s*:|log4shell|log4j[ _-]?(?:scan|shell)|jndi[ _-]?(?:scan|exploit)/i.test(requestText)) pattern = PATTERNS[1];
  else {
    const description = normalize(alert?.rule?.description);
    const level = Number(alert?.rule?.level);
    const related = /cve-2021-44228|jndi|log4shell|취약점|조회.*(?:잘린|구문)|(?:점검 도구|라이브러리).*(?:흔적|로그|악용)/i.test(description + '\n' + requestText);
    if (Number.isFinite(level) && level >= 5 && related) pattern = PATTERNS[2];
  }
  const confidence = pattern?.confidence ?? 0.1;
  return { action: confidence >= 0.85 ? 'block' : confidence >= 0.5 ? 'alert' : 'record',
    confidence, reason: pattern?.name ?? 'known-cve.no-exploit-signal' };
}
