// Standalone offline Wazuh-alert classifier. No external dependencies or I/O.
const PATTERNS = Object.freeze([
  { name: 'persistence.unsigned-service', confidence: 0.96,
    condition: 'Unsigned service plus temporary binary, changed image or repeated registration', evidence: 'MITRE T1543: service creation/modification for persistent execution' },
  { name: 'persistence.suspicious-task', confidence: 0.94,
    condition: 'Unfamiliar scheduled task executes a temporary program', evidence: 'MITRE T1053: scheduled execution of malicious code' },
  { name: 'persistence.unknown-startup', confidence: 0.92,
    condition: 'Executable added to Startup and explicitly absent from baseline', evidence: 'MITRE T1547.001: startup-folder autostart persistence' },
  { name: 'persistence.needs-review', confidence: 0.6,
    condition: 'Service/task/startup or file-integrity signal without corroborating evidence', evidence: 'T1543/T1053 describe mechanisms, not proof that every change is malicious' },
]);
const text = value => typeof value === 'string' ? value.slice(0, 8192).toLowerCase() : '';

export function decide(alert) {
  const data = alert?.data ?? {};
  const description = text(alert?.rule?.description);
  const path = text(data.path ?? data.image ?? data.command).replaceAll('/', '\\');
  const level = Number(alert?.rule?.level);
  const service = /서비스|\bservice\b/.test(description) || data.eventType === 'service';
  const task = /예약 작업|scheduled task|\bcron\b/.test(description) || data.eventType === 'scheduled_task';
  const startup = /시작 (?:폴더|프로그램|항목)|startup/.test(description) || /\\startup\\/.test(path);
  const unsigned = data.signed === false || /서명 없는|서명이 없|\bunsigned\b/.test(description);
  const knownSigned = data.signed === true || /서명된|정상 서명|digitally signed/.test(description);
  const temporary = /\\(?:temp|tmp)\\/.test(path) || /임시 (?:폴더|파일)/.test(description);
  const unfamiliar = data.baselineMatched === false || /평소 목록에 없|처음 보는|낯선|임의 문자열|새 서비스|새로운 서비스|unfamiliar|not in baseline/.test(description);
  const changedImage = /실행 파일.*(?:바뀌|변경)|image.*chang/.test(description);
  const registration = /등록|생성|추가|creat|install/.test(description) && !/등록은 없|등록이 없|not registered/.test(description);
  const repeated = Number(data.count) >= 3;
  const strong = Number.isFinite(level) && level >= 10 && !knownSigned;
  let pattern;
  if (strong && service && ((unsigned && (temporary || changedImage || (registration && repeated))) || (registration && unfamiliar && temporary))) pattern = PATTERNS[0];
  else if (strong && task && temporary && (unfamiliar || startup || /수업 시간 밖|outside.*hours/.test(description))) pattern = PATTERNS[1];
  else if (strong && startup && unfamiliar && /\.(?:exe|cmd|bat|ps1|vbs|lnk)$/.test(path) && registration) pattern = PATTERNS[2];
  else if (Number.isFinite(level) && level >= 5 && (service || task || startup || temporary || /무결성|file integrity/.test(description))) pattern = PATTERNS[3];
  const confidence = pattern?.confidence ?? 0.1;
  return { action: confidence >= .85 ? 'block' : confidence >= .5 ? 'alert' : 'record',
    confidence, reason: pattern?.name ?? 'persistence.no-correlated-signal' };
}
