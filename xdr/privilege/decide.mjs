// Offline, single-alert classifier. Evidence must be in the supplied alert.
const PATTERNS = Object.freeze([
  { name:'privilege.admin-group-risk',confidence:.96,condition:'Administrator group addition with remote origin, command use, bulk additions or re-grant',evidence:'MITRE T1078: abuse of valid accounts and elevated access' },
  { name:'privilege.elevated-command',confidence:.94,condition:'New elevation plus command execution, unfamiliar elevated session or cross-account command',evidence:'T1068/T1078: suspicious elevated execution; this alone does not identify a specific exploit' },
  { name:'privilege.needs-review',confidence:.6,condition:'Account/group/privileged activity without enough corroboration',evidence:'Normal administrative activity may use the same mechanisms; review without automatic revocation' },
]);
const text=value=>typeof value==='string'?value.slice(0,8192).toLowerCase():'';
export function decide(alert) {
  const data=alert?.data??{};
  const description=text(alert?.rule?.description);
  const level=Number(alert?.rule?.level);
  const group=text(data.group);
  const groupSupplied=group.length>0;
  const adminGroup=groupSupplied?/^(?:administrators|domain admins|관리자)$/.test(group):/관리자 그룹|admin(?:istrator)? group/.test(description)&&!/관리자 그룹[은이] 아니|not.*admin.*group/.test(description);
  const added=/추가|들어가|들어왔|추가됐|\badd(?:ed)?\b/.test(description)||data.eventType==='admin_group_add';
  const remote=/원격 주소|remote/.test(description)||data.remote===true;
  const command=/명령.*실행|권한 명령|command.*execut/.test(description)||data.eventType==='privileged_command';
  const newlyElevated=/방금 관리자가|곧바로|권한으로 바뀌|newly elevated/.test(description)||data.newlyElevated===true;
  const unfamiliar=/처음 보는|처음 봅니다|낯선|unfamiliar/.test(description)||data.sourceKnown===false;
  const offHours=/수업 시간 밖|업무.*(?:아닌|보이지 않는)|outside.*hours/.test(description)||data.outsideBusinessHours===true;
  const crossAccount=/다른 계정의 권한|다른 사용자의 권한|cross.account/.test(description)||data.crossAccount===true;
  const regrant=/빠진 계정.*다시|회수.*다시|제거.*다시|re.?grant/.test(description)||data.regranted===true;
  const cancelled=/취소|실패|cancelled|canceled|failed/.test(description)||data.success===false;
  const strong=Number.isFinite(level)&&level>=10&&!cancelled&&data.changeApproved!==true;
  let pattern;
  if(strong&&adminGroup&&((added&&(remote||command||Number(data.count)>=3))||regrant))pattern=PATTERNS[0];
  else if(strong&&((command&&(newlyElevated||crossAccount||(unfamiliar&&offHours)))||(newlyElevated&&unfamiliar)))pattern=PATTERNS[1];
  else if(Number.isFinite(level)&&level>=5&&(/권한|관리자|계정|그룹|privileg|admin|account|group/.test(description)||groupSupplied))pattern=PATTERNS[2];
  const confidence=pattern?.confidence??.1;
  return {action:confidence>=.85?'block':confidence>=.5?'alert':'record',confidence,reason:pattern?.name??'privilege.no-correlated-signal'};
}
