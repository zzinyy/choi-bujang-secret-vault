// Offline single-alert classifier. Numeric cutoffs are local policy, not MITRE thresholds.
const PATTERNS=Object.freeze([
  {name:'exfiltration.large-unfamiliar',confidence:.96,condition:'Large transfer to an explicitly unfamiliar destination',evidence:'MITRE T1041/T1048: exfiltration using command channels or other protocols'},
  {name:'exfiltration.correlated-transfer',confidence:.94,condition:'Large transfer plus repeated sends, unusual port or complete external copy',evidence:'T1041/T1048 motivate combining transfer behavior with destination and context'},
  {name:'exfiltration.offhours-archive',confidence:.92,condition:'Archive transfer to unfamiliar destination outside business hours',evidence:'T1048: investigate outbound transfers with multiple suspicious signals'},
  {name:'exfiltration.needs-review',confidence:.6,condition:'Transfer or archive activity without corroborating evidence',evidence:'Backups and synchronization can be legitimate; one anomaly is insufficient'},
]);
const text=value=>typeof value==='string'?value.slice(0,8192).toLowerCase():'';
const number=value=>((typeof value==='number'||(typeof value==='string'&&value.trim()))&&Number.isFinite(Number(value))&&Number(value)>=0)?Number(value):null;
export function decide(alert){
  const data=alert?.data??{},description=text(alert?.rule?.description);
  const level=number(alert?.rule?.level),bytes=number(data.bytes),count=number(data.count);
  const destination=typeof data.dstip==='string'&&data.dstip.trim().length>0;
  const unfamiliar=data.destinationKnown===false||/처음 보는|처음 봅니다|평소와 다른 주소|unfamiliar|new destination/.test(description);
  const known=data.destinationKnown===true||/평소 목적지|수업 자료 주소|approved destination/.test(description);
  const repeated=count!==null&&count>=5;
  const unusualPort=data.portKnown===false||/쓰지 않던 포트|비정상 포트|unusual port/.test(description);
  const archive=data.archive===true||/압축 파일|archive|\.zip\b|\.7z\b/.test(description);
  const offHours=data.outsideBusinessHours===true||/수업 시간 밖|업무 시간 밖|outside.*hours/.test(description);
  const wholeExternal=/자료실 전체.*외부|whole.*external/.test(description)||data.wholeRepositoryCopy===true;
  const failed=data.success===false||/실패|전송은 아직 없|전송은 없|전송이 없|failed|no transfer/.test(description);
  const large=bytes!==null&&bytes>=50000000;
  const strong=level!==null&&level>=10&&destination&&!failed&&!known&&data.transferApproved!==true&&bytes!==null&&bytes>0;
  let pattern;
  if(strong&&large&&unfamiliar)pattern=PATTERNS[0];
  else if(strong&&large&&(repeated||unusualPort||wholeExternal))pattern=PATTERNS[1];
  else if(strong&&archive&&offHours&&unfamiliar)pattern=PATTERNS[2];
  else if(level!==null&&level>=5&&(/전송|압축|자료.*읽|파일 수|목적지|통로|transfer|archive/.test(description)||bytes!==null))pattern=PATTERNS[3];
  const confidence=pattern?.confidence??.1;
  return {action:confidence>=.85?'block':confidence>=.5?'alert':'record',confidence,reason:pattern?.name??'exfiltration.no-correlated-signal'};
}
