import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFile } from 'node:fs/promises';
import { decide } from '../xdr/privilege/decide.mjs';
import { readAlerts } from '../xdr/privilege/read-alerts.mjs';
import { buildResponse, applyDenyRules } from '../xdr/privilege/respond.mjs';
import { decide as baseDecide, RULE_IDS } from '../src/decider.mjs';
const fixture=JSON.parse(await readFile(new URL('../xdr/fixtures/privilege.json',import.meta.url),'utf8'));
test('privilege evidence separates confirmed, ambiguous and normal alerts',()=>{
  const rows=fixture.alerts.map(decide);
  assert.ok(rows.slice(0,9).every(row=>row.action==='block'));
  assert.ok(rows.slice(9,17).every(row=>row.action==='alert'));
  assert.ok(rows.slice(17).every(row=>row.action==='record'));
  for(const row of rows){assert.deepEqual(Object.keys(row).sort(),['action','confidence','reason']);assert.equal(row.action,row.confidence>=.85?'block':row.confidence>=.5?'alert':'record');}
});
test('cancelled, authorized and non-administrator group events never block',()=>{
  for(const description of ['원격 주소에서 관리자 그룹에 추가 요청이 취소됐습니다.','다른 계정의 권한으로 관리자 명령 실행이 실패했습니다.']){
    assert.notEqual(decide({rule:{level:15,description},data:{group:'administrators'}}).action,'block');
  }
  assert.notEqual(decide({...fixture.alerts[0],data:{...fixture.alerts[0].data,changeApproved:true}}).action,'block');
  assert.notEqual(decide({rule:{level:15,description:'원격 주소에서 그룹 추가'},data:{group:'project-team'}}).action,'block');
  assert.equal(decide(null).action,'record');
  assert.deepEqual(decide({...fixture.alerts[0],id:'other-id'}),decide(fixture.alerts[0]));
});
test('standalone classification and redacted reading preserve the input count',async()=>{
  const source=await readFile(new URL('../xdr/privilege/decide.mjs',import.meta.url),'utf8');
  assert.ok(!/\bimport\s*(?:\(|['"{*])|\b(?:fetch|readFile|writeFile|eval)\s*\(/.test(source));
  assert.equal((await readAlerts()).length,26);
  assert.ok(!JSON.stringify(decide({...fixture.alerts[0],data:{password:'fixture-private'}})).includes('fixture-private'));
});
test('session-deny candidates are account-scoped, temporary and preserve baseline rules',async()=>{
  const now=Date.now(),response=buildResponse(fixture.alerts,now);
  assert.equal(response.rules.length,9);assert.equal(response.notifications.length,17);
  assert.ok(response.rules.every(row=>row.accountId&&row.evidenceAlertId&&Date.parse(row.expiresAt)===now+900000));
  const request={requestId:'fixture-request',deviceRegistered:true,service:'notes',method:'GET',route:'GET /notes/:id',path:'/notes/demo',queryLength:0,signals:{source:'none'}};
  const base=await baseDecide(request);
  const args={request,decision:base,rules:response.rules,now,trustedTransport:true,verifiedAgentId:'choi-bujang-pc',verifiedAccountId:'user01',verifiedSourceIp:'203.0.113.11'};
  const denial=applyDenyRules(args);assert.equal(denial.decision,'deny');assert.ok(denial.ruleIds.every(id=>RULE_IDS.includes(id)));
  assert.deepEqual(Object.keys(denial).sort(),['decision','reasonCode','requestId','ruleIds','schema']);
  for(const change of [{verifiedAccountId:'other-user'},{verifiedAccountId:undefined},{verifiedAgentId:'other-pc'},{verifiedSourceIp:'192.0.2.76'},{trustedTransport:false},{now:now+900000}])assert.equal(applyDenyRules({...args,...change}),base);
  const originalDeny=await baseDecide({...request,deviceRegistered:false});assert.equal(applyDenyRules({...args,decision:originalDeny}),originalDeny);
  assert.equal(buildResponse([{...fixture.alerts[0],data:{srcip:'203.0.113.11'}}],now).rules.length,0);
});
