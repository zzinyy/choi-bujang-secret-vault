import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFile } from 'node:fs/promises';
import { decide } from '../xdr/persistence/decide.mjs';
import { readAlerts } from '../xdr/persistence/read-alerts.mjs';
import { buildResponse, applyDenyRules } from '../xdr/persistence/respond.mjs';
import { decide as baseDecide, RULE_IDS } from '../src/decider.mjs';
const fixture = JSON.parse(await readFile(new URL('../xdr/fixtures/persistence.json', import.meta.url), 'utf8'));

test('persistence fixture separates correlated attacks, uncertain changes and normal events', () => {
  const rows = fixture.alerts.map(decide);
  assert.ok(rows.slice(0,8).every(row => row.action === 'block'));
  assert.ok(rows.slice(8,16).every(row => row.action === 'alert'));
  assert.ok(rows.slice(16).every(row => row.action === 'record'));
  for (const row of rows) {
    assert.deepEqual(Object.keys(row).sort(), ['action','confidence','reason']);
    assert.equal(row.action, row.confidence >= .85 ? 'block' : row.confidence >= .5 ? 'alert' : 'record');
  }
});
test('level, temporary binary and unknown signatures alone never quarantine', () => {
  assert.equal(decide(null).action, 'record');
  assert.notEqual(decide({ rule:{level:15,description:'임시 폴더에 실행 파일 생성, 서비스 등록은 없습니다.'},data:{path:'C:\\Temp\\draft.exe'} }).action,'block');
  assert.notEqual(decide({ rule:{level:15,description:'새 서비스 등록, 서명은 확인되지 않았습니다.'},data:{path:'C:\\lab\\tool.exe'} }).action,'block');
  assert.notEqual(decide({ rule:{level:15,description:'새 서비스 등록, 서명된 정상 프로그램'},data:{path:'C:\\Temp\\setup.exe',signed:true} }).action,'block');
  assert.equal(decide({ rule:{level:12,description:'서명 없는 새 서비스가 임시 폴더의 실행 파일을 가리킵니다.'},data:{path:'C:\\Temp\\service.exe'} }).action,'block');
  const renamed = {...fixture.alerts[0],id:'unseen-id',agent:{name:'different-pc'}};
  assert.deepEqual(decide(renamed),decide(fixture.alerts[0]));
});
test('persistence decision module is independent and output contains no raw paths or credentials', async () => {
  const source = await readFile(new URL('../xdr/persistence/decide.mjs', import.meta.url),'utf8');
  assert.ok(!/\bimport\s*(?:\(|['"{*])|\b(?:fetch|readFile|writeFile|eval)\s*\(/.test(source));
  assert.equal((await readAlerts()).length, fixture.alerts.length);
  assert.ok(!JSON.stringify(decide({...fixture.alerts[0],data:{...fixture.alerts[0].data,password:'private-fixture-value'}})).includes('private-fixture-value'));
});
test('quarantine candidates expire and the overlay preserves normal sources and baseline decisions',async()=>{
  const now=Date.now(); const response=buildResponse(fixture.alerts,now);
  assert.equal(response.rules.length,8); assert.equal(response.notifications.length,16);
  assert.ok(response.rules.every(row=>row.evidenceAlertId && Date.parse(row.expiresAt)===now+900000));
  const request={requestId:'fixture-request',deviceRegistered:true,service:'notes',method:'GET',route:'GET /notes/:id',path:'/notes/demo',queryLength:0,signals:{source:'none'}};
  const base=await baseDecide(request); assert.equal(base.decision,'allow');
  const args={request,decision:base,rules:response.rules,now,trustedTransport:true,verifiedAgentId:'choi-bujang-pc'};
  const denied=applyDenyRules({...args,verifiedSourceIp:'203.0.113.12'});
  assert.equal(denied.decision,'deny'); assert.ok(denied.ruleIds.every(id=>RULE_IDS.includes(id)));
  assert.deepEqual(Object.keys(denied).sort(),['decision','reasonCode','requestId','ruleIds','schema']);
  assert.equal(applyDenyRules({...args,verifiedSourceIp:'192.0.2.74'}),base);
  assert.equal(applyDenyRules({...args,verifiedSourceIp:'203.0.113.12',verifiedAgentId:'other-pc'}),base);
  assert.equal(applyDenyRules({...args,verifiedSourceIp:'203.0.113.12',trustedTransport:false}),base);
  assert.equal(applyDenyRules({...args,verifiedSourceIp:'203.0.113.12',now:now+900000}),base);
  const baselineDeny=await baseDecide({...request,deviceRegistered:false});
  assert.equal(applyDenyRules({...args,decision:baselineDeny,verifiedSourceIp:'192.0.2.74'}),baselineDeny);
});
