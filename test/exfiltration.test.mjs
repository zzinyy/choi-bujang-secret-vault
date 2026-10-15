import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFile } from 'node:fs/promises';
import { decide } from '../xdr/exfiltration/decide.mjs';
import { readAlerts } from '../xdr/exfiltration/read-alerts.mjs';
import { buildResponse, applyDenyRules } from '../xdr/exfiltration/respond.mjs';
import { decide as baseDecide, RULE_IDS } from '../src/decider.mjs';
const fixture=JSON.parse(await readFile(new URL('../xdr/fixtures/exfiltration.json',import.meta.url),'utf8'));
test('exfiltration separates clear, uncertain and normal transfer evidence',()=>{
  const rows=fixture.alerts.map(decide);
  assert.ok(rows.slice(0,10).every(row=>row.action==='block'));
  assert.ok(rows.slice(10,20).every(row=>row.action==='alert'));
  assert.ok(rows.slice(20).every(row=>row.action==='record'));
  for(const row of rows){assert.deepEqual(Object.keys(row).sort(),['action','confidence','reason']);assert.equal(row.action,row.confidence>=.85?'block':row.confidence>=.5?'alert':'record');}
});
test('volume alone, missing destination, failed and approved transfers never block',()=>{
  const alert=fixture.alerts[0];
  for(const change of [{bytes:'-1'},{bytes:'Infinity'},{bytes:'bad'},{dstip:null},{success:false},{transferApproved:true},{destinationKnown:true}])assert.notEqual(decide({...alert,data:{...alert.data,...change}}).action,'block');
  assert.notEqual(decide({rule:{level:15,description:'대용량 전송'},data:{bytes:999999999,dstip:'192.0.2.10'}}).action,'block');
  assert.notEqual(decide({...alert,data:{...alert.data,bytes:'49999999'}}).action,'block');
  assert.equal(decide({...alert,data:{...alert.data,bytes:'50000000'}}).action,'block');
  assert.equal(decide(null).action,'record');
  assert.deepEqual(decide({...alert,id:'unseen-id',agent:{name:'another-pc'}}),decide(alert));
});
test('independent classifier does not return file contents and reading preserves count',async()=>{
  const source=await readFile(new URL('../xdr/exfiltration/decide.mjs',import.meta.url),'utf8');
  assert.ok(!/\bimport\s*(?:\(|['"{*])|\b(?:fetch|readFile|writeFile|eval)\s*\(/.test(source));
  assert.equal((await readAlerts()).length,30);
  assert.ok(!JSON.stringify(decide({...fixture.alerts[0],data:{...fixture.alerts[0].data,body:'private-fixture-content'}})).includes('private-fixture-content'));
});
test('destination rules expire and preserve other PCs, normal destinations and baseline denial',async()=>{
  const now=Date.now(),response=buildResponse(fixture.alerts,now);
  assert.equal(response.rules.length,10);assert.equal(response.notifications.length,20);
  assert.ok(response.rules.every(row=>row.destinationIp&&row.evidenceAlertId&&Date.parse(row.expiresAt)===now+900000));
  const request={requestId:'fixture-request',deviceRegistered:true,service:'notes',method:'GET',route:'GET /notes/:id',path:'/notes/demo',queryLength:0,signals:{source:'none'}};
  const base=await baseDecide(request);
  const args={request,decision:base,rules:response.rules,now,trustedTransport:true,verifiedAgentId:'choi-bujang-pc',verifiedDestinationIp:'203.0.113.50'};
  const denied=applyDenyRules(args);assert.equal(denied.decision,'deny');assert.ok(denied.ruleIds.every(id=>RULE_IDS.includes(id)));
  assert.deepEqual(Object.keys(denied).sort(),['decision','reasonCode','requestId','ruleIds','schema']);
  for(const change of [{verifiedDestinationIp:'192.0.2.10'},{verifiedDestinationIp:undefined},{verifiedAgentId:'other-pc'},{trustedTransport:false},{now:now+900000}])assert.equal(applyDenyRules({...args,...change}),base);
  const originalDeny=await baseDecide({...request,deviceRegistered:false});assert.equal(applyDenyRules({...args,decision:originalDeny}),originalDeny);
  assert.equal(buildResponse([{...fixture.alerts[0],data:{...fixture.alerts[0].data,dstip:'not-an-ip'}}],now).rules.length,0);
});
