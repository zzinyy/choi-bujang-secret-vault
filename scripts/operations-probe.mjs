import { readFile, mkdir, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { probeAnonymous } from '../public/operations-evidence.js';
const root = resolve(import.meta.dirname, '..');
const config = JSON.parse(await readFile(resolve(root, 'aleph.config.json'), 'utf8'));
const report = { schema: 'student.operations.evidence.v1',
  target: config.publicAppUrl, engineSource: 'ALEPH SDP 엔진',
  officialJudge: { observed: 'not_run', catalogSize: 41, executedCount: null,
    reason: 'Official catalog and execution-record contract unavailable' },
  probes: await probeAnonymous(config.publicAppUrl) };
await mkdir(resolve(root, 'artifacts'), { recursive: true });
await writeFile(resolve(root, 'artifacts/operations-probe.json'), JSON.stringify(report, null, 2) + '\n');
console.log(JSON.stringify(report, null, 2));
