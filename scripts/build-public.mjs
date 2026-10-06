import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { deploymentIdentity } from './deployment-identity.mjs';

const root = resolve(import.meta.dirname, '..');
const config = JSON.parse(
  await readFile(resolve(root, 'aleph.config.json'), 'utf8')
);

if (config.step !== 3) {
  throw new Error('3단계 빌드에서는 aleph.config.json의 step이 3이어야 합니다.');
}

await mkdir(resolve(root, 'public'), { recursive: true });

// 2단계부터 메모 원문은 정적 파일에 포함하지 않습니다.
const publicData = {
  notes: []
};

await writeFile(
  resolve(root, 'public', 'data.json'),
  `${JSON.stringify(publicData, null, 2)}\n`,
  'utf8'
);

console.log('메모 원문을 제외한 public/data.json을 생성했습니다.');

if (!process.argv.includes('--local')) {
  const identity = deploymentIdentity(process.env, config);

  await writeFile(
    resolve(root, 'public', 'aleph.json'),
    `${JSON.stringify(identity, null, 2)}\n`,
    'utf8'
  );

  console.log('배포 정보를 public/aleph.json에 기록했습니다.');
}