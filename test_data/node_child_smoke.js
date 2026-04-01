const { spawnSync } = require('child_process');

const r = spawnSync(process.execPath, ['--max-old-space-size=16', '-e', 'console.log(7)'], {
  encoding: 'utf8',
});
const out = (r.stdout || '').trim();
const status = r.status === null ? -1 : r.status;
console.log(`TOS-NODE-CHILD stdout=${out} status=${status}`);
if (out !== '7' || status !== 0) {
  process.exit(1);
}
