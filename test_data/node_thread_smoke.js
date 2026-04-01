const { Worker } = require('worker_threads');

const workers = 2;
const iterations = 5000;
let remaining = workers;
let total = 0;
let failed = false;

function finish() {
  if (failed) {
    return;
  }
  remaining--;
  if (remaining !== 0) {
    return;
  }

  let expected = 0;
  for (let id = 0; id < workers; id++) {
    let local = 0;
    for (let i = 0; i < iterations; i++) {
      local += (i ^ id);
    }
    expected += local;
  }

  if (total !== expected) {
    console.log(`TOS-NODE-THREAD-FAIL total=${total} expected=${expected}`);
    process.exit(1);
  }

  console.log(`TOS-NODE-THREAD-OK total=${total}`);
}

for (let id = 0; id < workers; id++) {
  const worker = new Worker(
    `
const { parentPort, workerData } = require('worker_threads');
let local = 0;
for (let i = 0; i < workerData.iterations; i++) {
  local += (i ^ workerData.id);
}
parentPort.postMessage(local);
`,
    {
      eval: true,
      workerData: { id, iterations },
      resourceLimits: {
        maxOldGenerationSizeMb: 16,
        maxYoungGenerationSizeMb: 4,
      },
    }
  );

  worker.on('message', (value) => {
    total += value;
  });
  worker.on('error', (err) => {
    failed = true;
    console.log(`TOS-NODE-THREAD-FAIL error=${(err && err.message) || err}`);
    process.exit(1);
  });
  worker.on('exit', (code) => {
    if (code !== 0) {
      failed = true;
      console.log(`TOS-NODE-THREAD-FAIL exit=${code}`);
      process.exit(1);
    }
    finish();
  });
}
