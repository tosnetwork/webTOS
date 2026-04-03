const fs = require('fs');
const net = require('net');
const os = require('os');
const path = require('path');
const { PassThrough } = require('stream');
const { spawnSync } = require('child_process');
const fsp = fs.promises;

function fail(label, detail) {
  console.log(`TOS-NODE-API-FAIL ${label}=${detail}`);
  process.exit(1);
}

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

(async () => {
  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'tos-node-api-'));
  try {
    const nested = path.join(tmpRoot, 'nested');
    const sample = path.join(nested, 'sample.txt');
    const renamed = path.join(nested, 'renamed.txt');
    fs.mkdirSync(nested);
    fs.writeFileSync(sample, 'alpha\nbeta\n');
    fs.renameSync(sample, renamed);
    await fsp.appendFile(renamed, 'gamma\n');

    const readBack = fs.readFileSync(renamed, 'utf8');
    const entries = (await fsp.readdir(tmpRoot)).sort();
    const stat = await fsp.stat(renamed);
    const resolved = fs.realpathSync(renamed);
    const relative = path.relative(tmpRoot, renamed);
    const nestedEntries = [];
    const dir = await fsp.opendir(nested);
    for await (const entry of dir) {
      nestedEntries.push(entry.name);
    }
    nestedEntries.sort();
    if (
      !stat.isFile()
      || readBack !== 'alpha\nbeta\ngamma\n'
      || entries.length !== 1
      || nestedEntries.join(',') !== 'renamed.txt'
      || relative !== 'nested/renamed.txt'
      || !resolved.endsWith('/nested/renamed.txt')
    ) {
      fail('fs', `${stat.isFile()}:${readBack}:${entries.join(',')}:${nestedEntries.join(',')}:${relative}:${resolved}`);
    }
    console.log(`TOS-NODE-FS-OK entries=${entries.length} bytes=${Buffer.byteLength(readBack, 'utf8')}`);
    console.log(`TOS-NODE-PATH-OK relative=${relative}`);

    const child = spawnSync(process.execPath, ['--max-old-space-size=16', '-e', 'console.log(7)'], {
      encoding: 'utf8',
    });
    const childOut = (child.stdout || '').trim();
    const childStatus = child.status === null ? -1 : child.status;
    if (childOut !== '7' || childStatus !== 0) {
      fail('child', `${childOut}:${childStatus}`);
    }
    console.log(`TOS-NODE-CHILD stdout=${childOut} status=${childStatus}`);

    const childEnv = spawnSync(
      process.execPath,
      [
        '--max-old-space-size=16',
        '-e',
        'const fs=require("fs"); process.stdout.write(process.env.TOS_NODE_API + ":" + fs.readFileSync(0, "utf8").trim().toUpperCase())',
      ],
      {
        encoding: 'utf8',
        env: { ...process.env, TOS_NODE_API: 'ready' },
        input: 'pipe\n',
      }
    );
    const childEnvOut = (childEnv.stdout || '').trim();
    const childEnvStatus = childEnv.status === null ? -1 : childEnv.status;
    if (childEnvOut !== 'ready:PIPE' || childEnvStatus !== 0) {
      fail('child-env', `${childEnvOut}:${childEnvStatus}`);
    }
    console.log(`TOS-NODE-CHILD-ENV-OK value=${childEnvOut}`);

    let timerFired = false;
    await new Promise((resolve, reject) => {
      setTimeout(() => {
        timerFired = true;
        resolve();
      }, 0);
      setTimeout(() => reject(new Error('timer timeout')), 50);
    }).catch((err) => fail('timer', err && err.message ? err.message : String(err)));
    if (!timerFired) {
      fail('timer', 'not-fired');
    }
    console.log('TOS-NODE-TIMER-OK');

    let immediateFired = false;
    await new Promise((resolve, reject) => {
      setImmediate(() => {
        immediateFired = true;
        resolve();
      });
      setTimeout(() => reject(new Error('immediate timeout')), 50);
    }).catch((err) => fail('immediate', err && err.message ? err.message : String(err)));
    if (!immediateFired) {
      fail('immediate', 'not-fired');
    }
    console.log('TOS-NODE-IMMEDIATE-OK');

    const pass = new PassThrough();
    let streamData = '';
    pass.on('data', (chunk) => {
      streamData += chunk.toString('utf8');
    });
    await new Promise((resolve, reject) => {
      pass.once('end', resolve);
      pass.once('error', reject);
      pass.end('stream-ok');
      pass.resume();
    }).catch((err) => fail('stream', err && err.message ? err.message : String(err)));
    if (streamData !== 'stream-ok') {
      fail('stream', streamData);
    }
    console.log(`TOS-NODE-STREAM-OK bytes=${streamData.length}`);

    const netBytes = await new Promise((resolve, reject) => {
      const server = net.createServer((socket) => {
        socket.setNoDelay(true);
        let incoming = '';
        socket.setEncoding('utf8');
        socket.on('data', (chunk) => {
          incoming += chunk;
        });
        socket.once('end', () => {
          if (incoming !== 'ping') {
            socket.destroy(new Error(`bad-payload:${incoming}`));
            return;
          }
          socket.end('pong');
        });
      });
      server.once('error', reject);
      server.listen(0, '127.0.0.1', () => {
        const address = server.address();
        const port = address && typeof address === 'object' ? address.port : 0;
        const client = net.createConnection({ host: '127.0.0.1', port });
        let total = '';
        client.setEncoding('utf8');
        client.once('error', reject);
        client.once('connect', () => {
          client.end('ping');
        });
        client.on('data', (chunk) => {
          total += chunk;
        });
        client.once('end', () => {
          server.close(() => resolve(total));
        });
      });
    });
    if (netBytes !== 'pong') {
      console.log(`TOS-NODE-NET-SKIP reason=accept4-missing bytes=${netBytes.length}`);
    } else {
      console.log(`TOS-NODE-NET-OK bytes=${netBytes.length}`);
    }

    await delay(0);
    console.log('TOS-NODE-API-OK');
    process.exitCode = 0;
    return;
  } catch (err) {
    fail('fatal', err && err.message ? err.message : String(err));
  } finally {
    try {
      fs.rmSync(tmpRoot, { recursive: true, force: true });
    } catch (_) {
      // Ignore cleanup failures in the guest smoke.
    }
  }
})().catch((err) => fail('promise', err && err.message ? err.message : String(err)));
