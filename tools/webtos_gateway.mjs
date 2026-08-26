// Development network gateway for the browser host.
//
// A browser tab cannot open a TCP or UDP socket, and the guest does its own
// TLS and its own DNS, so what it needs is a byte relay rather than an HTTP
// proxy. This is that relay, and it is the only place in the stack that can
// reach the network on the guest's behalf — which makes it the only place
// where the policy belongs.
//
// Policy, in order:
//   1. Nothing is allowed unless an --allow rule names it. With no rules the
//      gateway starts and refuses every connection, loudly.
//   2. Every WebSocket must carry an Origin the gateway was told to accept
//      (localhost by default). Without this a page on any site the user
//      visits could drive their gateway as an open proxy. It constrains
//      browsers, which cannot forge an Origin; it does not constrain a local
//      program, which can. The allowlist is the boundary that holds for both.
//   3. It binds to the loopback interface unless told otherwise.
//   4. Every decision is logged, allowed and refused alike.
//
// Usage:
//   node tools/webtos_gateway.mjs --allow example.com:80 --allow 1.1.1.1:53
//   node tools/webtos_gateway.mjs --allow-file policy.txt --port 8081
//
// Rules are `host:port`, where host is an IPv4 literal or a name. The guest
// resolves DNS itself and connects to an address, so a name rule is matched by
// resolving it here and comparing addresses — which also means a rule cannot
// be a wildcard, as there would be no name to resolve.
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { connect as tcpConnect } from "node:net";
import { createSocket } from "node:dgram";
import { resolve4 } from "node:dns/promises";
import { isIPv4 } from "node:net";

let WebSocketServer;
try {
  ({ WebSocketServer } = await import("ws"));
} catch {
  console.error("the gateway needs the 'ws' package. Run:  npm install");
  process.exit(2);
}

// ------------------------------------------------------------------ options

function parseArgs(argv) {
  const options = {
    port: 8081,
    bind: "127.0.0.1",
    allow: [],
    origins: [],
    maxSockets: 64,
    dnsTtlMs: 60_000,
  };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    const value = () => {
      const next = argv[i + 1];
      if (next === undefined) {
        console.error(`${arg} needs a value`);
        process.exit(2);
      }
      i += 1;
      return next;
    };
    switch (arg) {
      case "--allow": options.allow.push(value()); break;
      case "--allow-file": options.allowFile = value(); break;
      case "--origin": options.origins.push(value()); break;
      case "--port": options.port = Number(value()); break;
      case "--bind": options.bind = value(); break;
      case "--max-sockets": options.maxSockets = Number(value()); break;
      case "--help":
        console.log(`usage: node tools/webtos_gateway.mjs [options]

  --allow HOST:PORT    permit one destination (repeatable); nothing is
                       permitted unless named. HOST is an IPv4 literal or a
                       name this gateway resolves
  --allow-file PATH    read rules from a file, one per line, # comments
  --origin ORIGIN      accept WebSockets from this page origin (repeatable);
                       defaults to http://localhost:* and http://127.0.0.1:*
  --port N             listen port (default 8081)
  --bind ADDR          listen address (default 127.0.0.1)
  --max-sockets N      concurrent relayed sockets (default 64)`);
        process.exit(0);
        break;
      default:
        console.error(`unknown option ${arg} (try --help)`);
        process.exit(2);
    }
  }
  return options;
}

const options = parseArgs(process.argv.slice(2));
if (options.allowFile) {
  const text = await readFile(options.allowFile, "utf8");
  for (const line of text.split("\n")) {
    const rule = line.replace(/#.*$/, "").trim();
    if (rule) options.allow.push(rule);
  }
}

// ------------------------------------------------------------------- policy

/// One `host:port` rule. `host` is an IPv4 literal, a name, or `*.suffix`.
function parseRule(rule) {
  const at = rule.lastIndexOf(":");
  if (at < 1) throw new Error(`rule ${JSON.stringify(rule)} is not host:port`);
  const host = rule.slice(0, at);
  const port = Number(rule.slice(at + 1));
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error(`rule ${JSON.stringify(rule)} has no valid port`);
  }
  if (host.includes("*")) {
    throw new Error(
      `rule ${JSON.stringify(rule)} uses a wildcard; the guest connects by address, ` +
        "so a rule must name one host to resolve",
    );
  }
  return { rule, host, port, literal: isIPv4(host) };
}

let rules;
try {
  rules = options.allow.map(parseRule);
} catch (e) {
  console.error(String(e.message ?? e));
  process.exit(2);
}

// Names in rules are resolved to addresses, because the guest connects to an
// address it resolved itself. Cached briefly so a burst of connections does
// not re-resolve, and refreshed so a rotating record does not go stale.
const dnsCache = new Map();
async function addressesFor(host) {
  const cached = dnsCache.get(host);
  if (cached && cached.until > Date.now()) return cached.addresses;
  let addresses = [];
  try {
    addresses = await resolve4(host);
  } catch {
    addresses = [];
  }
  dnsCache.set(host, { addresses, until: Date.now() + options.dnsTtlMs });
  return addresses;
}

/// Decides whether the guest may reach `ip:port`. Returns the rule that
/// permitted it, or null.
async function permit(ip, port) {
  for (const rule of rules) {
    if (rule.port !== port) continue;
    if (rule.literal) {
      if (rule.host === ip) return rule;
      continue;
    }
    // A name rule matches when the address the guest picked is one this
    // gateway resolves the name to.
    if ((await addressesFor(rule.host)).includes(ip)) return rule;
  }
  return null;
}

/// Page origins allowed to drive this gateway. The default covers a local
/// static server on any port; anything else must be named explicitly.
function originAllowed(origin) {
  if (!origin) return false;
  if (options.origins.length > 0) return options.origins.includes(origin);
  try {
    const url = new URL(origin);
    return (
      (url.protocol === "http:" || url.protocol === "https:") &&
      (url.hostname === "localhost" || url.hostname === "127.0.0.1" || url.hostname === "[::1]")
    );
  } catch {
    return false;
  }
}

// -------------------------------------------------------------------- relay

const CLOSE_REFUSED = 4403;
const CLOSE_UNREACHABLE = 4502;
const CLOSE_BAD_REQUEST = 4400;

const stamp = () => new Date().toISOString().slice(11, 23);
const log = (...parts) => console.log(`[${stamp()}]`, ...parts);

let openSockets = 0;

const server = createServer((req, res) => {
  res.writeHead(426, { "content-type": "text/plain" });
  res.end("webTOS gateway: WebSocket only\n");
});
const wss = new WebSocketServer({ noServer: true });

server.on("upgrade", (req, socket, head) => {
  const origin = req.headers.origin;
  if (!originAllowed(origin)) {
    log(`REFUSED upgrade from origin ${origin ?? "(none)"}`);
    socket.destroy();
    return;
  }
  if (openSockets >= options.maxSockets) {
    log(`REFUSED upgrade: ${openSockets} sockets already open`);
    socket.destroy();
    return;
  }
  wss.handleUpgrade(req, socket, head, (ws) => wss.emit("connection", ws, req));
});

wss.on("connection", (ws, req) => {
  const url = new URL(req.url, "http://gateway");
  if (url.pathname === "/tcp") relayTcp(ws, url);
  else if (url.pathname === "/udp") relayUdp(ws);
  else {
    log(`REFUSED ${url.pathname}: unknown endpoint`);
    ws.close(CLOSE_BAD_REQUEST, "unknown endpoint");
  }
});

async function relayTcp(ws, url) {
  const host = url.searchParams.get("host") ?? "";
  const port = Number(url.searchParams.get("port"));
  if (!isIPv4(host) || !Number.isInteger(port) || port < 1 || port > 65535) {
    log(`REFUSED tcp ${host}:${url.searchParams.get("port")}: malformed destination`);
    ws.close(CLOSE_BAD_REQUEST, "malformed destination");
    return;
  }
  const rule = await permit(host, port);
  if (!rule) {
    log(`REFUSED tcp ${host}:${port} (no rule)`);
    ws.close(CLOSE_REFUSED, "destination not allowed");
    return;
  }
  if (ws.readyState !== ws.OPEN) return;

  openSockets += 1;
  log(`ALLOW  tcp ${host}:${port} via ${rule.rule}`);
  let sent = 0;
  let received = 0;
  const socket = tcpConnect({ host, port });
  socket.setNoDelay(true);

  // Both ends report a close, and the pair must count as one.
  let closed = false;
  const shut = () => {
    if (closed) return;
    closed = true;
    openSockets -= 1;
    log(`CLOSE  tcp ${host}:${port} (${sent} B out, ${received} B in)`);
    socket.destroy();
    if (ws.readyState === ws.OPEN) ws.close();
  };

  socket.on("connect", () => ws.send("open"));
  socket.on("data", (chunk) => {
    received += chunk.length;
    // Back-pressure: pause the socket while the WebSocket buffer drains.
    if (ws.bufferedAmount > 1 << 20) socket.pause();
    ws.send(chunk, () => {
      if (socket.isPaused()) socket.resume();
    });
  });
  socket.on("end", () => {
    if (ws.readyState === ws.OPEN) ws.send("eof");
  });
  socket.on("error", (e) => {
    log(`ERROR  tcp ${host}:${port}: ${e.code ?? e.message}`);
    if (ws.readyState === ws.OPEN) ws.close(CLOSE_UNREACHABLE, e.code ?? "error");
    shut();
  });
  socket.on("close", shut);

  ws.on("message", (data, isBinary) => {
    if (!isBinary) {
      if (String(data) === "shutdown") socket.end();
      return;
    }
    sent += data.length;
    socket.write(data);
  });
  ws.on("close", shut);
}

function relayUdp(ws) {
  // Datagram frames are `ipv4:4, port:2 (big endian), payload` in both
  // directions, so one relayed socket serves every destination the guest
  // sends to — as a real UDP socket does.
  openSockets += 1;
  const socket = createSocket("udp4");
  let sent = 0;
  let received = 0;
  log("ALLOW  udp endpoint opened");

  let closed = false;
  const shut = () => {
    if (closed) return;
    closed = true;
    openSockets -= 1;
    log(`CLOSE  udp endpoint (${sent} B out, ${received} B in)`);
    try {
      socket.close();
    } catch {
      // Already closed.
    }
    if (ws.readyState === ws.OPEN) ws.close();
  };

  socket.on("message", (payload, from) => {
    received += payload.length;
    const frame = Buffer.alloc(6 + payload.length);
    for (const [i, part] of from.address.split(".").entries()) frame[i] = Number(part);
    frame.writeUInt16BE(from.port, 4);
    payload.copy(frame, 6);
    if (ws.readyState === ws.OPEN) ws.send(frame);
  });
  socket.on("error", (e) => {
    log(`ERROR  udp: ${e.code ?? e.message}`);
    shut();
  });
  socket.bind();

  ws.on("message", async (data, isBinary) => {
    if (!isBinary || data.length < 6) return;
    const frame = Buffer.from(data);
    const host = `${frame[0]}.${frame[1]}.${frame[2]}.${frame[3]}`;
    const port = frame.readUInt16BE(4);
    const rule = await permit(host, port);
    if (!rule) {
      log(`REFUSED udp ${host}:${port} (no rule)`);
      // The datagram is dropped, as a filtered network drops it. The guest's
      // own timeout is what tells it nothing came back.
      return;
    }
    sent += frame.length - 6;
    log(`ALLOW  udp ${host}:${port} via ${rule.rule} (${frame.length - 6} B)`);
    socket.send(frame.subarray(6), port, host);
  });
  ws.on("close", shut);
}

server.listen(options.port, options.bind, () => {
  // Report the port actually bound, so `--port 0` is usable by a caller that
  // parses this line.
  log(`webTOS gateway on ws://${options.bind}:${server.address().port}`);
  if (rules.length === 0) {
    log("POLICY no --allow rules: every destination will be refused");
  } else {
    for (const rule of rules) log(`POLICY allow ${rule.rule}`);
  }
  log(
    options.origins.length > 0
      ? `POLICY origins ${options.origins.join(", ")}`
      : "POLICY origins http(s)://localhost:* and http(s)://127.0.0.1:*",
  );
  if (options.bind !== "127.0.0.1" && options.bind !== "localhost") {
    log(`POLICY WARNING bound to ${options.bind}: reachable beyond this machine`);
  }
});
