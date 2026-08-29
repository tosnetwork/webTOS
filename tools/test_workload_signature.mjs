#!/usr/bin/env node

import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { chmod, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { signStatement, verifyStatement } from "./workload_signature.mjs";

const root = await mkdtemp(join(tmpdir(), "webtos-signature-"));
const statement = join(root, "statement.json");
const privatePath = join(root, "private.pem");
const publicPath = join(root, "public.pem");
const signature = join(root, "statement.sig.json");
const { privateKey, publicKey } = generateKeyPairSync("ed25519");
await writeFile(statement, '{"subject":"workload"}\n');
await writeFile(privatePath, privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });
await chmod(privatePath, 0o600);
await writeFile(publicPath, publicKey.export({ type: "spki", format: "pem" }));
await signStatement(statement, privatePath, signature);
await verifyStatement(statement, signature, publicPath);

await writeFile(statement, '{"subject":"tampered"}\n');
await assert.rejects(
  verifyStatement(statement, signature, publicPath),
  /statement digest mismatch/,
);
assert.match(await readFile(signature, "utf8"), /"algorithm": "Ed25519"/);
console.log("[workload-signature] PASS");
