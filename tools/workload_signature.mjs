#!/usr/bin/env node
// Detached Ed25519 signatures for canonical workload in-toto statements.

import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign as ed25519Sign,
  verify as ed25519Verify,
} from "node:crypto";
import { readFile, stat, writeFile } from "node:fs/promises";
import { pathToFileURL } from "node:url";

const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

function publicIdentity(publicKey) {
  const der = publicKey.export({ type: "spki", format: "der" });
  return `sha256:${sha256(der)}`;
}

export async function signStatement(statementPath, privateKeyPath, outputPath) {
  const keyStat = await stat(privateKeyPath);
  if (process.platform !== "win32" && (keyStat.mode & 0o077) !== 0) {
    throw new Error("private signing key must not be accessible to group or other users");
  }
  const statement = await readFile(statementPath);
  const privateKey = createPrivateKey(await readFile(privateKeyPath));
  if (privateKey.asymmetricKeyType !== "ed25519") throw new Error("signing key is not Ed25519");
  const publicKey = createPublicKey(privateKey);
  const document = {
    algorithm: "Ed25519",
    key_id: publicIdentity(publicKey),
    signature: ed25519Sign(null, statement, privateKey).toString("base64"),
    statement_sha256: sha256(statement),
  };
  await writeFile(outputPath, `${JSON.stringify(document, null, 2)}\n`, { flag: "wx", mode: 0o644 });
  return document;
}

export async function verifyStatement(statementPath, signaturePath, publicKeyPath) {
  const statement = await readFile(statementPath);
  const document = JSON.parse(await readFile(signaturePath, "utf8"));
  const publicKey = createPublicKey(await readFile(publicKeyPath));
  if (publicKey.asymmetricKeyType !== "ed25519") throw new Error("verification key is not Ed25519");
  if (document.algorithm !== "Ed25519") throw new Error("signature algorithm is not Ed25519");
  if (document.key_id !== publicIdentity(publicKey)) throw new Error("signature key id is not trusted");
  if (document.statement_sha256 !== sha256(statement)) throw new Error("statement digest mismatch");
  const signature = Buffer.from(document.signature, "base64");
  if (!ed25519Verify(null, statement, publicKey, signature)) throw new Error("invalid Ed25519 signature");
  return document;
}

async function main() {
  const [command, statement, key, signature] = process.argv.slice(2);
  if (!command || !statement || !key || !signature || !["sign", "verify"].includes(command)) {
    console.error(
      "usage: workload_signature.mjs sign <statement> <private-key.pem> <signature.json>\n" +
      "       workload_signature.mjs verify <statement> <public-key.pem> <signature.json>",
    );
    process.exit(2);
  }
  if (command === "sign") {
    const result = await signStatement(statement, key, signature);
    console.log(`signed ${result.statement_sha256} with ${result.key_id}`);
  } else {
    const result = await verifyStatement(statement, signature, key);
    console.log(`verified ${result.statement_sha256} with ${result.key_id}`);
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    console.error(error.message);
    process.exit(1);
  });
}
