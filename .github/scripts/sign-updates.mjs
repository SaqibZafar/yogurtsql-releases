// Signs update files with the updater key, producing the same .sig files as `tauri signer sign
// --app-version`: minisign, Ed25519 over the file's BLAKE2b-512 hash ("ED"), with a trusted
// comment that binds the file name and the app version (the app requires the version).
//
// It runs in the release workflow's signing job, which is the only job that ever sees the
// key. It uses nothing but Node's own crypto, so no npm package runs anywhere near the key.
//
// Usage: node sign-updates.mjs <version> <file>...
// Env:   TAURI_SIGNING_PRIVATE_KEY           the key file's contents, as `tauri signer generate`
//                                            writes it (base64 of a minisign secret key)
//        TAURI_SIGNING_PRIVATE_KEY_PASSWORD  its password (empty for an unencrypted key)
import { createHash, createPrivateKey, createPublicKey, scryptSync, sign } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import path from "node:path";

const [version, ...files] = process.argv.slice(2);
if (!/^\d+\.\d+\.\d+$/.test(version ?? "") || files.length === 0) {
  console.error("usage: node sign-updates.mjs <version> <file>...");
  process.exit(2);
}
const die = (message) => {
  console.log(`::error::${message}`);
  process.exit(1);
};

// --- The secret key ---------------------------------------------------------------------------

const raw = (process.env.TAURI_SIGNING_PRIVATE_KEY ?? "").trim();
if (!raw) die("TAURI_SIGNING_PRIVATE_KEY isn't set.");
// Tauri wraps the minisign key file in one more layer of base64.
let text = Buffer.from(raw, "base64").toString("utf8");
if (!text.startsWith("untrusted comment:")) text = raw;
const keyLine = text.split(/\r?\n/).filter(Boolean)[1];
if (!keyLine) die("TAURI_SIGNING_PRIVATE_KEY isn't a minisign secret key.");
const box = Buffer.from(keyLine, "base64");
// sig_alg(2) kdf_alg(2) chk_alg(2) salt(32) opslimit(8) memlimit(8) keynum_sk(104) = 158 bytes
if (box.length !== 158 || box.subarray(0, 2).toString("latin1") !== "Ed") die("TAURI_SIGNING_PRIVATE_KEY isn't an Ed25519 minisign secret key.");
const kdf = box.subarray(2, 4).toString("latin1");
let keynum = Buffer.from(box.subarray(54, 158));
if (kdf === "Sc") {
  const salt = box.subarray(6, 38);
  const opslimit = Number(box.readBigUInt64LE(38));
  const memlimit = Number(box.readBigUInt64LE(46));
  // libsodium's crypto_pwhash_scryptsalsa208sha256 turns opslimit/memlimit into N, r, p like this.
  const r = 8;
  const ops = Math.max(opslimit, 32768);
  let nLog2 = 1;
  let p;
  if (ops < memlimit / 32) {
    p = 1;
    const maxN = ops / (r * 4);
    for (nLog2 = 1; nLog2 < 63; nLog2 += 1) if (2 ** nLog2 > maxN / 2) break;
  } else {
    const maxN = memlimit / (r * 128);
    for (nLog2 = 1; nLog2 < 63; nLog2 += 1) if (2 ** nLog2 > maxN / 2) break;
    const maxrp = Math.min(Math.floor(ops / 4 / 2 ** nLog2), 0x3fffffff);
    p = Math.floor(maxrp / r);
  }
  const N = 2 ** nLog2;
  const stream = scryptSync(process.env.TAURI_SIGNING_PRIVATE_KEY_PASSWORD ?? "", salt, 104, { N, r, p, maxmem: 256 * N * r + 1024 * 1024 });
  for (let i = 0; i < 104; i += 1) keynum[i] ^= stream[i];
} else if (kdf !== "\0\0") {
  die(`TAURI_SIGNING_PRIVATE_KEY uses an unknown key encryption (${JSON.stringify(kdf)}).`);
}
const keyId = keynum.subarray(0, 8);
const seed = keynum.subarray(8, 40);
const privateKey = createPrivateKey({ key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]), format: "der", type: "pkcs8" });
// The secret key carries its public half; a wrong password yields a key that doesn't match it.
const spki = createPublicKey(privateKey).export({ format: "der", type: "spki" }).subarray(12);
if (!spki.equals(keynum.subarray(40, 72))) die("TAURI_SIGNING_PRIVATE_KEY_PASSWORD doesn't unlock TAURI_SIGNING_PRIVATE_KEY.");

// --- Signing ----------------------------------------------------------------------------------

// SIGN_TIMESTAMP is only for comparing output byte for byte with `tauri signer sign`.
const timestamp = /^\d+$/.test(process.env.SIGN_TIMESTAMP ?? "") ? Number(process.env.SIGN_TIMESTAMP) : Math.floor(Date.now() / 1000);
for (const file of files) {
  const name = path.basename(file);
  if (/[\t\r\n]/.test(name)) die(`${name}: a file name can't contain tabs or line breaks.`);
  const digest = createHash("blake2b512").update(readFileSync(file)).digest();
  const signature = sign(null, digest, privateKey);
  const trusted = `timestamp:${timestamp}\tfile:${name}\tversion:${version}`;
  const globalSignature = sign(null, Buffer.concat([signature, Buffer.from(trusted)]), privateKey);
  const minisign = [
    "untrusted comment: signature from tauri secret key",
    Buffer.concat([Buffer.from("ED"), keyId, signature]).toString("base64"),
    `trusted comment: ${trusted}`,
    globalSignature.toString("base64"),
    "",
  ].join("\n");
  writeFileSync(`${file}.sig`, Buffer.from(minisign).toString("base64"));
  console.log(`signed ${name}`);
}
console.log(`Key ${Buffer.from(keyId).reverse().toString("hex").toUpperCase()}, version ${version}.`);
