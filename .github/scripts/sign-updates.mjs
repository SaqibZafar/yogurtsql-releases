// Signs update files with the updater key, producing the same .sig files as `tauri signer sign
// --app-version`: minisign, Ed25519 over the file's BLAKE2b-512 hash ("ED"), with a trusted
// comment that binds the file name and the app version (the app requires the version).
//
// It runs in the release workflow's signing job, which is the only job that ever sees the
// keys. It uses nothing but Node's own crypto, so no npm package runs anywhere near them.
//
// Usage: node sign-updates.mjs <version> <file>...
// Env:   UPDATER_SIGNING_KEY / UPDATER_SIGNING_KEY_PASSWORD: the key file's contents as
//          `tauri signer generate` writes it (base64 of a minisign secret key) and its password.
//          (TAURI_SIGNING_PRIVATE_KEY / _PASSWORD are accepted too, for local checks.)
//        TRUSTED_PUBKEY: the updater public key built into the app (tauri.conf.json's pubkey).
//          Only a key matching it signs. Without it there must be exactly one key.
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
const hexId = (id) => Buffer.from(id).reverse().toString("hex").toUpperCase();

// --- The secret keys ------------------------------------------------------------------------

/** Decrypts a Tauri/minisign secret key. Returns null with a reason when it can't. */
function unlock(name, raw, password) {
  raw = (raw ?? "").trim();
  // Tauri wraps the minisign key file in one more layer of base64.
  let text = Buffer.from(raw, "base64").toString("utf8");
  if (!text.startsWith("untrusted comment:")) text = raw;
  const keyLine = text.split(/\r?\n/).filter(Boolean)[1];
  if (!keyLine) return { problem: `${name} isn't a minisign secret key.` };
  const box = Buffer.from(keyLine, "base64");
  // sig_alg(2) kdf_alg(2) chk_alg(2) salt(32) opslimit(8) memlimit(8) keynum_sk(104) = 158 bytes
  if (box.length !== 158 || box.subarray(0, 2).toString("latin1") !== "Ed") return { problem: `${name} isn't an Ed25519 minisign secret key.` };
  const kdf = box.subarray(2, 4).toString("latin1");
  const keynum = Buffer.from(box.subarray(54, 158));
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
    const stream = scryptSync(password ?? "", salt, 104, { N, r, p, maxmem: 256 * N * r + 1024 * 1024 });
    for (let i = 0; i < 104; i += 1) keynum[i] ^= stream[i];
  } else if (kdf !== "\0\0") {
    return { problem: `${name} uses an unknown key encryption (${JSON.stringify(kdf)}).` };
  }
  const keyId = keynum.subarray(0, 8);
  const privateKey = createPrivateKey({ key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), keynum.subarray(8, 40)]), format: "der", type: "pkcs8" });
  // The secret key carries its public half; a wrong password yields a key that doesn't match it.
  const publicKey = createPublicKey(privateKey).export({ format: "der", type: "spki" }).subarray(12);
  if (!publicKey.equals(keynum.subarray(40, 72))) return { problem: `${name}_PASSWORD doesn't unlock ${name}.` };
  return { name, keyId, publicKey, privateKey };
}

const candidates = [];
const problems = [];
for (const name of ["UPDATER_SIGNING_KEY", "TAURI_SIGNING_PRIVATE_KEY"]) {
  if (!(process.env[name] ?? "").trim()) continue;
  const key = unlock(name, process.env[name], process.env[`${name}_PASSWORD`]);
  if (key.problem) problems.push(key.problem);
  else candidates.push(key);
}

let chosen;
const trusted = (process.env.TRUSTED_PUBKEY ?? "").trim();
if (trusted) {
  const lines = Buffer.from(trusted, "base64").toString("utf8").split(/\r?\n/).filter(Boolean);
  const pk = Buffer.from(lines[1] ?? "", "base64");
  if (pk.length !== 42 || pk.subarray(0, 2).toString("latin1") !== "Ed") die("TRUSTED_PUBKEY isn't a minisign public key.");
  chosen = candidates.find((k) => k.keyId.equals(pk.subarray(2, 10)) && k.publicKey.equals(pk.subarray(10)));
  if (!chosen) {
    const have = candidates.map((k) => `${k.name} is key ${hexId(k.keyId)}`).concat(problems);
    die(`None of the signing keys is the one installed apps trust (key ${hexId(pk.subarray(2, 10))}). ${have.join(" ") || "No signing key is set."}`);
  }
} else {
  if (problems.length) die(problems.join(" "));
  if (candidates.length !== 1) die(candidates.length ? "More than one signing key is set: set TRUSTED_PUBKEY to choose." : "No signing key is set.");
  chosen = candidates[0];
}
const { keyId, privateKey } = chosen;
console.log(`Signing with ${chosen.name} (key ${hexId(keyId)}).`);

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
