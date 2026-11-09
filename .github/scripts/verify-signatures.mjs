// Checks every update signature in a folder the way the app's updater will: against the
// public key in the source's tauri.conf.json, and with the version the signature was made for.
// A build signed with any other key, or for another version, fails here instead of reaching
// users, whose apps would refuse the update.
//
// Usage: node verify-signatures.mjs <folder> <tauri.conf.json> <version>
import { createHash, createPublicKey, verify } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";

const [dir, confPath, version] = process.argv.slice(2);
if (!version) {
  console.error("usage: node verify-signatures.mjs <folder> <tauri.conf.json> <version>");
  process.exit(2);
}
const lines = (b64) => Buffer.from(b64.trim(), "base64").toString("utf8").split(/\r?\n/).filter(Boolean);
const conf = JSON.parse(readFileSync(confPath, "utf8"));
const pk = Buffer.from(lines(conf.plugins.updater.pubkey)[1], "base64");
const key = createPublicKey({ key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), pk.subarray(10)]), format: "der", type: "spki" });

const sigs = readdirSync(dir).filter((f) => f.endsWith(".sig"));
if (sigs.length === 0) {
  console.log("::error::No .sig files: the build made no update bundles.");
  process.exit(1);
}
let failed = false;
for (const sigName of sigs) {
  const file = sigName.slice(0, -".sig".length);
  const s = lines(readFileSync(path.join(dir, sigName), "utf8"));
  const sig = Buffer.from(s[1] ?? "", "base64");
  const trusted = (s[2] ?? "").replace(/^trusted comment: /, "");
  const data = readFileSync(path.join(dir, file));
  const message = sig.subarray(0, 2).toString() === "ED" ? createHash("blake2b512").update(data).digest() : data;
  const signedVersion = trusted.split("\t").find((f) => f.startsWith("version:"))?.slice("version:".length);
  let problem = null;
  if (sig.length !== 74) problem = "the signature is malformed";
  else if (!sig.subarray(2, 10).equals(pk.subarray(2, 10))) problem = "it was signed with a different key than the one the app trusts";
  else if (!verify(null, message, key, sig.subarray(10))) problem = "the signature doesn't match the file";
  else if (!verify(null, Buffer.concat([sig.subarray(10), Buffer.from(trusted)]), key, Buffer.from(s[3] ?? "", "base64"))) problem = "the trusted comment's signature doesn't match";
  else if (signedVersion !== version) problem = `it was signed for version ${signedVersion ?? "(none)"}, not ${version}`;
  if (problem) {
    console.log(`::error::${file}: ${problem}.`);
    failed = true;
  } else {
    console.log(`signature verified: ${file} (version ${signedVersion})`);
  }
}
process.exit(failed ? 1 : 0);
