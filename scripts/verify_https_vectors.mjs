// Independent Web Crypto verification of the language-neutral protocol fixture.
// Requires Node >=20; no npm dependencies or Go code are used.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { webcrypto } from 'node:crypto';

const v = JSON.parse(await readFile(new URL('../internal/remote/testdata/https.json', import.meta.url), 'utf8'));
const { subtle } = webcrypto;
const pub = await subtle.importKey('raw', Buffer.from(v.PublicKey, 'base64'), 'Ed25519', false, ['verify']);
const digest = Buffer.from(await subtle.digest('SHA-256', Buffer.from(v.Body))).toString('base64');
assert.equal(v.ContentDigest, `sha-256=:${digest}:`);
const params = v.SignatureInput.slice('agentssh='.length);
const base = `"@method": ${v.Method}\n"@target-uri": ${v.Target}\n"content-digest": ${v.ContentDigest}\n"@signature-params": ${params}`;
assert.equal(base, v.SignatureBase);
assert(await subtle.verify('Ed25519', pub, Buffer.from(v.Signature.slice('agentssh=:'.length, -1), 'base64'), Buffer.from(base)));
assert(await subtle.verify('Ed25519', pub, Buffer.from(v.BundleSignature, 'base64'), Buffer.concat([Buffer.from('agentssh-bundle\0'), Buffer.from(v.Bundle)])));
assert(await subtle.verify('Ed25519', pub, Buffer.from(v.SSHSignature, 'base64'), Buffer.from(v.SSHUserauth, 'base64')));
assert.equal(await subtle.verify('Ed25519', pub, Buffer.from(v.SSHSignature, 'base64'), Buffer.from('arbitrary data')), false);
console.log('HTTPS request, bundle and SSH fixtures verified with Web Crypto');
