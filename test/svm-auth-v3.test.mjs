import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  authSignBytes, authSignBytesV3, resolveSvmAuthVersion, SVM_AUTH_CHAIN_BOUND_FEATURE,
  buildPhantomSvmEnvelope, base58Encode,
} from '../src/index.js';

// Generated from x/svm/types SVMAuthSignBytes / SVMAuthSignBytesV3 (Go).
const vectors = JSON.parse(readFileSync(new URL('./fixtures/svm-auth-v3-vectors.json', import.meta.url)));

const hex = (h) => Uint8Array.from(h.match(/../g) ?? [], (x) => parseInt(x, 16));
const toHex = (b) => Buffer.from(b).toString('hex');

function inputs(c) {
  return {
    chainId: c.chain_id,
    programId: base58Encode(hex(c.program_id_hex)),
    accounts: c.accounts.map((a) => ({ pubkey: base58Encode(hex(a.address_hex)), isSigner: a.is_signer, isWritable: a.is_writable })),
    data: hex(c.data_hex),
    recentBlockhashHex: c.recent_blockhash_hex,
  };
}

test('vectors cover several cases', () => {
  assert.ok(vectors.cases.length >= 5);
});

for (const c of vectors.cases) {
  test(`v2 digest matches Go: ${c.name}`, async () => {
    assert.equal(toHex(await authSignBytes(inputs(c))), c.v2_digest_hex);
  });
  test(`v3 digest matches Go: ${c.name}`, async () => {
    assert.equal(toHex(await authSignBytesV3(inputs(c))), c.v3_digest_hex);
  });
}

test('v3 binds the chain id', async () => {
  const c = vectors.cases[0];
  const a = await authSignBytesV3(inputs(c));
  const b = await authSignBytesV3({ ...inputs(c), chainId: 'qorechain-vladi' });
  assert.notEqual(toHex(a), toHex(b));
});

test('v3 requires a chain id', async () => {
  const { chainId, ...rest } = inputs(vectors.cases[0]);
  await assert.rejects(authSignBytesV3(rest), /chainId is required/);
  await assert.rejects(authSignBytesV3({ ...rest, chainId: '' }), /chainId is required/);
});

const featuresFetch = (features, { ok = true, status = 200 } = {}) => {
  const calls = [];
  const fetch = async (url) => {
    calls.push(url);
    return { ok, status, json: async () => ({ features }) };
  };
  return { fetch, calls };
};

test('resolveSvmAuthVersion: v3 when the feature is enabled', async () => {
  const { fetch, calls } = featuresFetch([{ name: 'pqc-sign-bytes-v2', enabled: true }, { name: SVM_AUTH_CHAIN_BOUND_FEATURE, enabled: true }]);
  assert.equal(await resolveSvmAuthVersion({ rest: 'https://lcd.example/', fetch }), 'v3');
  assert.deepEqual(calls, ['https://lcd.example/qorechain/pqc/v1/protocol_features']);
});

test('resolveSvmAuthVersion: v2 when the feature is absent or disabled', async () => {
  assert.equal(await resolveSvmAuthVersion({ rest: 'https://x', fetch: featuresFetch([{ name: 'pqc-sign-bytes-v2', enabled: true }]).fetch }), 'v2');
  assert.equal(await resolveSvmAuthVersion({ rest: 'https://x', fetch: featuresFetch([{ name: SVM_AUTH_CHAIN_BOUND_FEATURE, enabled: false }]).fetch }), 'v2');
  assert.equal(await resolveSvmAuthVersion({ rest: 'https://x', fetch: featuresFetch([{ name: SVM_AUTH_CHAIN_BOUND_FEATURE, enabled: 'false' }]).fetch }), 'v2');
  assert.equal(await resolveSvmAuthVersion({ rest: 'https://x', fetch: featuresFetch([]).fetch }), 'v2');
});

test('resolveSvmAuthVersion: never guesses when the list cannot be read', async () => {
  await assert.rejects(resolveSvmAuthVersion({}), /without asking the network/);
  await assert.rejects(resolveSvmAuthVersion({ rest: 'https://x', fetch: featuresFetch([], { ok: false, status: 501 }).fetch }), /HTTP 501/);
  await assert.rejects(resolveSvmAuthVersion({ rest: 'https://x', fetch: featuresFetch(undefined).fetch }), /no feature list/);
  await assert.rejects(resolveSvmAuthVersion({ rest: 'https://x', fetch: featuresFetch(['x']).fetch }), /invalid entry/);
  await assert.rejects(resolveSvmAuthVersion({ rest: 'https://x', fetch: featuresFetch([{ name: SVM_AUTH_CHAIN_BOUND_FEATURE, enabled: 'yes' }]).fetch }), /invalid enabled value/);
  await assert.rejects(resolveSvmAuthVersion({ rest: 'https://x', fetch: async () => { throw new Error('offline'); } }), /offline/);
});

test('resolveSvmAuthVersion: explicit versions need no request', async () => {
  const fetch = async () => { throw new Error('must not be called'); };
  assert.equal(await resolveSvmAuthVersion({ svmAuthVersion: 'v2', fetch }), 'v2');
  assert.equal(await resolveSvmAuthVersion({ svmAuthVersion: 'v3', fetch }), 'v3');
  await assert.rejects(resolveSvmAuthVersion({ svmAuthVersion: 'v1' }), /must be 'auto', 'v2' or 'v3'/);
});

function recordingWallet() {
  const signed = [];
  return {
    signed,
    publicKey: { toBytes: () => new Uint8Array(32).fill(9) },
    signMessage: async (m) => { signed.push(toHex(m)); return { signature: new Uint8Array(64) }; },
  };
}

test('buildPhantomSvmEnvelope signs the form the network enables', async () => {
  const c = vectors.cases[0];
  const { chainId, ...p } = inputs(c);

  const w3 = recordingWallet();
  await buildPhantomSvmEnvelope({ wallet: w3, ...p, chainId, rest: 'https://x', fetch: featuresFetch([{ name: SVM_AUTH_CHAIN_BOUND_FEATURE, enabled: true }]).fetch });
  assert.deepEqual(w3.signed, [c.v3_digest_hex]);

  const w2 = recordingWallet();
  await buildPhantomSvmEnvelope({ wallet: w2, ...p, chainId, rest: 'https://x', fetch: featuresFetch([]).fetch });
  assert.deepEqual(w2.signed, [c.v2_digest_hex]);

  const wx = recordingWallet();
  await buildPhantomSvmEnvelope({ wallet: wx, ...p, chainId, svmAuthVersion: 'v3' });
  assert.deepEqual(wx.signed, [c.v3_digest_hex]);
});

test('buildPhantomSvmEnvelope refuses to sign without knowing the form', async () => {
  const { chainId, ...p } = inputs(vectors.cases[0]);
  const w = recordingWallet();
  await assert.rejects(buildPhantomSvmEnvelope({ wallet: w, ...p, chainId }), /without asking the network/);
  await assert.rejects(buildPhantomSvmEnvelope({ wallet: w, ...p, svmAuthVersion: 'v3' }), /chainId is required/);
  assert.equal(w.signed.length, 0);
});
