import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  getQorexNative, hasQorexSignAndBroadcast, connectQorex,
  validateQorexRequest, qorexSignAndBroadcast, isQorexRejection,
  QOREX_MAX_MESSAGES, QOREX_MAX_MEMO_BYTES, QOREX_MIN_GAS_LIMIT, QOREX_MAX_GAS_LIMIT,
} from '../src/index.js';

const CHAIN = 'qorechain-vladi';
const MSG = { typeUrl: '/cosmos.bank.v1beta1.MsgSend', value: new Uint8Array([1, 2, 3]) };

/** A stand-in for the injected provider, recording what the wallet is asked. */
function fakeQorex({ capabilities = ['signAndBroadcast'], result, throws } = {}) {
  const calls = { enable: [], signAndBroadcast: [] };
  return {
    calls,
    capabilities,
    async enable(chainId) { calls.enable.push(chainId); },
    async signAndBroadcast(req) {
      calls.signAndBroadcast.push(req);
      if (throws) throw throws;
      return result ?? { txHash: 'ABC', code: 0, height: 10, shield: null };
    },
  };
}

test('getQorexNative reads window.qorex.native and tolerates its absence', () => {
  assert.equal(getQorexNative(), undefined);
  globalThis.window = { qorex: { native: { marker: true } } };
  assert.deepEqual(getQorexNative(), { marker: true });
  delete globalThis.window;
});

test('hasQorexSignAndBroadcast distinguishes absent, old and current QoreX', () => {
  assert.equal(hasQorexSignAndBroadcast(undefined), false);
  assert.equal(hasQorexSignAndBroadcast({ capabilities: ['signDirect'] }), false);
  assert.equal(hasQorexSignAndBroadcast({}), false);
  assert.equal(hasQorexSignAndBroadcast(fakeQorex()), true);
});

test('connectQorex explains an absent wallet and an out-of-date one differently', async () => {
  await assert.rejects(
    () => connectQorex({ chainId: CHAIN }),
    /window\.qorex\.native is undefined/,
  );
  await assert.rejects(
    () => connectQorex({ chainId: CHAIN, provider: fakeQorex({ capabilities: ['signDirect'] }) }),
    /Update QoreX \(extension >= 0\.3\.5, app >= 1\.1\.5\)/,
  );
});

test('connectQorex enables the chain and returns the provider', async () => {
  const p = fakeQorex();
  assert.equal(await connectQorex({ chainId: CHAIN, provider: p }), p);
  assert.deepEqual(p.calls.enable, [CHAIN]);
});

test('a request is validated before the wallet ever prompts', () => {
  const ok = validateQorexRequest({ chainId: CHAIN, messages: [MSG], memo: 'hi', gasLimit: 300000 });
  assert.deepEqual(ok, { chainId: CHAIN, messages: [MSG], memo: 'hi', gasLimit: 300000 });

  // The wallet's active network is the wallet's to choose.
  assert.throws(() => validateQorexRequest({ chainId: 'cosmoshub-4', messages: [MSG] }),
    /chainId must be one of qorechain-vladi, qorechain-diana/);
  assert.throws(() => validateQorexRequest({ chainId: CHAIN, messages: [] }), /non-empty array/);
  assert.throws(
    () => validateQorexRequest({ chainId: CHAIN, messages: Array(QOREX_MAX_MESSAGES + 1).fill(MSG) }),
    new RegExp(`at most ${QOREX_MAX_MESSAGES} messages`),
  );
});

test('the three byte shapes QoreX accepts are accepted, and others are refused', () => {
  const bytes = validateQorexRequest({ chainId: CHAIN, messages: [MSG] }).messages[0].value;
  assert.ok(bytes instanceof Uint8Array);

  const fromArray = validateQorexRequest({
    chainId: CHAIN, messages: [{ typeUrl: MSG.typeUrl, value: [1, 2, 3] }],
  }).messages[0].value;
  assert.deepEqual(Array.from(fromArray), [1, 2, 3]);

  // base64 passes through verbatim — the wallet signs the bytes as given.
  const b64 = validateQorexRequest({
    chainId: CHAIN, messages: [{ typeUrl: MSG.typeUrl, value: 'AQID' }],
  }).messages[0].value;
  assert.equal(b64, 'AQID');

  // A decoded message object is the mistake worth catching: it would encode to
  // nothing useful, and the error names the fix.
  assert.throws(
    () => validateQorexRequest({ chainId: CHAIN, messages: [{ typeUrl: MSG.typeUrl, value: { amount: 1 } }] }),
    /must be protobuf bytes .* Encode the message first/s,
  );
});

test('PQC key management is refused locally, with the reason', () => {
  for (const typeUrl of [
    '/qorechain.pqc.v1.MsgRegisterPQCKey',
    '/qorechain.pqc.v1.MsgRegisterPQCKeyV2',
    '/qorechain.pqc.v1.MsgMigratePQCKey',
    '/qorechain.pqc.v1.MsgRotatePQCKey',
  ]) {
    assert.throws(
      () => validateQorexRequest({ chainId: CHAIN, messages: [{ typeUrl, value: new Uint8Array() }] }),
      /QoreX manages the account's post-quantum key itself/,
      typeUrl,
    );
  }
  assert.throws(
    () => validateQorexRequest({
      chainId: CHAIN,
      messages: [{ typeUrl: '/cosmos.authz.v1beta1.MsgExec', value: new Uint8Array() }],
    }),
    /refused by the wallet/,
  );
});

test('memo and gasLimit are bounded the way the wallet bounds them', () => {
  assert.throws(
    () => validateQorexRequest({ chainId: CHAIN, messages: [MSG], memo: 'x'.repeat(QOREX_MAX_MEMO_BYTES + 1) }),
    /memo must be at most 256 bytes/,
  );
  // Counted in BYTES, not characters: 100 emoji are 400 bytes.
  assert.throws(
    () => validateQorexRequest({ chainId: CHAIN, messages: [MSG], memo: '😀'.repeat(100) }),
    /at most 256 bytes, got 400/,
  );
  assert.throws(
    () => validateQorexRequest({ chainId: CHAIN, messages: [MSG], gasLimit: QOREX_MIN_GAS_LIMIT - 1 }),
    /gasLimit must be between/,
  );
  assert.throws(
    () => validateQorexRequest({ chainId: CHAIN, messages: [MSG], gasLimit: QOREX_MAX_GAS_LIMIT + 1 }),
    /gasLimit must be between/,
  );
  assert.throws(
    () => validateQorexRequest({ chainId: CHAIN, messages: [MSG], gasLimit: 1.5 }),
    /gasLimit must be an integer/,
  );
  // Omitted gasLimit stays omitted, so the wallet applies its own default.
  assert.equal('gasLimit' in validateQorexRequest({ chainId: CHAIN, messages: [MSG] }), false);
});

test('qorexSignAndBroadcast connects, forwards the request and returns the result', async () => {
  const p = fakeQorex({ result: { txHash: 'DEAD', code: 0, height: 42, shield: 'ok' } });
  const res = await qorexSignAndBroadcast({
    chainId: CHAIN, messages: [MSG], memo: 'm', gasLimit: 200000, provider: p,
  });
  assert.deepEqual(res, { txHash: 'DEAD', code: 0, height: 42, shield: 'ok' });
  assert.deepEqual(p.calls.enable, [CHAIN]);
  assert.deepEqual(p.calls.signAndBroadcast, [
    { chainId: CHAIN, messages: [MSG], memo: 'm', gasLimit: 200000 },
  ]);
});

test('an invalid request never reaches the wallet', async () => {
  const p = fakeQorex();
  await assert.rejects(
    () => qorexSignAndBroadcast({ chainId: CHAIN, messages: [], provider: p }),
    /non-empty array/,
  );
  assert.equal(p.calls.signAndBroadcast.length, 0);
});

test('a user rejection is distinguishable from a failure', async () => {
  const p = fakeQorex({ throws: new Error('QoreX: signature rejected') });
  await assert.rejects(
    () => qorexSignAndBroadcast({ chainId: CHAIN, messages: [MSG], provider: p }),
    (e) => isQorexRejection(e),
  );
  assert.equal(isQorexRejection(new Error('insufficient funds')), false);
  assert.equal(isQorexRejection(undefined), false);
  assert.equal(isQorexRejection('User rejected the request'), true);
});

// ─── the withdrawn signature-derived PQC key ────────────────────────────────

test('derivePqcKeyFromWallet refuses, and the message names the replacement', async () => {
  const { derivePqcKeyFromWallet } = await import('../src/index.js');
  await assert.rejects(
    () => derivePqcKeyFromWallet({}, 'qorechain-vladi', 'qor1abc'),
    /withdrawn in @qorechain\/wallet-adapter 0\.3\.0/,
  );
  await assert.rejects(
    () => derivePqcKeyFromWallet({}, 'qorechain-vladi', 'qor1abc'),
    /qorexSignAndBroadcast/,
  );
});

test('derivePqcKeyFromWallet never asks the wallet for a signature', async () => {
  const { derivePqcKeyFromWallet } = await import('../src/index.js');
  let asked = 0;
  const wallet = { signArbitrary: async () => { asked += 1; return { signature: 'AA==' }; } };
  await assert.rejects(() => derivePqcKeyFromWallet(wallet, 'qorechain-vladi', 'qor1abc'));
  assert.equal(asked, 0, 'the withdrawn function must not prompt the wallet');
});



// ─── rotating OFF a key minted by the withdrawn derivation ──────────────────

import { mldsa, shake256 } from '@qorechain/pqc';

const SIG_B64 = Buffer.from(new Uint8Array(64).fill(3)).toString('base64');
const legacyWallet = () => ({ signArbitrary: async () => ({ signature: SIG_B64 }) });
const legacyKey = () => mldsa.keygen(shake256(new Uint8Array(64).fill(3), 32));

test('the legacy derivation is no longer exported under any name', async () => {
  const m = await import('../src/index.js');
  assert.equal(m.deriveLegacyWalletSignatureKey, undefined);
  assert.equal(m.legacyWalletSignatureKey, undefined);
});

test('rotateFromLegacyWalletKey builds a valid rotation and never returns the old secret', async () => {
  const { rotateFromLegacyWalletKey, rotationSignBytes } = await import('../src/index.js');
  const legacy = legacyKey();
  const fresh = mldsa.keygen(new Uint8Array(32).fill(9));
  const msg = await rotateFromLegacyWalletKey({
    wallet: legacyWallet(), chainId: 'qorechain-vladi', address: 'qor1abc',
    registeredPublicKey: legacy.publicKey, newKeypair: fresh,
  });
  assert.equal(msg.typeUrl, '/qorechain.pqc.v1.MsgRotatePQCKey');
  const v = msg.value;
  assert.deepEqual(Buffer.from(v.oldPublicKey), Buffer.from(legacy.publicKey));
  assert.deepEqual(Buffer.from(v.newPublicKey), Buffer.from(fresh.publicKey));
  const bytes = new TextEncoder().encode(
    rotationSignBytes('qorechain-vladi', 1, 'qor1abc', legacy.publicKey, fresh.publicKey));
  assert.equal(mldsa.verify(legacy.publicKey, bytes, v.oldSignature), true, 'old key proves ownership');
  assert.equal(mldsa.verify(fresh.publicKey, bytes, v.newSignature), true, 'new key proves control');
  assert.equal(JSON.stringify(Object.keys(v)).includes('secret'), false, 'no secret leaves the call');
});

test('rotateFromLegacyWalletKey refuses for a key it did not mint, so it cannot create one', async () => {
  const { rotateFromLegacyWalletKey } = await import('../src/index.js');
  const someoneElse = mldsa.keygen(new Uint8Array(32).fill(5));
  await assert.rejects(
    () => rotateFromLegacyWalletKey({
      wallet: legacyWallet(), chainId: 'qorechain-vladi', address: 'qor1abc',
      registeredPublicKey: someoneElse.publicKey, newKeypair: mldsa.keygen(new Uint8Array(32).fill(9)),
    }),
    /was not minted by the withdrawn wallet-signature derivation/,
  );
});

test('rotateFromLegacyWalletKey takes the registered key in the base64 form the chain reports', async () => {
  const { rotateFromLegacyWalletKey } = await import('../src/index.js');
  const legacy = legacyKey();
  const msg = await rotateFromLegacyWalletKey({
    wallet: legacyWallet(), chainId: 'qorechain-vladi', address: 'qor1abc',
    registeredPublicKey: Buffer.from(legacy.publicKey).toString('base64'),
    newKeypair: mldsa.keygen(new Uint8Array(32).fill(9)),
  });
  assert.equal(msg.value.oldPublicKey.length, 2592);
});

test('rotateFromLegacyWalletKey refuses to rotate onto the same key', async () => {
  const { rotateFromLegacyWalletKey } = await import('../src/index.js');
  const legacy = legacyKey();
  await assert.rejects(
    () => rotateFromLegacyWalletKey({
      wallet: legacyWallet(), chainId: 'qorechain-vladi', address: 'qor1abc',
      registeredPublicKey: legacy.publicKey, newKeypair: legacyKey(),
    }),
    /must differ/,
  );
});

// ─── a hex string must never reach a bytes field ───────────────────────────

const MNEMONIC = 'test test test test test test test test test test test junk';

test('walletFromMnemonic().pubkey is a hex string — the shape that broke registration', async () => {
  const { walletFromMnemonic } = await import('../src/index.js');
  const w = await walletFromMnemonic(MNEMONIC);
  assert.equal(typeof w.pubkey, 'string');
  // What the old encoder did with it: 68 bytes, hex letters zeroed.
  assert.equal(Uint8Array.from(w.pubkey).length, 68);
});

test('toExactBytes decodes that string to the real 33-byte key, and refuses a mangled one', async () => {
  const { walletFromMnemonic, toExactBytes } = await import('../src/index.js');
  const w = await walletFromMnemonic(MNEMONIC);
  const key = toExactBytes(w.pubkey, 33, 'pubkey');
  assert.equal(key.length, 33);
  assert.ok(key[0] === 2 || key[0] === 3, 'a compressed secp256k1 key starts 0x02 or 0x03');
  assert.throws(() => toExactBytes(Uint8Array.from(w.pubkey), 33, 'pubkey'), /must be 33 bytes, got 68/);
  assert.throws(() => toExactBytes({ key: 1 }, 33, 'pubkey'), /must be bytes/);
  assert.throws(() => toExactBytes(null, 33, 'pubkey'), /got null/);
  assert.equal(toExactBytes(Buffer.from(key).toString('base64'), 33, 'pubkey').length, 33);
});

test('QoreChainSigner accepts the hex-string pubkey and stores the real bytes', async () => {
  const { walletFromMnemonic, QoreChainSigner } = await import('../src/index.js');
  const w = await walletFromMnemonic(MNEMONIC);
  const s = new QoreChainSigner({
    wallet: {}, chainId: 'qorechain-vladi', address: w.cosmos,
    pubkeySecp256k1: w.pubkey, accountNumber: 1, pqc: w.pqc, signBytesVersion: 'v2',
  });
  assert.ok(s.pubkeySecp256k1 instanceof Uint8Array);
  assert.equal(s.pubkeySecp256k1.length, 33);
  assert.throws(
    () => new QoreChainSigner({
      wallet: {}, chainId: 'qorechain-vladi', address: w.cosmos,
      pubkeySecp256k1: Uint8Array.from(w.pubkey), accountNumber: 1, pqc: w.pqc,
    }),
    /must be 33 bytes, got 68/,
  );
});

test('rotatePqcKeyMsg refuses a key string it would previously have UTF-8-encoded', async () => {
  const { rotatePqcKeyMsg } = await import('../src/index.js');
  assert.throws(
    () => rotatePqcKeyMsg({
      sender: 'qor1abc', oldPublicKey: 'not-a-key', newPublicKey: new Uint8Array(2592),
      oldSignature: new Uint8Array(4627), newSignature: new Uint8Array(4627),
    }),
    /oldPublicKey/,
  );
});
