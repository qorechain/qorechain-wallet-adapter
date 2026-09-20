import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { mldsa } from '@qorechain/pqc';
import { TxRaw, TxBody } from 'cosmjs-types/cosmos/tx/v1beta1/tx.js';
import {
  HYBRID_SIGN_BYTES_V2_DOMAIN, SIGN_BYTES_V2_UPGRADE, SIGN_BYTES_V2_UPGRADES, LEGACY_SIGN_BYTES_CHAINS,
  hybridSignBytesV1, hybridSignBytesV2, hybridSignBytes,
  signBytesVersionFor, resolveSignBytesVersion, clearSignBytesCache,
  isHybridSignBytesRejection, QoreChainSigner, signHybridEth, walletFromSeed,
} from '../src/index.js';
import * as pkg from '../src/index.js';

const here = dirname(fileURLToPath(import.meta.url));
const KAT = JSON.parse(readFileSync(join(here, 'fixtures', 'signbytes-kat-v3.1.98.json'), 'utf8'));
const hb = (s) => Uint8Array.from(Buffer.from(s, 'hex'));
const hx = (b) => Buffer.from(b).toString('hex');
const SEED = hb('8a9bacbdcedff00112233445566778899aabbccddeef00112233445566778899');
const MAIN = 'https://lcd.example/mainnet';
const TEST = 'https://lcd.example/testnet';

// Fake fetch: records calls, answers from a table keyed by URL prefix.
function fakeFetch(table) {
  const calls = [];
  const f = async (url) => {
    calls.push(url);
    for (const [prefix, ans] of Object.entries(table)) {
      if (url.startsWith(prefix)) {
        if (ans instanceof Error) throw ans;
        if (typeof ans === 'number') return { ok: false, status: ans, json: async () => ({}) };
        return { ok: true, status: 200, json: async () => ans };
      }
    }
    throw new Error('unexpected url ' + url);
  };
  f.calls = calls;
  return f;
}

// Fake LCD that answers applied_plan per PLAN NAME: `heights` maps name -> body
// (a number/string height, {} for "no such plan", or an Error/HTTP status to fail).
function planFetch(heights, base = MAIN) {
  const calls = [];
  const f = async (url) => {
    calls.push(url);
    const name = url.slice(url.lastIndexOf('/') + 1);
    const ans = Object.prototype.hasOwnProperty.call(heights, name) ? heights[name] : {};
    if (ans instanceof Error) throw ans;
    if (typeof ans === 'number' && !Number.isInteger(ans)) throw new Error('bad fixture');
    if (typeof ans === 'number') return { ok: false, status: ans, json: async () => ({}) };
    return { ok: true, status: 200, json: async () => (typeof ans === 'string' ? { height: ans } : ans) };
  };
  f.calls = calls;
  f.url = (name) => `${base}/cosmos/upgrade/v1beta1/applied_plan/${name}`;
  return f;
}

beforeEach(() => clearSignBytesCache());

test('constants', () => {
  assert.equal(HYBRID_SIGN_BYTES_V2_DOMAIN, 'qorechain-pqc-hybrid-v2');
  assert.equal(HYBRID_SIGN_BYTES_V2_DOMAIN, KAT.hybrid_domain);
  // The chain registers the same handler under both names (x/pqc/types
  // SignBytesV2Upgrades): mainnet applies "v3.2.0", the testnet already applied "v3.1.98".
  assert.deepEqual([...SIGN_BYTES_V2_UPGRADES], ['v3.2.0', 'v3.1.98']);
  assert.equal(SIGN_BYTES_V2_UPGRADE, 'v3.2.0', 'primary name = the current release');
  assert.equal(SIGN_BYTES_V2_UPGRADE, SIGN_BYTES_V2_UPGRADES[0]);
  assert.deepEqual([...LEGACY_SIGN_BYTES_CHAINS], ['qorechain-vladi', 'qorechain-diana']);
});

test('KAT: every hybrid_v2 vector reproduced byte-exact', () => {
  assert.equal(KAT.hybrid_v2.length, 5);
  for (const v of KAT.hybrid_v2) {
    const b0 = hb(v.body_without_pqc_ext_hex);
    const a = hb(v.auth_info_hex);
    assert.equal(hx(hybridSignBytesV2(v.chain_id, b0, a)), v.sign_bytes_hex, v.name);
    assert.equal(hx(hybridSignBytes('v2', v.chain_id, b0, a)), v.sign_bytes_hex, v.name);
  }
});

test('v1 layout = BE32(len b0) ‖ b0 ‖ BE32(len auth) ‖ auth, no chain-id', () => {
  const out = hybridSignBytesV1(Uint8Array.from([1, 2, 3]), Uint8Array.from([9, 9]));
  assert.deepEqual([...out], [0, 0, 0, 3, 1, 2, 3, 0, 0, 0, 2, 9, 9]);
  assert.deepEqual([...hybridSignBytes('v1', 'qorechain-vladi', Uint8Array.from([1, 2, 3]), Uint8Array.from([9, 9]))], [...out]);
  assert.deepEqual([...hybridSignBytesV1(new Uint8Array(), new Uint8Array())], [0, 0, 0, 0, 0, 0, 0, 0]);
});

test('v2 binds the chain-id and refuses an empty one; dispatcher refuses a missing version', () => {
  const b0 = Uint8Array.from([1]); const a = Uint8Array.from([2]);
  assert.notDeepEqual([...hybridSignBytesV2('chain-a', b0, a)], [...hybridSignBytesV2('chain-b', b0, a)]);
  assert.throws(() => hybridSignBytesV2('', b0, a));
  assert.throws(() => hybridSignBytes(undefined, 'qorechain-vladi', b0, a), /version must be/);
  assert.throws(() => hybridSignBytes('auto', 'qorechain-vladi', b0, a), /version must be/);
  assert.throws(() => hybridSignBytes(b0, a), /version must be/); // old frame(b0, auth) call shape
});

test('no implicit-form frame() export remains', () => {
  assert.equal(pkg.frame, undefined);
});

test('signBytesVersionFor truth table (numeric, "0" is NOT applied)', () => {
  for (const cid of ['qorechain-vladi', 'qorechain-diana']) {
    assert.equal(signBytesVersionFor(cid, 0), 'v1');
    assert.equal(signBytesVersionFor(cid, '0'), 'v1');
    assert.equal(signBytesVersionFor(cid, undefined), 'v1');
    assert.equal(signBytesVersionFor(cid, 5746000), 'v2');
    assert.equal(signBytesVersionFor(cid, '5746000'), 'v2');
    assert.equal(signBytesVersionFor(cid, 5746000n), 'v2');
  }
  assert.equal(signBytesVersionFor('qorechain-other', 0), 'v2');
  assert.equal(signBytesVersionFor('qorechain-other', '5746000'), 'v2');
  assert.throws(() => signBytesVersionFor('qorechain-vladi', 'abc'));
});

test('resolver: {"height":"0"} (truthy string) from EVERY plan -> v1', async () => {
  const f = fakeFetch({ [MAIN]: { height: '0' } });
  assert.equal(await resolveSignBytesVersion({ chainId: 'qorechain-vladi', rest: MAIN, fetch: f }), 'v1');
  assert.deepEqual(f.calls, [
    `${MAIN}/cosmos/upgrade/v1beta1/applied_plan/v3.2.0`,
    `${MAIN}/cosmos/upgrade/v1beta1/applied_plan/v3.1.98`,
  ], 'every known plan name is asked before concluding v1');
});

test('resolver: {} from every plan -> v1', async () => {
  const f = fakeFetch({ [MAIN]: {} });
  assert.equal(await resolveSignBytesVersion({ chainId: 'qorechain-vladi', rest: MAIN, fetch: f }), 'v1');
  assert.equal(f.calls.length, 2);
});

test('resolver: {"height":"5746000"} -> v2', async () => {
  const f = fakeFetch({ [TEST]: { height: '5746000' } });
  assert.equal(await resolveSignBytesVersion({ chainId: 'qorechain-diana', rest: TEST + '/', fetch: f }), 'v2');
  assert.equal(f.calls[0], `${TEST}/cosmos/upgrade/v1beta1/applied_plan/v3.2.0`, 'trailing slash normalised');
});

// --- both plan names (the mainnet-upgrade correctness fix) ---

test('resolver: mainnet plan v3.2.0 applied -> v2 after ONE request (short-circuit)', async () => {
  const f = planFetch({ 'v3.2.0': '9000000', 'v3.1.98': {} });
  assert.equal(await resolveSignBytesVersion({ chainId: 'qorechain-vladi', rest: MAIN, fetch: f }), 'v2');
  assert.deepEqual(f.calls, [f.url('v3.2.0')], 'the later names are not asked once one answered > 0');
});

test('resolver: only the earlier plan v3.1.98 applied (diana) -> v2 after two requests', async () => {
  const f = planFetch({ 'v3.2.0': '0', 'v3.1.98': '5746000' });
  assert.equal(await resolveSignBytesVersion({ chainId: 'qorechain-diana', rest: MAIN, fetch: f }), 'v2');
  assert.deepEqual(f.calls, [f.url('v3.2.0'), f.url('v3.1.98')]);
});

test('resolver: v3.2.0 absent ({}), v3.1.98 applied -> v2 (the live diana shape)', async () => {
  const f = planFetch({ 'v3.2.0': {}, 'v3.1.98': '5746000' });
  assert.equal(await resolveSignBytesVersion({ chainId: 'qorechain-diana', rest: MAIN, fetch: f }), 'v2');
  assert.equal(f.calls.length, 2);
});

test('resolver: both "0" -> v1; both {} -> v1; non-legacy chain still v2 with no HTTP', async () => {
  const zeros = planFetch({ 'v3.2.0': '0', 'v3.1.98': '0' });
  assert.equal(await resolveSignBytesVersion({ chainId: 'qorechain-vladi', rest: MAIN, fetch: zeros }), 'v1');
  assert.deepEqual(zeros.calls, [zeros.url('v3.2.0'), zeros.url('v3.1.98')]);
  clearSignBytesCache();
  const empty = planFetch({ 'v3.2.0': {}, 'v3.1.98': {} });
  assert.equal(await resolveSignBytesVersion({ chainId: 'qorechain-vladi', rest: MAIN, fetch: empty }), 'v1');
  assert.deepEqual(empty.calls, [empty.url('v3.2.0'), empty.url('v3.1.98')]);
  const none = planFetch({});
  assert.equal(await resolveSignBytesVersion({ chainId: 'qorechain-newnet', rest: MAIN, fetch: none }), 'v2');
  assert.equal(none.calls.length, 0);
});

test('resolver: a failure on EITHER plan query throws, never a guess', async () => {
  await assert.rejects(resolveSignBytesVersion({ chainId: 'qorechain-vladi', rest: MAIN,
    fetch: planFetch({ 'v3.2.0': 503, 'v3.1.98': '5746000' }) }), /HTTP 503/);
  clearSignBytesCache();
  const second = planFetch({ 'v3.2.0': '0', 'v3.1.98': new Error('ECONNREFUSED') });
  await assert.rejects(resolveSignBytesVersion({ chainId: 'qorechain-vladi', rest: MAIN, fetch: second }),
    (e) => /ECONNREFUSED/.test(e.message) && /v3\.2\.0/.test(e.message) && /v3\.1\.98/.test(e.message));
  assert.equal(second.calls.length, 2);
  clearSignBytesCache();
  await assert.rejects(resolveSignBytesVersion({ chainId: 'qorechain-vladi', rest: MAIN,
    fetch: planFetch({ 'v3.2.0': '0', 'v3.1.98': { height: 'zzz' } }) }));
});

test('resolver: one answer for both names is cached; forceRefresh re-asks from the first name', async () => {
  const f = planFetch({ 'v3.2.0': '0', 'v3.1.98': '0' });
  assert.equal(await resolveSignBytesVersion({ chainId: 'qorechain-vladi', rest: MAIN, fetch: f }), 'v1');
  assert.equal(f.calls.length, 2);
  assert.equal(await resolveSignBytesVersion({ chainId: 'qorechain-vladi', rest: MAIN, fetch: f }), 'v1', 'cached');
  assert.equal(f.calls.length, 2, 'no further requests within the TTL');
  const g = planFetch({ 'v3.2.0': '9000000' }); // mainnet upgrade lands
  assert.equal(await resolveSignBytesVersion({ chainId: 'qorechain-vladi', rest: MAIN, fetch: g, forceRefresh: true }), 'v2');
  assert.deepEqual(g.calls, [g.url('v3.2.0')]);
});

test('resolver: explicit v1/v2 returned as-is with no HTTP; bad value throws', async () => {
  const f = fakeFetch({});
  assert.equal(await resolveSignBytesVersion({ chainId: 'qorechain-vladi', signBytesVersion: 'v2', fetch: f }), 'v2');
  assert.equal(await resolveSignBytesVersion({ chainId: 'qorechain-diana', signBytesVersion: 'v1', fetch: f }), 'v1');
  assert.equal(f.calls.length, 0);
  await assert.rejects(resolveSignBytesVersion({ chainId: 'qorechain-vladi', signBytesVersion: 'v3', fetch: f }));
});

test('resolver: non-legacy chain -> v2 with no HTTP (even without rest)', async () => {
  const f = fakeFetch({});
  assert.equal(await resolveSignBytesVersion({ chainId: 'qorechain-newnet', fetch: f }), 'v2');
  assert.equal(f.calls.length, 0);
});

test('resolver: legacy chain without rest -> error naming rest / explicit version', async () => {
  await assert.rejects(resolveSignBytesVersion({ chainId: 'qorechain-vladi', fetch: fakeFetch({}) }),
    (e) => /rest/.test(e.message) && /'v1' \| 'v2'/.test(e.message));
});

test('resolver: HTTP failure, network error and bad JSON -> error, never a guess', async () => {
  await assert.rejects(resolveSignBytesVersion({ chainId: 'qorechain-vladi', rest: MAIN, fetch: fakeFetch({ [MAIN]: 503 }) }), /HTTP 503/);
  clearSignBytesCache();
  await assert.rejects(resolveSignBytesVersion({ chainId: 'qorechain-vladi', rest: MAIN, fetch: fakeFetch({ [MAIN]: new Error('ECONNREFUSED') }) }), /ECONNREFUSED/);
  clearSignBytesCache();
  await assert.rejects(resolveSignBytesVersion({ chainId: 'qorechain-vladi', rest: MAIN, fetch: fakeFetch({ [MAIN]: { height: 'zzz' } }) }));
});

test('resolver: cache hit within TTL, per (rest, chainId); forceRefresh and TTL expiry re-query', async () => {
  const table = { [MAIN]: { height: '0' } };
  const f = fakeFetch(table);
  // "not applied" costs one request per plan name; a positive answer short-circuits.
  assert.equal(await resolveSignBytesVersion({ chainId: 'qorechain-vladi', rest: MAIN, fetch: f }), 'v1');
  assert.equal(f.calls.length, 2);
  table[MAIN] = { height: '9000000' }; // network upgrades
  assert.equal(await resolveSignBytesVersion({ chainId: 'qorechain-vladi', rest: MAIN, fetch: f }), 'v1', 'cached');
  assert.equal(f.calls.length, 2, 'no request while the answer is cached');
  assert.equal(await resolveSignBytesVersion({ chainId: 'qorechain-vladi', rest: MAIN, fetch: f, forceRefresh: true }), 'v2');
  assert.equal(f.calls.length, 3);
  // a different rest is a different cache entry
  const g = fakeFetch({ [TEST]: { height: '5746000' } });
  assert.equal(await resolveSignBytesVersion({ chainId: 'qorechain-vladi', rest: TEST, fetch: g }), 'v2');
  assert.equal(g.calls.length, 1);
  // ttlMs = 0 -> always re-query
  await resolveSignBytesVersion({ chainId: 'qorechain-vladi', rest: MAIN, fetch: f, ttlMs: 0 });
  assert.equal(f.calls.length, 4);
  clearSignBytesCache();
  await resolveSignBytesVersion({ chainId: 'qorechain-vladi', rest: MAIN, fetch: f });
  assert.equal(f.calls.length, 5);
});

test('isHybridSignBytesRejection: cosmjs shapes, message text, other codespaces', () => {
  assert.equal(isHybridSignBytesRejection({ code: 21, codespace: 'pqc', log: '' }), true); // BroadcastTxError
  assert.equal(isHybridSignBytesRejection({ code: 21, rawLog: 'hybrid PQC signature verification failed: bad sig' }), true); // DeliverTxResponse
  assert.equal(isHybridSignBytesRejection(new Error('Broadcasting transaction failed with code 21 (codespace: pqc). Log: hybrid PQC signature verification failed')), true);
  assert.equal(isHybridSignBytesRejection({ code: 21, codespace: 'sdk', log: 'tx too large' }), false);
  assert.equal(isHybridSignBytesRejection({ code: 0, rawLog: '' }), false);
  assert.equal(isHybridSignBytesRejection({ code: 5, codespace: 'pqc', log: 'other' }), false);
  assert.equal(isHybridSignBytesRejection(null), false);
  assert.equal(isHybridSignBytesRejection('hybrid PQC signature verification failed'), true);
});

// ---- signer ----

const fakeWallet = { async signDirect() { return { signature: { signature: Buffer.from(new Uint8Array(64).fill(1)).toString('base64') } }; } };
const TX = {
  messages: [{ typeUrl: '/cosmos.bank.v1beta1.MsgSend', value: new Uint8Array([1, 2, 3]) }],
  fee: { amount: [{ denom: 'uqor', amount: '25000' }], gasLimit: 250000n },
  memo: 'sb', sequence: 1,
};
function signer(opts) {
  return new QoreChainSigner({
    wallet: fakeWallet, chainId: 'qorechain-vladi', address: 'qor1x', pubkeySecp256k1: new Uint8Array(33).fill(2),
    accountNumber: 1, pqc: mldsa.keygen(SEED), ...opts,
  });
}
function pqcSigOf(txRaw) {
  const { bodyBytes, authInfoBytes } = TxRaw.decode(txRaw);
  const body = TxBody.decode(bodyBytes);
  const sig = body.extensionOptions[0].value.slice(5);
  const b0 = TxBody.encode(TxBody.fromPartial({ messages: body.messages, memo: body.memo, timeoutHeight: body.timeoutHeight })).finish();
  return { sig, b0, authInfoBytes };
}

test('signer: v2 signature verifies over the v2 bytes and NOT over v1 (and vice versa)', async () => {
  const s = signer({ signBytesVersion: 'v2' });
  const tx2 = await s.signHybrid(TX);
  assert.equal(tx2.signBytesVersion, 'v2');
  const { sig, b0, authInfoBytes } = pqcSigOf(tx2);
  assert.equal(mldsa.verify(s.pqc.publicKey, hybridSignBytesV2('qorechain-vladi', b0, authInfoBytes), sig), true);
  assert.equal(mldsa.verify(s.pqc.publicKey, hybridSignBytesV1(b0, authInfoBytes), sig), false);

  const tx1 = await s.signHybrid({ ...TX, signBytesVersion: 'v1' }); // per-call override
  assert.equal(tx1.signBytesVersion, 'v1');
  const p1 = pqcSigOf(tx1);
  assert.equal(mldsa.verify(s.pqc.publicKey, hybridSignBytesV1(p1.b0, p1.authInfoBytes), p1.sig), true);
  assert.equal(mldsa.verify(s.pqc.publicKey, hybridSignBytesV2('qorechain-vladi', p1.b0, p1.authInfoBytes), p1.sig), false);
});

test('signer: auto resolves through rest (mainnet "0" -> v1, testnet -> v2); legacy + no rest throws', async () => {
  const f = fakeFetch({ [MAIN]: { height: '0' }, [TEST]: { height: '5746000' } });
  assert.equal((await signer({ rest: MAIN, fetch: f }).signHybrid(TX)).signBytesVersion, 'v1');
  assert.equal((await signer({ chainId: 'qorechain-diana', rest: TEST, fetch: f }).signHybrid(TX)).signBytesVersion, 'v2');
  await assert.rejects(signer({ fetch: f }).signHybrid(TX), /rest/);
  assert.equal((await signer({ chainId: 'qorechain-newnet', fetch: f }).signHybrid(TX)).signBytesVersion, 'v2');
});

// The README's caller-side retry, exercised against a fake transport.
async function sendWithRetry(s, tx, broadcast) {
  const first = await s.signHybrid(tx);
  try {
    return await broadcast(first);
  } catch (err) {
    if (!isHybridSignBytesRejection(err) || s.signBytesVersion !== 'auto') throw err;
    await s.refreshSignBytesVersion();
    return broadcast(await s.signHybrid(tx));
  }
}
function rejectingTransport(acceptVersion, codespace = 'pqc') {
  const seen = [];
  const fn = async (txRaw) => {
    seen.push(txRaw.signBytesVersion);
    if (txRaw.signBytesVersion !== acceptVersion) {
      throw Object.assign(new Error(`Broadcasting transaction failed with code 21 (codespace: ${codespace})`), { code: 21, codespace, log: codespace === 'pqc' ? 'hybrid PQC signature verification failed' : 'other' });
    }
    return { code: 0 };
  };
  fn.seen = seen;
  return fn;
}

test('retry: refused with pqc/21 -> refresh -> re-sign with the new form -> accepted', async () => {
  const table = { [MAIN]: { height: '0' } };
  const f = fakeFetch(table);
  const s = signer({ rest: MAIN, fetch: f });
  await s.signHybrid(TX); // warms the cache with v1
  table[MAIN] = { height: '9000000' }; // mainnet upgraded while the wallet was open
  const t = rejectingTransport('v2');
  assert.deepEqual(await sendWithRetry(s, TX, t), { code: 0 });
  assert.deepEqual(t.seen, ['v1', 'v2']);
  assert.equal(await s.refreshSignBytesVersion(), 'v2');
});

test('retry: explicit version -> no retry; code 21 from another codespace -> no retry', async () => {
  const f = fakeFetch({ [MAIN]: { height: '0' } });
  const t1 = rejectingTransport('v2');
  await assert.rejects(sendWithRetry(signer({ signBytesVersion: 'v1', fetch: f }), TX, t1));
  assert.deepEqual(t1.seen, ['v1']);
  const t2 = rejectingTransport('never', 'wasm');
  await assert.rejects(sendWithRetry(signer({ rest: MAIN, fetch: f }), TX, t2));
  assert.deepEqual(t2.seen, ['v1']);
});

// ---- eth-native hybrid signer ----

test('signHybridEth: explicit form used and reported; legacy chain with no version/rest throws', async () => {
  const w = await walletFromSeed(new Uint8Array(32).fill(7));
  const key = { privateKey: w.privateKey, pubkey: w.pubkey, pqc: w.pqc };
  const args = { key, chainId: 'qorechain-vladi', accountNumber: 1, ...TX };
  await assert.rejects(signHybridEth(args), /rest/);
  const tx1 = await signHybridEth({ ...args, signBytesVersion: 'v1' });
  assert.equal(tx1.signBytesVersion, 'v1');
  const p = pqcSigOf(tx1);
  assert.equal(mldsa.verify(w.pqc.publicKey, hybridSignBytesV1(p.b0, p.authInfoBytes), p.sig), true);
  const f = fakeFetch({ [TEST]: { height: '5746000' } });
  const tx2 = await signHybridEth({ ...args, chainId: 'qorechain-diana', rest: TEST, fetch: f });
  assert.equal(tx2.signBytesVersion, 'v2');
  const q = pqcSigOf(tx2);
  assert.equal(mldsa.verify(w.pqc.publicKey, hybridSignBytesV2('qorechain-diana', q.b0, q.authInfoBytes), q.sig), true);
  assert.equal(mldsa.verify(w.pqc.publicKey, hybridSignBytesV1(q.b0, q.authInfoBytes), q.sig), false);
});
