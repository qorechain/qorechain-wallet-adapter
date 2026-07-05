import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  evmAuthSignBytes, cosmosAuthSignBytes, rotationSignBytes,
  executeEvmMsg, executeCosmosMsg, revokeAuthenticatorMsg,
  rotatePqcKeyMsgFromMnemonic, derivePqcLegacy,
} from '../src/authenticator.js';

const enc = new TextEncoder();
function be64(n) { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(n)); return b; }
function lp(x) { const b = Buffer.isBuffer(x) ? x : Buffer.from(x); return Buffer.concat([be64(b.length), b]); }

// Reference implementations transcribed directly from the chain Go source
// (x/abstractaccount/types/{evm,cosmos}_sign.go) — if the adapter drifts, these fail.
function refEvm({ chainId, account, pubkey, to, value, data, nonce }) {
  const body = Buffer.concat([
    Buffer.from('qorechain-evm-auth-v1'),
    lp(chainId), lp(account), lp(Buffer.from(pubkey)),
    lp(to), lp(value), lp(Buffer.from(data)),
    be64(nonce),
  ]);
  return new Uint8Array(createHash('sha256').update(body).digest());
}
function refCosmos({ chainId, account, pubkey, to, amount, nonce }) {
  const body = Buffer.concat([
    Buffer.from('qorechain-cosmos-auth-v1'),
    lp(chainId), lp(account), lp(Buffer.from(pubkey)),
    lp(to), lp(amount),
    be64(nonce),
  ]);
  return new Uint8Array(createHash('sha256').update(body).digest());
}

const PUB = new Uint8Array(32).fill(7);

test('evmAuthSignBytes matches the chain byte-for-byte', async () => {
  const p = { chainId: 'qorechain-diana', account: 'qor1abc', pubkey: PUB, to: '0x00000000000000000000000000000000000000aa', value: '100000000000000000', data: new Uint8Array([1, 2, 3]), nonce: 1977 };
  assert.deepEqual(await evmAuthSignBytes(p), refEvm(p));
});

test('evmAuthSignBytes defaults (empty to/value/data)', async () => {
  const p = { chainId: 'c', account: 'a', pubkey: PUB, nonce: 0 };
  assert.deepEqual(await evmAuthSignBytes(p), refEvm({ ...p, to: '', value: '0', data: new Uint8Array(0) }));
});

test('cosmosAuthSignBytes matches the chain byte-for-byte', async () => {
  const p = { chainId: 'qorechain-diana', account: 'qor1abc', pubkey: PUB, to: 'qor1def', amount: '100uqor', nonce: 3 };
  assert.deepEqual(await cosmosAuthSignBytes(p), refCosmos(p));
});

test('EVM and Cosmos domains differ (no cross-lane replay)', async () => {
  const base = { chainId: 'c', account: 'a', pubkey: PUB, nonce: 1 };
  const e = await evmAuthSignBytes({ ...base, to: 'x', value: 'y', data: new Uint8Array() });
  const c = await cosmosAuthSignBytes({ ...base, to: 'x', amount: '1uqor' });
  assert.notDeepEqual(e, c);
});

test('rotationSignBytes format', () => {
  const s = rotationSignBytes('qorechain-diana', 1, 'qor1abc', new Uint8Array([0xde, 0xad]), new Uint8Array([0xbe, 0xef]));
  assert.equal(s, 'qorechain-pqc-rotate-v1|qorechain-diana|1|qor1abc|dead|beef');
});

test('executeEvmMsg / executeCosmosMsg shape', () => {
  const e = executeEvmMsg({ relayer: 'r', account: 'a', scheme: 'ed25519', pubkey: PUB, signature: new Uint8Array(64), gasLimit: 100000, nonce: 5 });
  assert.equal(e.typeUrl, '/qorechain.abstractaccount.v1.MsgExecuteEVM');
  assert.equal(e.value.gasLimit, 100000n);
  assert.equal(e.value.data.length, 0);
  const c = executeCosmosMsg({ relayer: 'r', account: 'a', scheme: 'ed25519', pubkey: PUB, signature: new Uint8Array(64), to: 'qor1x', amount: '250uqor', nonce: 2 });
  assert.equal(c.typeUrl, '/qorechain.abstractaccount.v1.MsgExecuteCosmos');
  assert.deepEqual(c.value.amount, [{ denom: 'uqor', amount: '250' }]);
  assert.equal(c.value.nonce, 2n);
});

test('revokeAuthenticatorMsg shape', () => {
  const m = revokeAuthenticatorMsg({ owner: 'qor1o', scheme: 'ed25519', pubkey: PUB });
  assert.equal(m.typeUrl, '/qorechain.abstractaccount.v1.MsgRevokeAuthenticator');
  assert.equal(m.value.accountAddress, 'qor1o');
});

test('rotatePqcKeyMsgFromMnemonic builds a dual-signed migration (bridge→adapter)', () => {
  const account = 'qor1wv0fvt5qzx7gllk9ckzv3u6ypceaqq8evuny0h';
  const mnemonic = 'test test test test test test test test test test test junk';
  const { msg, oldKeypair, newKeypair } = rotatePqcKeyMsgFromMnemonic({ account, mnemonic, chainId: 'qorechain-diana' });
  assert.equal(msg.typeUrl, '/qorechain.pqc.v1.MsgRotatePQCKey');
  // old = legacy(bridge) derivation; verify our exported legacy helper matches.
  assert.deepEqual(msg.value.oldPublicKey, derivePqcLegacy(mnemonic).publicKey);
  // new must differ from old; both signatures present.
  assert.notDeepEqual(msg.value.oldPublicKey, msg.value.newPublicKey);
  assert.ok(msg.value.oldSignature.length > 0 && msg.value.newSignature.length > 0);
  assert.deepEqual(oldKeypair.publicKey, msg.value.oldPublicKey);
  assert.deepEqual(newKeypair.publicKey, msg.value.newPublicKey);
});
