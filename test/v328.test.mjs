import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Ed25519, Secp256k1, Keccak256 } from '@cosmjs/crypto';
import { TxBody } from 'cosmjs-types/cosmos/tx/v1beta1/tx.js';
import {
  authenticatorLinkMessage, AUTHENTICATOR_LINK_DOMAIN, phantomPossessionProof, metaMaskPossessionProof,
  registerAuthenticatorMsg, registerEthAuthenticatorMsg, spendingRuleBoundsEveryDenom, linkAuthenticatorMsgs,
  updateSpendingRulesMsg, authenticatorExecutionResults, assertAuthenticatorExecutionsSucceeded,
  openEvmWindowMsg, decodeEvmWindowMsg, validateEvmWindowScope,
} from '../src/index.js';

const te = new TextEncoder();
const ACCOUNT = 'qor1rfjz7r3u8t65teavh5utquj3kwvsj983hh5zaj';
const toHex = (b) => Buffer.from(b).toString('hex');

// ---- link message ----

test('link message: known answer', () => {
  const text = authenticatorLinkMessage({ chainId: 'qorechain-diana', account: ACCOUNT, scheme: 'ed25519', pubkey: new Uint8Array(32).fill(7) });
  assert.equal(text,
    'QoreChain authenticator link v1\nchain: qorechain-diana\naccount: qor1rfjz7r3u8t65teavh5utquj3kwvsj983hh5zaj\n' +
    'scheme: ed25519\nkey: 0707070707070707070707070707070707070707070707070707070707070707');
  assert.ok(text.startsWith(AUTHENTICATOR_LINK_DOMAIN + '\n'));
});

test('link message: key as hex, lowercased; fields required', () => {
  const t = authenticatorLinkMessage({ chainId: 'c', account: 'a', scheme: 'secp256k1', pubkey: '0xABCDEF' });
  assert.ok(t.endsWith('\nkey: abcdef'));
  assert.throws(() => authenticatorLinkMessage({ chainId: '', account: 'a', scheme: 's', pubkey: [1] }), /chainId is required/);
  assert.throws(() => authenticatorLinkMessage({ chainId: 'c', account: 'a', scheme: 's', pubkey: [] }), /pubkey is required/);
});

// ---- possession proofs verify the way the chain checks them ----

test('Phantom proof: ed25519 over the raw text', async () => {
  const kp = await Ed25519.makeKeypair(new Uint8Array(32).fill(3));
  const wallet = {
    publicKey: { toBytes: () => kp.pubkey },
    signMessage: async (m) => ({ signature: await Ed25519.createSignature(m, kp) }),
  };
  const proof = await phantomPossessionProof({ wallet, chainId: 'qorechain-diana', account: ACCOUNT });
  const text = authenticatorLinkMessage({ chainId: 'qorechain-diana', account: ACCOUNT, scheme: 'ed25519', pubkey: kp.pubkey });
  assert.equal(proof.length, 64);
  assert.ok(await Ed25519.verifySignature(proof, te.encode(text), kp.pubkey));
  // Another chain id does not verify.
  const other = authenticatorLinkMessage({ chainId: 'qorechain-vladi', account: ACCOUNT, scheme: 'ed25519', pubkey: kp.pubkey });
  assert.equal(await Ed25519.verifySignature(proof, te.encode(other), kp.pubkey), false);
});

test('MetaMask proof: EIP-191 personal_sign recovers the linked address', async () => {
  const priv = new Uint8Array(32).fill(5);
  const kp = await Secp256k1.makeKeypair(priv);
  const uncompressed = kp.pubkey; // 65 bytes
  const address = '0x' + toHex(new Keccak256(uncompressed.slice(1)).digest().slice(12));
  const provider = {
    request: async ({ method, params }) => {
      assert.equal(method, 'personal_sign');
      const msg = Buffer.from(params[0].slice(2), 'hex');
      const prefixed = Buffer.concat([Buffer.from(`\x19Ethereum Signed Message:\n${msg.length}`), msg]);
      const sig = await Secp256k1.createSignature(new Keccak256(prefixed).digest(), priv);
      return '0x' + toHex(Uint8Array.from([...sig.r(32), ...sig.s(32), sig.recovery + 27]));
    },
  };
  const proof = await metaMaskPossessionProof({ provider, address, chainId: 'qorechain-diana', account: ACCOUNT });
  assert.equal(proof.length, 65);
  const text = te.encode(authenticatorLinkMessage({ chainId: 'qorechain-diana', account: ACCOUNT, scheme: 'secp256k1', pubkey: address }));
  const hash = new Keccak256(Buffer.concat([Buffer.from(`\x19Ethereum Signed Message:\n${text.length}`), text])).digest();
  const { ExtendedSecp256k1Signature } = await import('@cosmjs/crypto');
  const rec = Secp256k1.recoverPubkey(new ExtendedSecp256k1Signature(proof.slice(0, 32), proof.slice(32, 64), proof[64] - 27), hash);
  const recovered = '0x' + toHex(new Keccak256(Secp256k1.uncompressPubkey(rec).slice(1)).digest().slice(12));
  assert.equal(recovered, address);
});

// ---- composers require the proof ----

test('register composers refuse a missing proof and carry a given one', () => {
  const base = { owner: ACCOUNT, phantomPubkey: new Uint8Array(32), expiryUnix: 1 };
  assert.throws(() => registerAuthenticatorMsg(base), /possessionProof is required from chain v3\.2\.8/);
  assert.throws(() => registerAuthenticatorMsg({ ...base, possessionProof: new Uint8Array(0) }), /possessionProof is required/);
  const m = registerAuthenticatorMsg({ ...base, possessionProof: new Uint8Array(64).fill(1) });
  assert.equal(m.value.possessionProof.length, 64);
  assert.throws(() => registerEthAuthenticatorMsg({ owner: ACCOUNT, ethAddress: '0x' + '11'.repeat(20), expiryUnix: 1 }), /possessionProof is required/);
  const e = registerEthAuthenticatorMsg({ owner: ACCOUNT, ethAddress: '0x' + '11'.repeat(20), expiryUnix: 1, possessionProof: [1, 2] });
  assert.deepEqual([...e.value.possessionProof], [1, 2]);
});

// ---- spending rule ----

test('spendingRuleBoundsEveryDenom mirrors the chain', () => {
  assert.equal(spendingRuleBoundsEveryDenom(undefined), false);
  assert.equal(spendingRuleBoundsEveryDenom({ enabled: false, perTxLimit: 5 }), false);
  assert.equal(spendingRuleBoundsEveryDenom({ enabled: true }), false);
  assert.equal(spendingRuleBoundsEveryDenom({ enabled: true, perTxLimit: 5n }), true);
  assert.equal(spendingRuleBoundsEveryDenom({ enabled: true, dailyLimit: '10' }), true);
  assert.equal(spendingRuleBoundsEveryDenom({ enabled: true, allowedDenoms: ['uqor'] }), false);
  assert.equal(spendingRuleBoundsEveryDenom({ enabled: true, allowedDenoms: ['uqor'], denomLimits: [{ denom: 'uqor', perTxLimit: '0', dailyLimit: '0' }] }), false);
  assert.equal(spendingRuleBoundsEveryDenom({ enabled: true, allowedDenoms: ['uqor', 'erc20/0xAB'], denomLimits: [{ denom: 'uqor', perTxLimit: '1' }, { denom: 'erc20/0xab', dailyLimit: '9' }] }), true);
  assert.equal(spendingRuleBoundsEveryDenom({ enabled: true, allowedDenoms: ['uqor', 'ufoo'], denomLimits: [{ denom: 'uqor', perTxLimit: '1' }] }), false);
});

test('linkAuthenticatorMsgs: rules first, then register; value permissions need a bounding first enabled rule', () => {
  const reg = registerAuthenticatorMsg({ owner: ACCOUNT, phantomPubkey: new Uint8Array(32), permissions: ['svm'], expiryUnix: 1, possessionProof: [1] });
  assert.throws(() => linkAuthenticatorMsgs({ registerMsg: reg }), /move value/);
  assert.throws(() => linkAuthenticatorMsgs({ registerMsg: reg, rules: [{ enabled: true }, { enabled: true, perTxLimit: 1 }] }), /move value/);
  const msgs = linkAuthenticatorMsgs({ registerMsg: reg, rules: [{ enabled: false }, { enabled: true, perTxLimit: 1000 }] });
  assert.deepEqual(msgs.map((m) => m.typeUrl), [
    '/qorechain.abstractaccount.v1.MsgUpdateSpendingRules', '/qorechain.abstractaccount.v1.MsgRegisterAuthenticator',
  ]);
  assert.equal(msgs[0].value.accountAddress, ACCOUNT);
  // A key without value permissions needs no rule.
  const ro = registerAuthenticatorMsg({ owner: ACCOUNT, phantomPubkey: new Uint8Array(32), permissions: ['vote'], expiryUnix: 1, possessionProof: [1] });
  assert.deepEqual(linkAuthenticatorMsgs({ registerMsg: ro }).map((m) => m.typeUrl), ['/qorechain.abstractaccount.v1.MsgRegisterAuthenticator']);
  assert.throws(() => updateSpendingRulesMsg({ owner: ACCOUNT }), /rules must be an array/);
});

// ---- execution results ----

function pb(fields) {
  const out = [];
  const varint = (n) => { let v = BigInt(n); do { let b = Number(v & 0x7fn); v >>= 7n; if (v > 0n) b |= 0x80; out.push(b); } while (v > 0n); };
  for (const [no, kind, val] of fields) {
    if (kind === 'v') { varint((no << 3) | 0); varint(val); } else { varint((no << 3) | 2); varint(val.length); out.push(...val); }
  }
  return Uint8Array.from(out);
}

test('authenticatorExecutionResults reads success=false inside a code 0 tx', () => {
  const result = {
    code: 0,
    msgResponses: [
      { typeUrl: '/qorechain.abstractaccount.v1.MsgExecuteEVMResponse', value: pb([[1, 'v', 1], [2, 'b', [0xaa]], [3, 'v', 21000]]) },
      { typeUrl: '/cosmos.bank.v1beta1.MsgSendResponse', value: new Uint8Array(0) },
      { typeUrl: '/qorechain.abstractaccount.v1.MsgExecuteCosmosResponse', value: new Uint8Array(0) },
    ],
    events: [{ type: 'abstractaccount_execution_failed', attributes: [
      { key: 'account', value: ACCOUNT }, { key: 'lane', value: 'cosmos' }, { key: 'nonce', value: '4' }, { key: 'reason', value: 'spending limit' },
    ] }],
  };
  const r = authenticatorExecutionResults(result);
  assert.equal(r.length, 2);
  assert.equal(r[0].success, true);
  assert.equal(r[0].gasUsed, 21000n);
  assert.deepEqual([...r[0].ret], [0xaa]);
  assert.equal(r[1].success, false);
  assert.equal(r[1].reason, 'spending limit');
  assert.throws(() => assertAuthenticatorExecutionsSucceeded(result), /authenticator execution failed .*spending limit.*nonce is consumed/);
  assert.throws(() => assertAuthenticatorExecutionsSucceeded({ code: 5, rawLog: 'x' }), /code 5/);
  assert.equal(assertAuthenticatorExecutionsSucceeded({ code: 0, msgResponses: [result.msgResponses[0]] }).length, 1);
});

// ---- EVM window scope (fields 5..9) ----

const VALOPER = 'qorvaloper1rfjz7r3u8t65teavh5utquj3kwvsj983nrdm0h';

test('window scope fields round-trip through a TxBody', () => {
  const msg = openEvmWindowMsg({
    sender: ACCOUNT, blocks: 100, maxTxs: 2, maxValue: '5',
    nativeOnly: true,
    allowedTargets: ['0x' + 'AB'.repeat(20)],
    validators: ['0x' + '0c'.repeat(20), '0x' + '0d'.repeat(20)],
    stakingValidators: [VALOPER],
    ibcReceivers: ['channel-0/cosmos1receiver'],
  });
  const decoded = TxBody.decode(TxBody.encode(TxBody.fromPartial({ messages: [msg] })).finish()).messages[0];
  assert.deepEqual(decodeEvmWindowMsg(decoded), {
    sender: ACCOUNT, blocks: 100n, maxTxs: 2n, maxValue: '5',
    nativeOnly: true,
    allowedTargets: ['0x' + 'ab'.repeat(20)],
    validators: ['0x' + '0c'.repeat(20), '0x' + '0d'.repeat(20)],
    stakingValidators: [VALOPER],
    ibcReceivers: ['channel-0/cosmos1receiver'],
  });
});

test('window scope is checked as the chain does', () => {
  const f = (scope) => () => validateEvmWindowScope(scope);
  assert.throws(f({ validators: ['0x12'] }), /validators: .* is not a 0x-prefixed 20-byte address/);
  assert.throws(f({ allowedTargets: Array.from({ length: 17 }, (_, i) => '0x' + i.toString(16).padStart(40, '0')) }), /maximum is 16/);
  assert.throws(f({ validators: ['0x' + 'aa'.repeat(20), '0x' + 'AA'.repeat(20)] }), /more than once/);
  assert.throws(f({ stakingValidators: [ACCOUNT] }), /not a validator operator address/);
  assert.throws(f({ ibcReceivers: ['channel-0'] }), /not <source channel>\/<receiver>/);
  assert.throws(f({ ibcReceivers: ['/cosmos1x'] }), /not <source channel>\/<receiver>/);
  assert.throws(f({ ibcReceivers: ['channel-0/a b'] }), /whitespace or a comma/);
  assert.throws(f({ ibcReceivers: ['c/' + 'x'.repeat(255)] }), /1 to 256 characters/);
  assert.throws(f({ nativeOnly: 'yes' }), /nativeOnly must be a boolean/);
  assert.deepEqual(validateEvmWindowScope({}), { nativeOnly: false, allowedTargets: [], validators: [], stakingValidators: [], ibcReceivers: [] });
});

test('a window without scope encodes exactly as before', () => {
  const plain = openEvmWindowMsg({ sender: ACCOUNT, blocks: 1, maxTxs: 1, maxValue: '1' });
  const empty = openEvmWindowMsg({ sender: ACCOUNT, blocks: 1, maxTxs: 1, maxValue: '1', nativeOnly: false, validators: [] });
  assert.deepEqual([...plain.value], [...empty.value]);
});
