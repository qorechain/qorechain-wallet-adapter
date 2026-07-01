// Regression for the hedged-signing bug (pqc <0.1.1 / adapter <=0.1.1):
// QoreChain's PQC ante verifier accepts only DETERMINISTIC ML-DSA-87 signatures
// (FIPS-204 §3.4). The adapter's signHybrid used @qorechain/pqc's mldsa.sign,
// which was hedged/randomized — every tx it produced was rejected by the chain.
// These tests pin signHybrid's embedded PQC signature to the deterministic
// output the chain verifier recomputes (independently derived via @noble with
// extraEntropy:false, the mode validated against the shared /vectors).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { QoreChainSigner, frame } from '../src/index.js';
import { mldsa } from '@qorechain/pqc';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { TxRaw, TxBody, AuthInfo } from 'cosmjs-types/cosmos/tx/v1beta1/tx.js';

const hb = (s) => Uint8Array.from(Buffer.from(s, 'hex'));
const hx = (b) => Buffer.from(b).toString('hex');

// Fixed keypair from the shared vectors' first ML-DSA-87 seed.
const SEED = hb('8a9bacbdcedff00112233445566778899aabbccddeef00112233445566778899');

// Keplr-like wallet stub: a fixed classical signature (its value is irrelevant
// here — the chain-critical part under test is the PQC extension).
const fakeWallet = {
  async signDirect() {
    return { signature: { signature: Buffer.from(new Uint8Array(64).fill(1)).toString('base64') } };
  },
};

function makeSigner() {
  return new QoreChainSigner({
    wallet: fakeWallet,
    chainId: 'qorechain-diana',
    address: 'qor1qqqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v9ccrydpk8qarc0jqwzwvfk',
    pubkeySecp256k1: new Uint8Array(33).fill(2),
    accountNumber: 7,
    pqc: mldsa.keygen(SEED),
  });
}

const TX = {
  messages: [{ typeUrl: '/cosmos.bank.v1beta1.MsgSend', value: new Uint8Array([1, 2, 3]) }],
  fee: { amount: [{ denom: 'uqor', amount: '25000' }], gasLimit: 250000n },
  memo: 'hedged-regression',
  sequence: 3,
};

function extractPqcSig(txRawBytes) {
  const { bodyBytes, authInfoBytes } = TxRaw.decode(txRawBytes);
  const body = TxBody.decode(bodyBytes);
  assert.equal(body.extensionOptions.length, 1, 'exactly one PQC hybrid extension');
  const ext = body.extensionOptions[0];
  assert.equal(ext.typeUrl, '/qorechain.pqc.v1.PQCHybridSignature');
  // PQCHybridSignature: field1 varint algId=1, field2 len-delimited sig.
  assert.equal(ext.value[0], 0x08);
  assert.equal(ext.value[1], 1, 'algorithm must be ML-DSA-87');
  assert.equal(ext.value[2], 0x12);
  // 4627-byte sig => 2-byte length varint (0x93 0x24).
  const sig = ext.value.slice(5);
  assert.equal(sig.length, 4627);
  return { sig, body, authInfoBytes };
}

test('signHybrid embeds the DETERMINISTIC ML-DSA-87 signature the chain verifier expects', async () => {
  const signer = makeSigner();
  const txRaw = await signer.signHybrid(TX);
  const { sig, body, authInfoBytes } = extractPqcSig(txRaw);

  // Recompute B0 (body without the PQC extension) exactly as the chain does.
  const b0 = TxBody.encode(TxBody.fromPartial({
    messages: TX.messages, memo: TX.memo, timeoutHeight: 0n,
  })).finish();
  // Independent expectation: @noble deterministic mode (extraEntropy:false) —
  // byte-identical to the chain's Rust FFI, per the shared /vectors.
  const expected = ml_dsa87.sign(frame(b0, authInfoBytes), signer.pqc.secretKey, { extraEntropy: false });
  assert.equal(hx(sig), hx(expected),
    'signHybrid must produce the deterministic signature (hedged signing is rejected by the chain)');
  assert.equal(body.memo, TX.memo);
  assert.deepEqual([...AuthInfo.decode(authInfoBytes).fee.amount[0].amount], [...'25000']);
});

test('signHybrid is fully reproducible: same inputs => identical TxRaw bytes', async () => {
  const a = await makeSigner().signHybrid(TX);
  const b = await makeSigner().signHybrid(TX);
  assert.equal(hx(a), hx(b), 'two runs over identical inputs must be byte-identical');
});
