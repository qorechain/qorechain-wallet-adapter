import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fromBech32, fromHex, toHex } from '@cosmjs/encoding';
import { generateQoreWallet, walletFromMnemonic, addressesFrom20, qoreAddresses, base58Decode } from '../src/index.js';

// The three encodings must all resolve to the SAME 20-byte account.
function assertSame20(w) {
  const fromCosmos = fromBech32(w.cosmos).data;
  const fromEvm = fromHex(w.evm.replace(/^0x/, ''));
  const fromSvm = base58Decode(w.svm, 32).slice(0, 20); // svm = 20 bytes + 12 zero pad
  assert.equal(fromCosmos.length, 20);
  assert.equal(toHex(fromCosmos), toHex(fromEvm), 'cosmos vs evm 20 bytes differ');
  assert.equal(toHex(fromCosmos), toHex(fromSvm), 'cosmos vs svm 20 bytes differ');
  // svm high 12 bytes are zero padding
  assert.equal(toHex(base58Decode(w.svm, 32).slice(20)), '0'.repeat(24), 'svm not right-padded with 12 zero bytes');
}

test('generateQoreWallet: all three encodings decode to identical 20 bytes', async () => {
  const w = await generateQoreWallet();
  assert.ok(w.cosmos.startsWith('qor1'));
  assert.ok(w.evm.startsWith('0x') && w.evm.length === 42);
  assert.ok(w.svm.length > 20);
  assertSame20(w);
});

test('EIP-55 checksum is valid (round-trips lower/upper by keccak rule)', async () => {
  const w = await generateQoreWallet();
  // qoreAddresses re-derives from the 0x form and must reproduce the same checksummed evm.
  const re = qoreAddresses({ evm: w.evm });
  assert.equal(re.evm, w.evm);
  assert.equal(re.cosmos, w.cosmos);
  assert.equal(re.svm, w.svm);
});

test('deterministic: walletFromMnemonic reproduces the same addresses + PQC key', async () => {
  const w = await generateQoreWallet();
  const w2 = await walletFromMnemonic(w.mnemonic);
  assert.equal(w2.cosmos, w.cosmos);
  assert.equal(w2.evm, w.evm);
  assert.equal(w2.svm, w.svm);
  assert.equal(w2.privateKey, w.privateKey);
  assert.equal(toHex(w2.pqc.publicKey), toHex(w.pqc.publicKey));
});

test('ML-DSA-87 pubkey is 2592 bytes (FIPS-204)', async () => {
  const w = await generateQoreWallet();
  assert.equal(w.pqc.publicKey.length, 2592);
});

test('addressesFrom20 matches a known 20-byte account (the 0x57b6… recipient)', () => {
  const addr = addressesFrom20(fromHex('57b6f9c9c1b4e2646b15a421679e601c34f8b37c'));
  assert.equal(addr.cosmos, 'qor127m0njwpkn3xg6c45ssk08nqrs603vmu0xyjnq'); // verified live on mainnet
  assert.equal(addr.evm.toLowerCase(), '0x57b6f9c9c1b4e2646b15a421679e601c34f8b37c');
});
