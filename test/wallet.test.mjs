import { test } from 'node:test';
import { createHash } from 'node:crypto';
import assert from 'node:assert/strict';
import { fromBech32, fromHex, toHex } from '@cosmjs/encoding';
import {
  generateQoreWallet, walletFromMnemonic, walletFromSeed, addressesFrom20, qoreAddresses, base58Decode,
  pqcKeyFromRecoveryCode, pqcKeyFromSecret, pqcRecoveryCodeFromSecret,
} from '../src/index.js';

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

test('walletFromSeed: deterministic, unified 3-address, ML-DSA-87 key', async () => {
  const seed = fromHex('11'.repeat(32));
  const w1 = await walletFromSeed(seed, { legacySeedDerivation: true });
  const w2 = await walletFromSeed('0x' + '11'.repeat(32), { legacySeedDerivation: true }); // hex form must match bytes form
  assert.equal(w1.cosmos, w2.cosmos);
  assert.equal(w1.evm, w2.evm);
  assert.equal(w1.svm, w2.svm);
  assert.equal(w1.privateKey, w2.privateKey);
  assert.equal(toHex(w1.pqc.publicKey), toHex(w2.pqc.publicKey));
  assertSame20(w1);
  assert.equal(w1.pqc.publicKey.length, 2592);
  assert.equal(w1.mnemonic, null);
  // a different seed yields a different account
  const w3 = await walletFromSeed(fromHex('22'.repeat(32)), { legacySeedDerivation: true });
  assert.notEqual(w3.cosmos, w1.cosmos);
});

// ---- seed path: the PQC key needs a second secret ----

const SEED01 = new Uint8Array(32).fill(0x01);
const SEED01_ADDR = 'qor1rfjz7r3u8t65teavh5utquj3kwvsj983hh5zaj';
const CODE07 = 'QRC1-0W3G-E1R7-0W3G-E1R7-0W3G-E1R7-0W3G-E1R7-0W3G-E1R7-0W3G-E1R7-0W3X-19XK';
const RECOVERY_PUB_SHA256 = 'cf50dca6c9a0d86eeac9d6a50ee54e567e2126184143be694b8df1f31c8e23ef';
const LEGACY_PUB_SHA256 = '3710d198ff5d3206601e9dfd7e0e4bac0656de0fee28f5a20b39e05c81e46bd0';
const sha256hex = (b) => createHash('sha256').update(b).digest('hex');

test('walletFromSeed known answers: recoveryCode and pqcSecret give the same key, legacy keeps the old one', async () => {
  const byCode = await walletFromSeed(SEED01, { recoveryCode: CODE07 });
  assert.equal(byCode.cosmos, SEED01_ADDR);
  assert.equal(byCode.pqc.publicKey.length, 2592);
  assert.equal(sha256hex(byCode.pqc.publicKey), RECOVERY_PUB_SHA256);
  const secret = new Uint8Array(32).fill(0x07);
  const bySecret = await walletFromSeed(SEED01, { pqcSecret: secret });
  assert.equal(sha256hex(bySecret.pqc.publicKey), RECOVERY_PUB_SHA256);
  assert.deepEqual(secret, new Uint8Array(32).fill(0x07), 'the caller\'s secret is left untouched');
  const legacy = await walletFromSeed(SEED01, { legacySeedDerivation: true });
  assert.equal(legacy.cosmos, SEED01_ADDR);
  assert.equal(sha256hex(legacy.pqc.publicKey), LEGACY_PUB_SHA256);
  // the classical half is the same whichever PQC option is used
  assert.equal(byCode.privateKey, legacy.privateKey);
  assert.equal(byCode.evm, legacy.evm);
});

test('walletFromSeed and the recovery helpers agree on the code format', async () => {
  const secret = new Uint8Array(32).fill(0x07);
  assert.equal(pqcRecoveryCodeFromSecret(secret), CODE07);
  assert.equal(sha256hex((await pqcKeyFromSecret(secret, SEED01_ADDR)).publicKey), RECOVERY_PUB_SHA256);
  assert.equal(sha256hex((await pqcKeyFromRecoveryCode(CODE07, SEED01_ADDR)).publicKey), RECOVERY_PUB_SHA256);
  assert.throws(() => pqcRecoveryCodeFromSecret(new Uint8Array(31)), /32 bytes/);
  await assert.rejects(pqcKeyFromSecret(new Uint8Array(31), SEED01_ADDR), /32 bytes/);
  await assert.rejects(pqcKeyFromSecret(secret, '0x9858EfFD232B4033E47d90003D41EC34EcaEda94'), /qor1/);
});

test('walletFromSeed reads a code typed loosely, and refuses a mistyped one', async () => {
  // lower case, spaces instead of dashes, O for 0, and the prefix written "qrcl"
  const typed = 'qrcl ' + CODE07.slice(5).toLowerCase().replace(/-/g, ' ').replace(/0/g, 'o');
  const w = await walletFromSeed(SEED01, { recoveryCode: typed });
  assert.equal(sha256hex(w.pqc.publicKey), RECOVERY_PUB_SHA256);
  const withI = CODE07.replace(/1/g, 'I');
  assert.equal(sha256hex((await walletFromSeed(SEED01, { recoveryCode: withI })).pqc.publicKey), RECOVERY_PUB_SHA256);
  const typo = CODE07.slice(0, -1) + (CODE07.endsWith('K') ? 'M' : 'K');
  await assert.rejects(walletFromSeed(SEED01, { recoveryCode: typo }), /checksum does not match/);
});

test('walletFromSeed with no PQC option throws and names the three choices', async () => {
  for (const opts of [undefined, {}, { legacySeedDerivation: false }]) {
    await assert.rejects(walletFromSeed(SEED01, opts), (e) =>
      /recoveryCode/.test(e.message) && /pqcSecret/.test(e.message) && /legacySeedDerivation/.test(e.message));
  }
});

test('walletFromSeed with more than one PQC option throws', async () => {
  const secret = new Uint8Array(32).fill(0x07);
  for (const opts of [
    { recoveryCode: CODE07, pqcSecret: secret },
    { recoveryCode: CODE07, legacySeedDerivation: true },
    { pqcSecret: secret, legacySeedDerivation: true },
    { recoveryCode: CODE07, pqcSecret: secret, legacySeedDerivation: true },
  ]) {
    await assert.rejects(walletFromSeed(SEED01, opts), /only one of/);
  }
});

test('walletFromSeed refuses the seed itself as pqcSecret', async () => {
  await assert.rejects(walletFromSeed(SEED01, { pqcSecret: SEED01.slice() }), /independent of the seed/);
  await assert.rejects(walletFromSeed(SEED01, { pqcSecret: new Uint8Array(16) }), /32 bytes/);
});
