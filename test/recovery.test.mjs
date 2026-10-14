import { test } from 'node:test';
import assert from 'node:assert/strict';
import { shake256 } from '@qorechain/pqc';
import {
  generatePqcRecoveryCode, pqcKeyFromRecoveryCode, isValidRecoveryCode, normalizeRecoveryCode,
  walletFromMnemonic,
} from '../src/index.js';

const ADDR = 'qor1npvwllfr9dqr8erajqqr6s0vxnk2ak55am9g2c';
// Known answer: a secret of 32 × 0x42. Pinned so the format, checksum and
// derivation cannot drift silently between releases.
const KAT_CODE = 'QRC1-8914-4GJ2-8914-4GJ2-8914-4GJ2-8914-4GJ2-8914-4GJ2-8914-4GJ2-8914-6MGY';
const KAT_PUB_FINGERPRINT = 'adb07c6fdea40d1585fec4a11d1c4fc3';
const fp = (k) => Buffer.from(shake256(k.publicKey, 16)).toString('hex');

test('known-answer vector: format and derived key are pinned', async () => {
  const real = globalThis.crypto.getRandomValues.bind(globalThis.crypto);
  globalThis.crypto.getRandomValues = (a) => { a.fill(0x42); return a; };
  try {
    assert.equal(await generatePqcRecoveryCode(), KAT_CODE);
  } finally {
    globalThis.crypto.getRandomValues = real;
  }
  const k = await pqcKeyFromRecoveryCode(KAT_CODE, ADDR);
  assert.equal(k.publicKey.length, 2592);
  assert.equal(k.secretKey.length, 4896);
  assert.equal(fp(k), KAT_PUB_FINGERPRINT);
});

test('a generated code looks nothing like a seed phrase and round-trips', async () => {
  const c = await generatePqcRecoveryCode();
  assert.match(c, /^QRC1(-[0-9A-HJKMNP-TV-Z]{4}){14}$/);
  assert.equal(c.includes(' '), false, 'no spaces: it must not read as a word list');
  assert.equal(isValidRecoveryCode(c), true);
  const a = await pqcKeyFromRecoveryCode(c, ADDR);
  const b = await pqcKeyFromRecoveryCode(c, ADDR);
  assert.equal(fp(a), fp(b));
});

test('two generated codes differ', async () => {
  assert.notEqual(await generatePqcRecoveryCode(), await generatePqcRecoveryCode());
});

test('a single mistyped character is caught by the checksum, not turned into a wrong key', async () => {
  const chars = [...KAT_CODE];
  const i = KAT_CODE.indexOf('4GJ2') + 1; // a data character, not a separator
  chars[i] = chars[i] === 'G' ? 'H' : 'G';
  const typo = chars.join('');
  assert.equal(isValidRecoveryCode(typo), false);
  await assert.rejects(() => pqcKeyFromRecoveryCode(typo, ADDR), /checksum does not match/);
});

test('what people actually type is accepted: lowercase, no prefix, no dashes, confusable letters', async () => {
  const want = fp(await pqcKeyFromRecoveryCode(KAT_CODE, ADDR));
  const variants = [
    KAT_CODE.toLowerCase(),
    KAT_CODE.slice('QRC1-'.length),
    KAT_CODE.replace(/-/g, ''),
    KAT_CODE.replace(/-/g, ' '),
    KAT_CODE.replace(/1/g, 'I'),   // I read as 1
    KAT_CODE.replace(/1/g, 'l'),   // l read as 1
  ];
  for (const v of variants) assert.equal(fp(await pqcKeyFromRecoveryCode(v, ADDR)), want, v);
});

test('malformed codes are refused with a message a UI can show', () => {
  assert.throws(() => normalizeRecoveryCode('QRC1-8914'), /must have 56 characters/);
  assert.throws(() => normalizeRecoveryCode(KAT_CODE.replace('8914', '891U')), /invalid character "U"/);
  assert.equal(isValidRecoveryCode(KAT_CODE.replace('8914', '89!4')), false);
  assert.throws(() => normalizeRecoveryCode(12345), /must be a string/);
});

test('the key is bound to the account: another address yields another key', async () => {
  const other = 'qor1xyerxdp4xcmnswfsxyerxdp4xcmnswfs6ql9fs';
  const a = await pqcKeyFromRecoveryCode(KAT_CODE, ADDR);
  const b = await pqcKeyFromRecoveryCode(KAT_CODE, other);
  assert.notEqual(fp(a), fp(b));
  // An upper-case spelling of the same address is the same account.
  assert.equal(fp(await pqcKeyFromRecoveryCode(KAT_CODE, ADDR.toUpperCase())), fp(a));
  await assert.rejects(() => pqcKeyFromRecoveryCode(KAT_CODE, '0x9858EfFD232B4033E47d90003D41EC34EcaEda94'),
    /must be the account's qor1… address/);
});

test('the recovery key is independent of the account\'s classical key', async () => {
  // The same mnemonic always gives the same classical key; two different codes
  // must still give two different PQC keys for it. That is the whole point.
  const w = await walletFromMnemonic('test test test test test test test test test test test junk');
  const a = await pqcKeyFromRecoveryCode(await generatePqcRecoveryCode(), w.cosmos);
  const b = await pqcKeyFromRecoveryCode(await generatePqcRecoveryCode(), w.cosmos);
  assert.notEqual(fp(a), fp(b));
  assert.notEqual(fp(a), fp(w.pqc), 'not the mnemonic-derived key either');
});
