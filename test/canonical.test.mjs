import { test } from 'node:test';
import assert from 'node:assert/strict';
import { toHex } from '@cosmjs/encoding';
import { rotatePqcKeyMsgFromMnemonic, walletFromMnemonic } from '../src/index.js';
import { canonicalMnemonic, canonicalAccount } from '../src/authenticator.js';

const M = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

test('canonical rotation key ignores case and spacing of phrase and address', async () => {
  const w = await walletFromMnemonic(M);
  const want = toHex(w.pqc.publicKey);
  const key = (account, mnemonic) => toHex(rotatePqcKeyMsgFromMnemonic({ account, mnemonic, chainId: 'qorechain-diana' }).newKeypair.publicKey);
  assert.equal(key(w.cosmos, M), want);
  for (const m of [M.toUpperCase(), `  ${M}\n`, M.replace(/ /g, '  '), M.replace(/ /g, '\t')]) {
    assert.equal(key(w.cosmos, m), want);
  }
  assert.equal(key(w.cosmos.toUpperCase(), M), want);
  assert.equal(key(w.evm, M), want);
  assert.equal(canonicalMnemonic(` ${M.toUpperCase()} `), M);
  assert.equal(canonicalAccount(w.cosmos.toUpperCase()), w.cosmos);
});

test('an invalid phrase is refused without being echoed', () => {
  assert.throws(() => canonicalMnemonic('abandon abandon secretword'), (e) => e.message === 'invalid mnemonic');
});
