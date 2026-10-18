import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  evmAuthSignBytes,
  evmAuthSignBytesV2,
  resolveEvmAuthDigestVersion,
  buildMetaMaskExecuteEvm,
} from '../src/index.js';

const hex = (b) => Buffer.from(b).toString('hex');
const unhex = (s) => Uint8Array.from(Buffer.from(s, 'hex'));

// Computed with the chain's own EVMAuthSignBytes / EVMAuthSignBytesV2
// (x/abstractaccount/types/evm_sign.go at the frozen v3.2.3 commit).
const input = {
  chainId: 'qorechain-diana',
  account: 'qor1hkkxx5jmmw02wcz26c74lsp74qysj6h495vv0k',
  pubkey: unhex('038844ec286297bf780ce0fbe07df2a74c5e0e841df5f3adc363f0372755b76d74'),
  to: '0x63c0c19a282a1b52b07dd5a65b58948a07dae32b',
  value: '1000',
  data: unhex('a9059cbb'),
  nonce: 7,
};

test('AA digests match the chain byte for byte', async () => {
  assert.equal(hex(await evmAuthSignBytes(input)), 'c2614c477a15020777adb1e889748557debc6dece7207ded95d30ee6d7bd778a');
  assert.equal(
    hex(await evmAuthSignBytesV2({ ...input, gasLimit: 250000 })),
    '19d7518ad25079dff616819b7554d7d39700fb9e4331a6cbc635685122f0c18b',
  );
  await assert.rejects(evmAuthSignBytesV2({ ...input, gasLimit: 0 }), /gasLimit/);
});

test('resolveEvmAuthDigestVersion follows the v3.2.3 plan', async () => {
  const answer = (height) => async () => ({ ok: true, status: 200, json: async () => ({ height }) });
  assert.equal(await resolveEvmAuthDigestVersion({ rest: 'https://lcd/', fetch: answer('0') }), 'v1');
  assert.equal(await resolveEvmAuthDigestVersion({ rest: 'https://lcd', fetch: answer('8003746') }), 'v2');
  await assert.rejects(
    resolveEvmAuthDigestVersion({ rest: 'https://lcd', fetch: async () => ({ ok: false, status: 503 }) }),
    /HTTP 503/,
  );
});

test('MetaMask builder signs the digest version it is told to', async () => {
  const signed = [];
  const provider = {
    request: async ({ params }) => {
      signed.push(params[0]);
      return '0x' + '11'.repeat(65);
    },
  };
  const address = '0x' + '22'.repeat(20);
  const common = { provider, address, relayer: 'qor1relayer', chainId: input.chainId, account: input.account, to: input.to, value: '1000', data: input.data, gasLimit: 250000, nonce: 7 };
  await buildMetaMaskExecuteEvm(common);
  await buildMetaMaskExecuteEvm({ ...common, digestVersion: 'v2' });
  assert.notEqual(signed[0], signed[1]);
  await assert.rejects(buildMetaMaskExecuteEvm({ ...common, digestVersion: 'v3' }), /digestVersion/);
});

test('the legacy derivation is refused as the NEW key of a rotation', async () => {
  const { rotatePqcKeyMsgFromMnemonic } = await import('../src/authenticator.js');
  const base = {
    account: 'qor1hkkxx5jmmw02wcz26c74lsp74qysj6h495vv0k',
    mnemonic: 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
    chainId: 'qorechain-diana',
  };
  assert.throws(() => rotatePqcKeyMsgFromMnemonic({ ...base, oldDerivation: 'adapter', newDerivation: 'bridge' }), /deprecated for new keys/);
  assert.ok(rotatePqcKeyMsgFromMnemonic(base));
});
