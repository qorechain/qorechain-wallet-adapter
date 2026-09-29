import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  MSG_OPEN_EVM_WINDOW_TYPE_URL, MSG_CLOSE_EVM_WINDOW_TYPE_URL,
  MAX_EVM_WINDOW_BLOCKS, MAX_EVM_WINDOW_TXS,
  openEvmWindowMsg, closeEvmWindowMsg, decodeEvmWindowMsg, validateEvmWindowBounds,
  fetchEvmWindow, parseEvmWindow,
  isEvmWindowRejection, EVM_WINDOW_REJECTION_KINDS, EVM_WINDOW_REMEDIES,
  QoreChainSigner,
} from '../src/index.js';
import { TxBody } from 'cosmjs-types/cosmos/tx/v1beta1/tx.js';

const SENDER = 'qor1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqzutd0j';

// ---------------------------------------------------------------------------
// composers: type URL + encoded bytes round-trip
// ---------------------------------------------------------------------------

test('openEvmWindowMsg: type URL + protobuf bytes round-trip exactly', () => {
  const msg = openEvmWindowMsg({ sender: SENDER, blocks: 300, maxTxs: 5, maxValue: '2000000' });
  assert.equal(msg.typeUrl, MSG_OPEN_EVM_WINDOW_TYPE_URL);
  assert.ok(msg.value instanceof Uint8Array, 'value must be Any-encoded bytes');

  const back = decodeEvmWindowMsg(msg);
  assert.equal(back.sender, SENDER);
  assert.equal(back.blocks, 300n);
  assert.equal(back.maxTxs, 5n);
  assert.equal(back.maxValue, '2000000'); // cosmos.Int travels as a STRING

  // Field order + wire types, byte for byte: 0x0a sender, 0x10 blocks (varint),
  // 0x18 max_txs (varint), 0x22 max_value (string).
  assert.equal(msg.value[0], 0x0a);
  const i = 2 + SENDER.length;
  assert.equal(msg.value[i], 0x10);
  assert.equal(msg.value[i + 1], 0xac); // 300 = 0xac 0x02 as a varint
  assert.equal(msg.value[i + 2], 0x02);

  // Golden vector: byte-identical to what the chain's own generated encoder
  // produces for the same message (qorechain-core x/pqc/types, tag v3.2.0).
  assert.equal(
    [...msg.value].map((b) => b.toString(16).padStart(2, '0')).join(''),
    '0a2a716f723171717171717171717171717171717171717171717171717171717171717171717a'
    + '757464306a10ac021805220732303030303030',
  );
});

test('openEvmWindowMsg: number, bigint and string bounds all encode identically', () => {
  const a = openEvmWindowMsg({ sender: SENDER, blocks: 17280, maxTxs: 1000, maxValue: 12345 });
  const b = openEvmWindowMsg({ sender: SENDER, blocks: 17280n, maxTxs: 1000n, maxValue: 12345n });
  const c = openEvmWindowMsg({ sender: SENDER, blocks: '17280', maxTxs: '1000', maxValue: '12345' });
  assert.deepEqual(a.value, b.value);
  assert.deepEqual(a.value, c.value);
  // The maxima themselves are accepted; only above them is refused.
  assert.equal(decodeEvmWindowMsg(a).blocks, MAX_EVM_WINDOW_BLOCKS);
  assert.equal(decodeEvmWindowMsg(a).maxTxs, MAX_EVM_WINDOW_TXS);
});

test('closeEvmWindowMsg: type URL + sender only', () => {
  const msg = closeEvmWindowMsg({ sender: SENDER });
  assert.equal(msg.typeUrl, MSG_CLOSE_EVM_WINDOW_TYPE_URL);
  assert.deepEqual(decodeEvmWindowMsg(msg), { sender: SENDER });
  assert.equal(msg.value.length, 2 + SENDER.length);
  // Golden vector from the chain's own encoder.
  assert.equal(
    [...msg.value].map((b) => b.toString(16).padStart(2, '0')).join(''),
    '0a2a716f723171717171717171717171717171717171717171717171717171717171717171717a757464306a',
  );
});

test('composers produce messages a TxBody accepts (the signHybrid carrier shape)', () => {
  const messages = [
    openEvmWindowMsg({ sender: SENDER, blocks: 300, maxTxs: 3, maxValue: '1000000' }),
    closeEvmWindowMsg({ sender: SENDER }),
  ];
  const bodyBytes = TxBody.encode(TxBody.fromPartial({ messages, memo: '', timeoutHeight: 0n })).finish();
  const decoded = TxBody.decode(bodyBytes);
  assert.equal(decoded.messages.length, 2);
  assert.equal(decoded.messages[0].typeUrl, MSG_OPEN_EVM_WINDOW_TYPE_URL);
  assert.equal(decoded.messages[1].typeUrl, MSG_CLOSE_EVM_WINDOW_TYPE_URL);
  assert.deepEqual(decodeEvmWindowMsg(decoded.messages[0]), {
    sender: SENDER, blocks: 300n, maxTxs: 3n, maxValue: '1000000',
  });
  // And a QoreChainSigner really carries them (the ML-DSA part is covered elsewhere).
  assert.ok(typeof QoreChainSigner.prototype.signHybrid === 'function');
});

test('sender is required', () => {
  assert.throws(() => openEvmWindowMsg({ blocks: 1, maxTxs: 1, maxValue: 1 }), /sender is required/);
  assert.throws(() => closeEvmWindowMsg({ sender: '' }), /sender is required/);
});

// ---------------------------------------------------------------------------
// validation bounds — each refusal must NAME the bound it broke
// ---------------------------------------------------------------------------

const ok = { sender: SENDER, blocks: 300, maxTxs: 5, maxValue: '2000000' };

test('blocks: 0 and 17281 are refused, naming blocks and the maximum', () => {
  assert.throws(() => openEvmWindowMsg({ ...ok, blocks: 0 }), /blocks must be greater than 0/);
  assert.throws(() => openEvmWindowMsg({ ...ok, blocks: 17281 }), /blocks 17281 exceeds the maximum 17280/);
  assert.throws(() => openEvmWindowMsg({ ...ok, blocks: -1 }), /blocks must be greater than 0/);
});

test('max_txs: 0 and 1001 are refused, naming max_txs and the maximum', () => {
  assert.throws(() => openEvmWindowMsg({ ...ok, maxTxs: 0 }), /max_txs must be greater than 0/);
  assert.throws(() => openEvmWindowMsg({ ...ok, maxTxs: 1001 }), /max_txs 1001 exceeds the maximum 1000/);
});

test('max_value: 0 and negative are refused, naming max_value', () => {
  assert.throws(() => openEvmWindowMsg({ ...ok, maxValue: 0 }), /max_value must be greater than 0/);
  assert.throws(() => openEvmWindowMsg({ ...ok, maxValue: '-1' }), /max_value must be greater than 0/);
  assert.throws(() => openEvmWindowMsg({ ...ok, maxValue: -5n }), /max_value must be greater than 0/);
});

test('every bound is REQUIRED — omitting one is refused, never defaulted', () => {
  assert.throws(() => openEvmWindowMsg({ sender: SENDER, maxTxs: 5, maxValue: '1' }), /blocks is required/);
  assert.throws(() => openEvmWindowMsg({ sender: SENDER, blocks: 1, maxValue: '1' }), /max_txs is required/);
  assert.throws(() => openEvmWindowMsg({ sender: SENDER, blocks: 1, maxTxs: 1 }), /max_value is required/);
});

test('floats and garbage are refused rather than truncated', () => {
  assert.throws(() => openEvmWindowMsg({ ...ok, blocks: 1.5 }), /blocks must be a whole number/);
  assert.throws(() => openEvmWindowMsg({ ...ok, maxValue: '1e6' }), /max_value must be a whole number/);
  assert.throws(() => openEvmWindowMsg({ ...ok, maxTxs: NaN }), /max_txs must be a whole number/);
});

test('validateEvmWindowBounds normalises without building a message', () => {
  assert.deepEqual(validateEvmWindowBounds({ blocks: '300', maxTxs: 5, maxValue: 2000000n }), {
    blocks: 300n, maxTxs: 5n, maxValue: '2000000',
  });
});

// ---------------------------------------------------------------------------
// query parsing — both shapes, numbers kept EXACT
// ---------------------------------------------------------------------------

function fetchOnce(body, { status = 200 } = {}) {
  const calls = [];
  const fetch = async (url) => {
    calls.push(url);
    return { ok: status >= 200 && status < 300, status, json: async () => body };
  };
  return { fetch, calls };
}

test('fetchEvmWindow: found:false is a normal 200 answer, safe to poll', async () => {
  const { fetch, calls } = fetchOnce({ found: false });
  const w = await fetchEvmWindow({ rest: 'https://api.example/', address: SENDER, fetch });
  assert.equal(calls[0], `https://api.example/qorechain/pqc/v1/evm_window/${SENDER}`);
  assert.equal(w.found, false);
  assert.equal(w.live, false);
  assert.equal(w.expiryHeight, null);
  assert.equal(w.remainingValue, null);
});

test('fetchEvmWindow: the live shape parses to BigInt, never a float', async () => {
  const live = {
    found: true, live: true, opened_height: '6069608', expiry_height: '6069908',
    max_txs: '5', used_txs: '1', max_value: '2000000', used_value: '3363',
    remaining_blocks: '286', remaining_txs: '4', remaining_value: '1996637',
  };
  const { fetch } = fetchOnce(live);
  const w = await fetchEvmWindow({ rest: 'https://api.example', address: SENDER, fetch });
  assert.equal(w.found, true);
  assert.equal(w.live, true);
  assert.equal(w.openedHeight, 6069608n);
  assert.equal(w.expiryHeight, 6069908n);
  assert.equal(w.maxTxs, 5n);
  assert.equal(w.usedTxs, 1n);
  assert.equal(w.maxValue, 2000000n);
  assert.equal(w.usedValue, 3363n);          // the measured diana consumption
  assert.equal(w.remainingBlocks, 286n);
  assert.equal(w.remainingTxs, 4n);
  assert.equal(w.remainingValue, 1996637n);
  for (const k of ['openedHeight', 'expiryHeight', 'maxTxs', 'usedTxs', 'maxValue', 'usedValue', 'remainingBlocks', 'remainingTxs', 'remainingValue']) {
    assert.equal(typeof w[k], 'bigint', `${k} must be a BigInt`);
  }
});

test('query values above 2^53 survive exactly (no float truncation)', () => {
  // 9,007,199,254,740,993 uqor = 2^53 + 1. Number() would render it as 2^53.
  const big = '9007199254740993';
  const w = parseEvmWindow({
    found: true, live: true, opened_height: '1', expiry_height: '2',
    max_txs: '1', used_txs: '0',
    max_value: big, used_value: '0', remaining_blocks: '1', remaining_txs: '1', remaining_value: big,
  });
  assert.equal(w.maxValue, 9007199254740993n);
  assert.equal(w.maxValue.toString(), big);
  assert.notEqual(w.maxValue, BigInt(Number(big))); // proves Number() would have lost it
  assert.equal(w.remainingValue.toString(), big);
});

test('fetchEvmWindow: a non-200 throws, and rest/address are required', async () => {
  const { fetch } = fetchOnce({}, { status: 500 });
  await assert.rejects(() => fetchEvmWindow({ rest: 'https://api.example', address: SENDER, fetch }), /HTTP 500/);
  await assert.rejects(() => fetchEvmWindow({ address: SENDER, fetch }), /`rest` is required/);
  await assert.rejects(() => fetchEvmWindow({ rest: 'https://api.example', fetch }), /`address` is required/);
});

// ---------------------------------------------------------------------------
// the refusal classifier
// ---------------------------------------------------------------------------

test('classifier: codespace pqc codes 26 / 27 / 28', () => {
  assert.equal(isEvmWindowRejection({ codespace: 'pqc', code: 26 }), 'no-window');
  assert.equal(isEvmWindowRejection({ codespace: 'pqc', code: 27 }), 'exhausted');
  assert.equal(isEvmWindowRejection({ codespace: 'pqc', code: 28 }), 'invalid');
  assert.equal(isEvmWindowRejection({ codespace: 'pqc', code: '26' }), 'no-window');
});

test("classifier: the chain's own text, as it arrives over EVM JSON-RPC", () => {
  const noWindow = `account ${SENDER} has no open EVM authorisation window; open one with MsgOpenEVMWindow, signed on the Cosmos lane with the account's post-quantum key`;
  const exhausted = `the EVM authorisation window for ${SENDER} does not admit this transaction (remaining: 0 blocks, 0 transactions, 0 uqor; this transaction needs 3363 uqor)`;

  // bare strings
  assert.equal(isEvmWindowRejection(noWindow), 'no-window');
  assert.equal(isEvmWindowRejection(exhausted), 'exhausted');
  // a nested viem-shaped JSON-RPC error: no codespace anywhere, text only
  const rpcErr = {
    name: 'TransactionExecutionError',
    shortMessage: 'An unknown RPC error occurred.',
    cause: { code: -32000, message: 'failed to execute message', data: { message: noWindow } },
  };
  assert.equal(isEvmWindowRejection(rpcErr), 'no-window');
  // cosmjs DeliverTxResponse / BroadcastTxError shapes
  assert.equal(isEvmWindowRejection({ code: 27, rawLog: exhausted }), 'exhausted');
  assert.equal(isEvmWindowRejection(new Error(`broadcast failed: ${exhausted}`)), 'exhausted');
  assert.equal(isEvmWindowRejection({ log: 'invalid EVM authorisation window: blocks must be positive' }), 'invalid');
});

test('classifier: "no registered post-quantum key" is its OWN kind, not no-window', () => {
  const noKey = `account ${SENDER} has no registered post-quantum key; the EVM lane requires one, like every other lane`;
  // The chain raises this one under code 26, the same code as "no window" — only
  // the text tells them apart, and they have different remedies.
  assert.equal(isEvmWindowRejection(noKey), 'no-pqc-key');
  assert.equal(isEvmWindowRejection({ codespace: 'pqc', code: 26, rawLog: noKey }), 'no-pqc-key');
  assert.equal(isEvmWindowRejection({ codespace: 'pqc', code: 28, log: noKey }), 'no-pqc-key');
  assert.match(EVM_WINDOW_REMEDIES['no-pqc-key'], /Register a post-quantum key/);
  assert.notEqual(EVM_WINDOW_REMEDIES['no-pqc-key'], EVM_WINDOW_REMEDIES['no-window']);
});

test('classifier: anything else must NOT match', () => {
  assert.equal(isEvmWindowRejection(null), null);
  assert.equal(isEvmWindowRejection(undefined), null);
  assert.equal(isEvmWindowRejection('nonce too low'), null);
  assert.equal(isEvmWindowRejection(new Error('insufficient funds for gas * price + value')), null);
  // right codes, WRONG codespace
  assert.equal(isEvmWindowRejection({ codespace: 'sdk', code: 26 }), null);
  assert.equal(isEvmWindowRejection({ codespace: 'evm', code: 27 }), null);
  // right codespace, unrelated code (21 is the hybrid sign-bytes refusal)
  assert.equal(isEvmWindowRejection({ codespace: 'pqc', code: 21, rawLog: 'hybrid PQC signature verification failed' }), null);
  // success is not a refusal
  assert.equal(isEvmWindowRejection({ code: 0, codespace: '', rawLog: '' }), null);
});

test('classifier: every kind has a remedy, and the kind list matches', () => {
  assert.deepEqual([...EVM_WINDOW_REJECTION_KINDS].sort(), ['exhausted', 'invalid', 'no-pqc-key', 'no-window']);
  for (const k of EVM_WINDOW_REJECTION_KINDS) {
    assert.equal(typeof EVM_WINDOW_REMEDIES[k], 'string');
    assert.ok(EVM_WINDOW_REMEDIES[k].length > 20, `${k} needs a usable remedy`);
  }
});

// ---------------------------------------------------------------------------
// the package must not open a window behind the caller's back
// ---------------------------------------------------------------------------

test('no automatic opening: the composers are pure and do no I/O', async () => {
  const realFetch = globalThis.fetch;
  let called = false;
  globalThis.fetch = async () => { called = true; throw new Error('the composers must not touch the network'); };
  try {
    openEvmWindowMsg({ sender: SENDER, blocks: 300, maxTxs: 5, maxValue: '2000000' });
    closeEvmWindowMsg({ sender: SENDER });
  } finally {
    globalThis.fetch = realFetch;
  }
  assert.equal(called, false);
});
