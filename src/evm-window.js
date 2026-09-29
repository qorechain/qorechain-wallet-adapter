// @qorechain/wallet-adapter — the EVM-lane post-quantum authorisation window
// (chain v3.2.0; testnet qorechain-diana applied it at height 5,920,000).
//
// THE PROBLEM. QoreChain requires an ML-DSA-87 hybrid signature on the Cosmos
// lane. The EVM lane cannot carry one: MetaMask signs secp256k1 over an
// Ethereum transaction, has no way to attach a second signature, and does not
// implement eth_signTransaction, so there is not even a moment between signing
// and broadcast in which one could be added.
//
// So the post-quantum signature travels AHEAD of the transaction instead of
// with it. The account opens a bounded WINDOW with a Cosmos-lane message —
// itself subject to the ordinary PQC requirement — and from v3.2.0 the EVM lane
// admits only transactions covered by a live window from an account that also
// holds a registered post-quantum key. Inside a window, MetaMask and every
// other EVM tool work unmodified: the check reads chain state, not the
// transaction. The nearest familiar shape is an ERC-20 approval.
//
// A window is bounded three ways at once, because a stolen classical key is
// worth exactly what an open window admits:
//   blocks     — an authorisation that never expires is a permanent downgrade
//                to classical security;
//   max_txs    — the bound a person can actually reason about ("three sends");
//   max_value  — uqor, counting transferred value PLUS the maximum fee each
//                admitted transaction could pay (gas limit x gas fee cap).
//                Value alone would leave the account drainable through fees,
//                because the holder of the classical key sets the gas price.
// Any one of the three running out closes the window in practice.
//
// THIS MODULE OPENS NOTHING BY ITSELF. It gives a wallet the building blocks —
// the two message composers, the status query and the refusal classifier — so
// the wallet can show an EXPLICIT authorisation step with the three limits on
// it. Silently opening a window before a send would hand back the property the
// window exists to create.
//
// THE ORDERING TRAP. QoreChain unifies the identity, so the Cosmos sequence IS
// the EVM nonce, and opening a window ADVANCES it (measured on diana: 2 before,
// 3 after). The order is: open the window, THEN read the nonce, THEN sign the
// EVM transaction. Signing first gives "nonce too low".

export const MSG_OPEN_EVM_WINDOW_TYPE_URL = '/qorechain.pqc.v1.MsgOpenEVMWindow';
export const MSG_CLOSE_EVM_WINDOW_TYPE_URL = '/qorechain.pqc.v1.MsgCloseEVMWindow';

/**
 * The chain's MaxEVMWindowBlocks. The chain constant is commented "about 24
 * hours at 5s blocks", but NO QoreChain network runs at 5s: diana is at ~1.03 s
 * (17280 blocks ≈ 5 h) and mainnet at ~3.1 s (≈ 15 h). Never print "24 hours"
 * in a wallet — say "up to 17280 blocks", or compute from the network's own
 * recent block time.
 */
export const MAX_EVM_WINDOW_BLOCKS = 17280n;
/** The chain's MaxEVMWindowTxs. */
export const MAX_EVM_WINDOW_TXS = 1000n;

/** REST path of the window query, relative to the LCD root. */
export const EVM_WINDOW_QUERY_PATH = '/qorechain/pqc/v1/evm_window';

const te = new TextEncoder();

// ---------------------------------------------------------------------------
// minimal protobuf writer/reader (same house style as ./framing.js — the
// package deliberately carries no generated qorechain types)
// ---------------------------------------------------------------------------

function varintBytes(n) {
  const out = [];
  let v = BigInt(n);
  do {
    let b = Number(v & 0x7fn);
    v >>= 7n;
    if (v > 0n) b |= 0x80;
    out.push(b);
  } while (v > 0n);
  return out;
}

function varintField(fieldNo, value) {
  return [(fieldNo << 3) | 0, ...varintBytes(value)];
}

function stringField(fieldNo, str) {
  const bytes = te.encode(str);
  return [(fieldNo << 3) | 2, ...varintBytes(bytes.length), ...bytes];
}

// ---------------------------------------------------------------------------
// client-side validation, mirroring the chain's MsgOpenEVMWindow.Validate
// ---------------------------------------------------------------------------

function requireAddress(fn, field, v) {
  if (typeof v !== 'string' || v.trim() === '') {
    throw new Error(`${fn}: ${field} is required (the bech32 account that owns the window)`);
  }
  return v;
}

// Accepts number | bigint | decimal string. Rejects floats, NaN, hex, blanks —
// a window bound that was silently truncated is a security parameter chosen by
// accident.
function toExactInt(fn, field, v) {
  if (v === undefined || v === null || v === '') {
    throw new Error(`${fn}: ${field} is required — every window bound must be given explicitly, there is no default`);
  }
  if (typeof v === 'bigint') return v;
  if (typeof v === 'number') {
    if (!Number.isFinite(v) || !Number.isInteger(v)) {
      throw new Error(`${fn}: ${field} must be a whole number, got ${v}`);
    }
    return BigInt(v);
  }
  if (typeof v === 'string') {
    if (!/^-?\d+$/.test(v.trim())) {
      throw new Error(`${fn}: ${field} must be a whole number, got ${JSON.stringify(v)}`);
    }
    return BigInt(v.trim());
  }
  throw new Error(`${fn}: ${field} must be a number, bigint or integer string, got ${typeof v}`);
}

/**
 * Validate the three window bounds exactly as the chain's ValidateBasic does,
 * and return them normalised (blocks/maxTxs as BigInt, maxValue as a decimal
 * uqor string). Exported so a wallet can validate its authorisation form before
 * it ever builds a transaction. `fn` only shapes the error message.
 */
export function validateEvmWindowBounds({ blocks, maxTxs, maxValue }, fn = 'openEvmWindowMsg') {
  const b = toExactInt(fn, 'blocks', blocks);
  if (b <= 0n) {
    throw new Error(`${fn}: blocks must be greater than 0 (got ${b}); a window that lasts no blocks admits nothing`);
  }
  if (b > MAX_EVM_WINDOW_BLOCKS) {
    throw new Error(`${fn}: blocks ${b} exceeds the maximum ${MAX_EVM_WINDOW_BLOCKS} (MaxEVMWindowBlocks)`);
  }

  const t = toExactInt(fn, 'max_txs', maxTxs);
  if (t <= 0n) {
    throw new Error(`${fn}: max_txs must be greater than 0 (got ${t}); a window that admits nothing is a mistake, not a policy`);
  }
  if (t > MAX_EVM_WINDOW_TXS) {
    throw new Error(`${fn}: max_txs ${t} exceeds the maximum ${MAX_EVM_WINDOW_TXS} (MaxEVMWindowTxs)`);
  }

  const v = toExactInt(fn, 'max_value', maxValue);
  if (v <= 0n) {
    throw new Error(`${fn}: max_value must be greater than 0 (got ${v}); it is a uqor amount bounding transferred value PLUS the maximum fee (gas limit x gas fee cap)`);
  }

  return { blocks: b, maxTxs: t, maxValue: v.toString() };
}

// ---------------------------------------------------------------------------
// message composers — Any-encoded, ready for QoreChainSigner.signHybrid
// ---------------------------------------------------------------------------

/**
 * MsgOpenEVMWindow, Any-encoded: `{ typeUrl, value: Uint8Array }`, the shape
 * `QoreChainSigner.signHybrid({ messages: [...] })` and `signHybridEth` carry.
 *
 * It is an ORDINARY Cosmos-lane protobuf message with no client-built
 * sign-bytes of its own: it travels the existing hybrid-signing path, which is
 * the whole point — the classical key alone can never open a window.
 *
 * Opening REPLACES any existing window rather than adding to it, and it
 * advances the account sequence, which on QoreChain is also the EVM nonce. Read
 * the nonce AFTER this lands.
 */
export function openEvmWindowMsg({ sender, blocks, maxTxs, maxValue }) {
  const fn = 'openEvmWindowMsg';
  requireAddress(fn, 'sender', sender);
  const bounds = validateEvmWindowBounds({ blocks, maxTxs, maxValue }, fn);
  return {
    typeUrl: MSG_OPEN_EVM_WINDOW_TYPE_URL,
    value: Uint8Array.from([
      ...stringField(1, sender),            // sender
      ...varintField(2, bounds.blocks),     // blocks
      ...varintField(3, bounds.maxTxs),     // max_txs
      ...stringField(4, bounds.maxValue),   // max_value (cosmos.Int, uqor)
    ]),
  };
}

/**
 * MsgCloseEVMWindow, Any-encoded. Revokes the sender's window immediately —
 * it takes effect in the same block, so a wallet can offer "end authorisation"
 * without waiting for expiry.
 */
export function closeEvmWindowMsg({ sender }) {
  requireAddress('closeEvmWindowMsg', 'sender', sender);
  return {
    typeUrl: MSG_CLOSE_EVM_WINDOW_TYPE_URL,
    value: Uint8Array.from(stringField(1, sender)),
  };
}

/**
 * Decode either window message back from its Any encoding — the inverse of the
 * composers, for inspection, tests and confirmation screens that want to show
 * what they are about to sign. Numbers come back as BigInt, max_value as the
 * exact decimal string. Throws on an unknown typeUrl.
 */
export function decodeEvmWindowMsg({ typeUrl, value } = {}) {
  if (typeUrl !== MSG_OPEN_EVM_WINDOW_TYPE_URL && typeUrl !== MSG_CLOSE_EVM_WINDOW_TYPE_URL) {
    throw new Error(`decodeEvmWindowMsg: not an EVM-window message: ${JSON.stringify(typeUrl)}`);
  }
  const buf = value instanceof Uint8Array ? value : Uint8Array.from(value || []);
  const td = new TextDecoder();
  const out = {};
  let i = 0;
  const readVarint = () => {
    let shift = 0n, v = 0n;
    for (;;) {
      if (i >= buf.length) throw new Error('decodeEvmWindowMsg: truncated varint');
      const b = buf[i++];
      v |= BigInt(b & 0x7f) << shift;
      if ((b & 0x80) === 0) return v;
      shift += 7n;
    }
  };
  while (i < buf.length) {
    const key = Number(readVarint());
    const field = key >>> 3;
    const wire = key & 7;
    if (wire === 0) {
      const v = readVarint();
      if (field === 2) out.blocks = v;
      else if (field === 3) out.maxTxs = v;
    } else if (wire === 2) {
      const len = Number(readVarint());
      const s = td.decode(buf.subarray(i, i + len));
      i += len;
      if (field === 1) out.sender = s;
      else if (field === 4) out.maxValue = s;
    } else {
      throw new Error(`decodeEvmWindowMsg: unexpected wire type ${wire} for field ${field}`);
    }
  }
  return typeUrl === MSG_CLOSE_EVM_WINDOW_TYPE_URL ? { sender: out.sender } : out;
}

// ---------------------------------------------------------------------------
// status query
// ---------------------------------------------------------------------------

function toBig(v) {
  if (v === undefined || v === null || v === '') return 0n;
  if (typeof v === 'bigint') return v;
  // The node renders every one of these as a JSON STRING precisely so nothing
  // has to survive a float. Keep it that way: BigInt(String(v)) throws on
  // garbage instead of guessing, and never truncates above 2^53.
  return BigInt(String(v).trim());
}

const EMPTY_WINDOW = Object.freeze({
  found: false, live: false,
  openedHeight: null, expiryHeight: null,
  maxTxs: null, usedTxs: null,
  maxValue: null, usedValue: null,
  remainingBlocks: null, remainingTxs: null, remainingValue: null,
});

/**
 * Parse a `QueryEVMWindowResponse` body into the typed status. Exported
 * separately from the fetch so a caller with its own transport (gRPC-gateway,
 * a cached proxy, a test fixture) can use the same parser.
 *
 * Every numeric field comes back as a BigInt — NEVER a float. `max_value`,
 * `used_value` and `remaining_value` are cosmos.Int uqor amounts and routinely
 * exceed 2^53, where Number silently loses the low digits.
 */
export function parseEvmWindow(body) {
  if (!body || typeof body !== 'object') {
    throw new Error('parseEvmWindow: expected a QueryEVMWindowResponse object');
  }
  // found:false is a 200 answer, not an error — the query is safe to poll.
  if (body.found !== true && String(body.found) !== 'true') return { ...EMPTY_WINDOW };
  return {
    found: true,
    live: body.live === true || String(body.live) === 'true',
    openedHeight: toBig(body.opened_height ?? body.openedHeight),
    expiryHeight: toBig(body.expiry_height ?? body.expiryHeight),
    maxTxs: toBig(body.max_txs ?? body.maxTxs),
    usedTxs: toBig(body.used_txs ?? body.usedTxs),
    maxValue: toBig(body.max_value ?? body.maxValue),
    usedValue: toBig(body.used_value ?? body.usedValue),
    remainingBlocks: toBig(body.remaining_blocks ?? body.remainingBlocks),
    remainingTxs: toBig(body.remaining_txs ?? body.remainingTxs),
    remainingValue: toBig(body.remaining_value ?? body.remainingValue),
  };
}

/**
 * `GET {rest}/qorechain/pqc/v1/evm_window/{address}` → the typed status.
 *
 * The node answers 200 with `found:false` when there is no window, so this is
 * safe to poll and does not throw for the ordinary "no window yet" case. A
 * wallet uses it to decide whether it can REUSE a live window instead of
 * opening another one: opening replaces the old window and costs a Cosmos
 * transaction (and a nonce).
 */
export async function fetchEvmWindow({ rest, address, fetch = globalThis.fetch } = {}) {
  if (typeof rest !== 'string' || rest.trim() === '') {
    throw new Error("fetchEvmWindow: `rest` is required (the network's LCD URL)");
  }
  if (typeof address !== 'string' || address.trim() === '') {
    throw new Error('fetchEvmWindow: `address` is required (the bech32 account)');
  }
  if (typeof fetch !== 'function') {
    throw new Error('fetchEvmWindow: no fetch implementation available; pass one as `fetch`');
  }
  const base = rest.trim().replace(/\/+$/, '');
  const url = `${base}${EVM_WINDOW_QUERY_PATH}/${encodeURIComponent(address.trim())}`;
  let res;
  try {
    res = await fetch(url, { headers: { accept: 'application/json' } });
  } catch (e) {
    throw new Error(`fetchEvmWindow: ${url} failed (${e && e.message ? e.message : e})`);
  }
  if (!res || !res.ok) {
    throw new Error(`fetchEvmWindow: HTTP ${res ? res.status : 'no response'} from ${url}`);
  }
  return parseEvmWindow(await res.json());
}

// ---------------------------------------------------------------------------
// refusal classifier
// ---------------------------------------------------------------------------

/** The four states the EVM lane can refuse a transaction in. */
export const EVM_WINDOW_REJECTION_KINDS = Object.freeze(['no-window', 'exhausted', 'invalid', 'no-pqc-key']);

/**
 * What a wallet should do about each kind. `no-pqc-key` is deliberately its own
 * state: opening a window cannot fix it, the account has to REGISTER a
 * post-quantum key first.
 */
export const EVM_WINDOW_REMEDIES = Object.freeze({
  'no-window': 'Open an EVM authorisation window (MsgOpenEVMWindow) on the Cosmos lane, then re-read the nonce and sign again.',
  exhausted: 'The window ran out of blocks, transactions or value. Open a new one with bounds that cover what is left to do.',
  invalid: 'The window request or the window itself was refused as invalid. Check blocks (1..17280), max_txs (1..1000) and max_value (> 0, uqor).',
  'no-pqc-key': 'Register a post-quantum key for this account first (MsgRegisterPQCKeyV2). A window cannot be opened, and the EVM lane cannot be used, without one.',
});

const NO_PQC_KEY_RE = /no registered post-quantum key/i;
const NO_WINDOW_RE = /no open EVM authorisation window/i;
const EXHAUSTED_RE = /EVM authorisation window exhausted|authorisation window for \S+ does not admit this transaction/i;
const INVALID_RE = /invalid EVM authorisation window/i;

// Broadcast failures reach a wallet in a dozen shapes: a cosmjs
// BroadcastTxError, a DeliverTxResponse, a plain Error, a string, and — over
// EVM JSON-RPC — a nested viem/ethers error whose only trace of the chain's
// refusal is the text carried in `details` / `shortMessage` / `cause`.
function collectTexts(x, depth = 0, acc = []) {
  if (x === undefined || x === null || depth > 6) return acc;
  if (typeof x === 'string') { acc.push(x); return acc; }
  if (typeof x !== 'object') return acc;
  for (const f of [x.log, x.rawLog, x.raw_log, x.message, x.details, x.shortMessage, x.reason, x.description]) {
    if (typeof f === 'string') acc.push(f);
  }
  if (x.error) collectTexts(x.error, depth + 1, acc);
  if (x.data && typeof x.data !== 'string') collectTexts(x.data, depth + 1, acc);
  else if (typeof x.data === 'string') acc.push(x.data);
  if (x.cause) collectTexts(x.cause, depth + 1, acc);
  if (Array.isArray(x.metaMessages)) for (const m of x.metaMessages) if (typeof m === 'string') acc.push(m);
  return acc;
}

/**
 * Classify a broadcast failure as an EVM-window refusal.
 *
 * Returns one of `'no-window' | 'exhausted' | 'invalid' | 'no-pqc-key'`, or
 * `null` when the error is something else — so it reads as a predicate
 * (`if (isEvmWindowRejection(err))`) while still saying WHICH state it is.
 *
 * Two sources, both needed. On the Cosmos lane the refusal arrives structured:
 * codespace `pqc`, code 26 (no window), 27 (exhausted), 28 (invalid). Over EVM
 * JSON-RPC there is no codespace at all — the refusal arrives as a broadcast
 * error carrying the chain's own text — so the text is matched too, and it is
 * matched FIRST: code 26 covers both "no window" and "no registered
 * post-quantum key", and only the text tells those two apart. They have
 * different remedies (open a window vs. register a key), so they are different
 * kinds here.
 *
 * Code 26/27/28 from any codespace other than `pqc` does NOT match.
 */
export function isEvmWindowRejection(errOrResult) {
  if (errOrResult === undefined || errOrResult === null) return null;

  const texts = collectTexts(errOrResult);
  // Most specific first: a no-key refusal also names the EVM lane.
  for (const t of texts) if (NO_PQC_KEY_RE.test(t)) return 'no-pqc-key';
  for (const t of texts) {
    if (EXHAUSTED_RE.test(t)) return 'exhausted';
    if (NO_WINDOW_RE.test(t)) return 'no-window';
    if (INVALID_RE.test(t)) return 'invalid';
  }

  if (typeof errOrResult === 'object' && errOrResult.codespace === 'pqc') {
    switch (Number(errOrResult.code)) {
      case 26: return 'no-window';
      case 27: return 'exhausted';
      case 28: return 'invalid';
      default: return null;
    }
  }
  return null;
}
