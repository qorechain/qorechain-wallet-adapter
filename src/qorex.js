// @qorechain/wallet-adapter — QoreX, the browser/in-app wallet provider.
//
// WHY A dApp CANNOT SIGN A QORECHAIN TRANSACTION ITSELF. Every transaction from
// an account with a registered post-quantum key must carry BOTH a secp256k1 and
// an ML-DSA-87 signature. Only the wallet holds the ML-DSA key, so a page can
// never assemble that transaction, and `signDirect` — which signs a SignDoc the
// page built, byte for byte — is refused on QoreChain unless the body already
// carries the hybrid extension, which a page cannot produce either.
//
// So the page sends MESSAGES and the wallet does the rest: it shows the decoded
// messages and the fee, builds the transaction for the selected account, adds
// the hybrid signature (registering the account's PQC key first if this is its
// first transaction), broadcasts, and resolves with the result.
//
// Requires QoreX extension >= 0.3.5 or app >= 1.1.5. Feature-detect rather than
// version-check: `capabilities` names what the installed build can actually do.
//
// See qorex docs/DAPP-INTEGRATION.md for the wallet side of this contract.

/** The provider object QoreX injects for the QoreChain (Cosmos) lane. */
import { MsgExec, MsgGrant } from 'cosmjs-types/cosmos/authz/v1beta1/tx.js';
import { GenericAuthorization } from 'cosmjs-types/cosmos/authz/v1beta1/authz.js';

export function getQorexNative() {
  return globalThis.window?.qorex?.native;
}

/** The capability string a build advertises when it can sign and broadcast. */
export const QOREX_SIGN_AND_BROADCAST = 'signAndBroadcast';

/**
 * Whether QoreX is present AND this build can sign and broadcast. False for an
 * older QoreX, which is the case worth telling the user about: the remedy is an
 * update, not a different wallet.
 */
export function hasQorexSignAndBroadcast(provider = getQorexNative()) {
  return Boolean(provider?.capabilities?.includes?.(QOREX_SIGN_AND_BROADCAST));
}

/** The chain ids QoreX serves. A dApp cannot switch the wallet's network. */
export const QOREX_CHAIN_IDS = Object.freeze(['qorechain-vladi', 'qorechain-diana']);

/** Bounds the wallet enforces; checked here so a mistake fails before a prompt. */
export const QOREX_MAX_MESSAGES = 32;
export const QOREX_MAX_MEMO_BYTES = 256;
export const QOREX_MIN_GAS_LIMIT = 100_000;
export const QOREX_MAX_GAS_LIMIT = 5_000_000;

/**
 * Messages the wallet refuses from a dApp, directly, inside authz MsgExec, or
 * as the message of an authz GenericAuthorization grant:
 * PQC key management (the wallet manages the account's keys itself, and a dApp
 * that could rotate them could take the account) and anything that grants
 * standing authority over the account.
 */
export const QOREX_REFUSED_TYPE_URLS = Object.freeze([
  '/qorechain.pqc.v1.MsgRegisterPQCKey',
  '/qorechain.pqc.v1.MsgRegisterPQCKeyV2',
  '/qorechain.pqc.v1.MsgMigratePQCKey',
  '/qorechain.pqc.v1.MsgRotatePQCKey',
  // The rest of the chain's PQC key-management list: the account's ML-KEM key
  // (whoever replaces it reads what is encrypted to the account from then on)
  // and its PQC multisig member set.
  '/qorechain.pqc.v1.MsgRegisterKEMKey',
  '/qorechain.pqc.v1.MsgRemoveKEMKey',
  '/qorechain.pqc.v1.MsgRegisterPQCMultisig',
  // Who may spend from the account, and how much. A dApp asking for these is
  // asking for standing authority over the account, so only the wallet's own
  // screens can send them.
  '/qorechain.abstractaccount.v1.MsgRegisterAuthenticator',
  '/qorechain.abstractaccount.v1.MsgRevokeAuthenticator',
  '/qorechain.abstractaccount.v1.MsgUpdateSpendingRules',
  '/qorechain.abstractaccount.v1.MsgCreateAbstractAccount',
  '/qorechain.pqc.v1.MsgOpenEVMWindow',
  '/qorechain.pqc.v1.MsgCloseEVMWindow',
  '/qorechain.pqc.v1.MsgAuthorizeEVMDelegation',
  '/qorechain.pqc.v1.MsgClearEVMDelegation',
]);

const ACCOUNT_AUTHORITY_TYPE_URLS = new Set(QOREX_REFUSED_TYPE_URLS.slice(QOREX_REFUSED_TYPE_URLS.indexOf(
  '/qorechain.abstractaccount.v1.MsgRegisterAuthenticator',
)));

/** Why the wallet refuses this message type, in words a dApp developer can act on. */
function refusalReason(typeUrl) {
  return ACCOUNT_AUTHORITY_TYPE_URLS.has(typeUrl)
    ? 'it changes who may spend from the account (authenticators, spending rules, EVM windows and delegations), ' +
        'which the user manages from QoreX itself'
    : 'QoreX manages the account\'s post-quantum key itself';
}

const AUTHZ_EXEC = '/cosmos.authz.v1beta1.MsgExec';
const AUTHZ_GRANT = '/cosmos.authz.v1beta1.MsgGrant';
const GENERIC_AUTHORIZATION = '/cosmos.authz.v1beta1.GenericAuthorization';

// A MsgGrant with a GenericAuthorization for a refused message hands the
// grantee the right to send that message for the account: refuse it as the
// message itself. A MsgGrant that cannot be decoded is refused too.
function refuseGrantOfRefused(value, where) {
  let grant;
  try {
    grant = MsgGrant.decode(execBytes(value));
  } catch {
    fail(`${where}: ${AUTHZ_GRANT} could not be decoded`);
  }
  const auth = grant.grant?.authorization;
  if (auth?.typeUrl !== GENERIC_AUTHORIZATION) return;
  let msg;
  try {
    msg = GenericAuthorization.decode(auth.value).msg;
  } catch {
    fail(`${where}: ${AUTHZ_GRANT} carries a GenericAuthorization that could not be decoded`);
  }
  if (QOREX_REFUSED_TYPE_URLS.includes(msg)) {
    fail(`${where}: ${AUTHZ_GRANT} grants ${msg}; granting it is refused like the message itself (${refusalReason(msg)})`);
  }
}

function fail(msg) {
  throw new Error(`qorexSignAndBroadcast: ${msg}`);
}

/** How deep nested MsgExec may go before the request is refused as unreadable. */
const MAX_EXEC_DEPTH = 8;

function execBytes(value) {
  if (value instanceof Uint8Array) return value;
  if (typeof globalThis.Buffer === 'function') return new Uint8Array(globalThis.Buffer.from(value, 'base64'));
  return Uint8Array.from(globalThis.atob(value), (c) => c.charCodeAt(0));
}

// Refuse the messages above carried inside authz MsgExec, at any depth. A
// MsgExec that cannot be decoded is refused too: the wallet would not be able
// to show what it does.
function refuseKeyManagementInExec(value, where, depth) {
  if (depth > MAX_EXEC_DEPTH) fail(`${where}: ${AUTHZ_EXEC} nested more than ${MAX_EXEC_DEPTH} deep`);
  let exec;
  try {
    exec = MsgExec.decode(execBytes(value));
  } catch {
    fail(`${where}: ${AUTHZ_EXEC} could not be decoded`);
  }
  exec.msgs.forEach((inner, j) => {
    if (QOREX_REFUSED_TYPE_URLS.includes(inner.typeUrl)) {
      const what = ACCOUNT_AUTHORITY_TYPE_URLS.has(inner.typeUrl) ? 'account authority' : 'PQC key management';
      fail(`${where}: ${AUTHZ_EXEC} carries ${inner.typeUrl}; ${what} is refused inside authz (${refusalReason(inner.typeUrl)})`);
    }
    if (inner.typeUrl === AUTHZ_EXEC) refuseKeyManagementInExec(inner.value, `${where}.msgs[${j}]`, depth + 1);
    if (inner.typeUrl === AUTHZ_GRANT) refuseGrantOfRefused(inner.value, `${where}.msgs[${j}]`);
  });
}

/** Accept the three shapes QoreX accepts, and reject anything else loudly. */
function normaliseValue(value, i) {
  if (value instanceof Uint8Array) return value;
  if (Array.isArray(value) && value.every((b) => Number.isInteger(b) && b >= 0 && b <= 255)) {
    return Uint8Array.from(value);
  }
  if (typeof value === 'string') return value; // base64, passed through verbatim
  fail(
    `messages[${i}].value must be protobuf bytes (Uint8Array, number[] or a base64 string), got ${
      value === null ? 'null' : typeof value
    }. Encode the message first, e.g. MsgSend.encode(MsgSend.fromPartial({…})).finish().`,
  );
}

/**
 * Validate a call the way the wallet will, so the failure arrives in the page's
 * console with a remedy rather than as a rejected prompt the user has to read.
 * Returns the normalised request.
 */
export function validateQorexRequest({ chainId, messages, memo = '', gasLimit } = {}) {
  if (!QOREX_CHAIN_IDS.includes(chainId)) {
    fail(
      `chainId must be one of ${QOREX_CHAIN_IDS.join(', ')}, got ${JSON.stringify(chainId)}. ` +
        'It must also equal the wallet\'s active network — a dApp cannot switch it.',
    );
  }
  if (!Array.isArray(messages) || messages.length === 0) fail('messages must be a non-empty array');
  if (messages.length > QOREX_MAX_MESSAGES) {
    fail(`at most ${QOREX_MAX_MESSAGES} messages per call, got ${messages.length}`);
  }
  const out = messages.map((m, i) => {
    if (!m || typeof m.typeUrl !== 'string' || !m.typeUrl.startsWith('/')) {
      fail(`messages[${i}].typeUrl must be a type URL starting with "/"`);
    }
    if (QOREX_REFUSED_TYPE_URLS.includes(m.typeUrl)) {
      fail(
        ACCOUNT_AUTHORITY_TYPE_URLS.has(m.typeUrl)
          ? `${m.typeUrl} is refused: ${refusalReason(m.typeUrl)}.`
          : `${m.typeUrl} is refused: QoreX manages the account's post-quantum key itself. ` +
              'Key registration happens automatically on the account\'s first transaction.',
      );
    }
    const value = normaliseValue(m.value, i);
    if (m.typeUrl === AUTHZ_EXEC) {
      // authz is allowed, as in the wallet, but not as a way around the rule
      // above: QoreX decodes MsgExec, shows it, and refuses the messages above
      // at any depth. Check the same here, so a dApp gets the reason up front.
      refuseKeyManagementInExec(value, `messages[${i}]`, 1);
    }
    if (m.typeUrl === AUTHZ_GRANT) refuseGrantOfRefused(value, `messages[${i}]`);
    return { typeUrl: m.typeUrl, value };
  });
  if (typeof memo !== 'string') fail('memo must be a string');
  const memoBytes = new TextEncoder().encode(memo).length;
  if (memoBytes > QOREX_MAX_MEMO_BYTES) {
    fail(`memo must be at most ${QOREX_MAX_MEMO_BYTES} bytes, got ${memoBytes}`);
  }
  if (gasLimit !== undefined) {
    if (!Number.isInteger(gasLimit)) fail('gasLimit must be an integer');
    if (gasLimit < QOREX_MIN_GAS_LIMIT || gasLimit > QOREX_MAX_GAS_LIMIT) {
      fail(`gasLimit must be between ${QOREX_MIN_GAS_LIMIT} and ${QOREX_MAX_GAS_LIMIT}, got ${gasLimit}`);
    }
  }
  const req = { chainId, messages: out, memo };
  if (gasLimit !== undefined) req.gasLimit = gasLimit;
  return req;
}

/**
 * Connect the page to QoreX for one chain. Safe to call again; QoreX prompts
 * once per site. Returns the provider.
 *
 * @throws when QoreX is absent, or too old to sign and broadcast.
 */
export async function connectQorex({ chainId, provider = getQorexNative() } = {}) {
  if (!provider) {
    throw new Error(
      'QoreX is not available: window.qorex.native is undefined. Install the QoreX ' +
        'extension, or open this page in the QoreX app browser.',
    );
  }
  if (!hasQorexSignAndBroadcast(provider)) {
    throw new Error(
      'This QoreX build cannot sign and broadcast QoreChain transactions. ' +
        'Update QoreX (extension >= 0.3.5, app >= 1.1.5).',
    );
  }
  if (!QOREX_CHAIN_IDS.includes(chainId)) {
    throw new Error(`connectQorex: chainId must be one of ${QOREX_CHAIN_IDS.join(', ')}`);
  }
  await provider.enable(chainId);
  return provider;
}

/**
 * Send QoreChain messages through QoreX: the wallet builds, hybrid-signs and
 * broadcasts them, and resolves with `{ txHash, code, height?, shield }`.
 *
 * `code` is the chain's delivery code — 0 means it landed. A user rejection
 * rejects with `QoreX: signature rejected`.
 *
 * The message bytes are signed exactly as given: the wallet does not re-encode
 * them, so encode with the same registry you would use to broadcast yourself.
 */
export async function qorexSignAndBroadcast({
  chainId,
  messages,
  memo = '',
  gasLimit,
  provider = getQorexNative(),
} = {}) {
  const p = await connectQorex({ chainId, provider });
  const req = validateQorexRequest({ chainId, messages, memo, gasLimit });
  return p.signAndBroadcast(req);
}

/** True when a thrown error is the user declining the prompt, not a failure. */
export function isQorexRejection(err) {
  const text = typeof err === 'string' ? err : (err?.message ?? '');
  return /signature rejected|user rejected|request rejected/i.test(text);
}
