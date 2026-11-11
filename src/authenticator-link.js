// @qorechain/wallet-adapter: linking a wallet key to an account (chain v3.2.8).
//
// From chain v3.2.8 two things are required to link a key with
// MsgRegisterAuthenticator:
//
//   1. possession_proof (field 8): a signature BY THE KEY BEING LINKED over the
//      link message below. It binds the chain, the account, the scheme and the
//      key, so a key can only be linked by its holder.
//   2. A spending rule on the account that bounds every denom, when the key gets
//      a permission that moves value (send, evm, deploy, svm, all). The message
//      carries no per-key rule; the account's first enabled rule applies. Send
//      MsgUpdateSpendingRules first, in the same transaction:
//      linkAuthenticatorMsgs builds that pair.
//
// The link message is plain text so the wallet shows the user what they sign:
//
//   QoreChain authenticator link v1
//   chain: <chain id>
//   account: <bech32 account>
//   scheme: <scheme>
//   key: <lowercase hex of the public key, or of the 20-byte address>
//
// How the chain checks the proof: an ed25519 key (Phantom signMessage) signs the
// text itself; a 20-byte Ethereum address (MetaMask personal_sign) signs it
// under EIP-191; a 33-byte compressed secp256k1 key signs sha256 of the text
// (64-byte r||s), as any Cosmos signature.

export const AUTHENTICATOR_LINK_DOMAIN = 'QoreChain authenticator link v1';

/** Permissions with which a linked key can move value; each needs a bounding spending rule. */
export const VALUE_PERMISSIONS = Object.freeze(['send', 'evm', 'deploy', 'svm', 'all']);

const te = new TextEncoder();

function toHex(bytes) {
  let s = '';
  for (const b of bytes) s += b.toString(16).padStart(2, '0');
  return s;
}

function hexToBytes(hex) {
  const h = String(hex).replace(/^0x/i, '');
  if (h.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(h)) throw new Error(`not a hex string: ${JSON.stringify(hex)}`);
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.substr(i * 2, 2), 16);
  return out;
}

function keyBytes(pubkey) {
  if (pubkey instanceof Uint8Array) return pubkey;
  if (Array.isArray(pubkey)) return Uint8Array.from(pubkey);
  if (typeof pubkey === 'string') return hexToBytes(pubkey);
  throw new Error('pubkey must be a Uint8Array, a byte array or a hex string');
}

/**
 * The exact text the linked key signs for MsgRegisterAuthenticator.possession_proof.
 * `pubkey` is the value put in the message's `pubkey`: a 32-byte ed25519 key, a
 * 33-byte compressed secp256k1 key, or the 20-byte Ethereum address.
 */
export function authenticatorLinkMessage({ chainId, account, scheme, pubkey }) {
  for (const [name, v] of [['chainId', chainId], ['account', account], ['scheme', scheme]]) {
    if (typeof v !== 'string' || v.length === 0) throw new Error(`authenticatorLinkMessage: ${name} is required`);
  }
  const key = keyBytes(pubkey);
  if (key.length === 0) throw new Error('authenticatorLinkMessage: pubkey is required');
  return `${AUTHENTICATOR_LINK_DOMAIN}\nchain: ${chainId}\naccount: ${account}\nscheme: ${scheme}\nkey: ${toHex(key)}`;
}

function walletPubkey(wallet) {
  return wallet.publicKey?.toBytes ? wallet.publicKey.toBytes() : new Uint8Array(wallet.publicKey);
}

/**
 * Ask a Phantom-style ed25519 wallet to sign the link message for `account` on
 * `chainId`. Returns the 64-byte signature to pass as `possessionProof`.
 */
export async function phantomPossessionProof({ wallet, chainId, account }) {
  const text = authenticatorLinkMessage({ chainId, account, scheme: 'ed25519', pubkey: walletPubkey(wallet) });
  const { signature } = await wallet.signMessage(te.encode(text));
  return signature instanceof Uint8Array ? signature : Uint8Array.from(signature);
}

/**
 * Ask an EIP-1193 provider (MetaMask) to personal_sign the link message for
 * `address` linked to `account` on `chainId`. Returns the 65-byte signature to
 * pass as `possessionProof`.
 */
export async function metaMaskPossessionProof({ provider, address, chainId, account }) {
  const text = authenticatorLinkMessage({ chainId, account, scheme: 'secp256k1', pubkey: hexToBytes(address) });
  const sigHex = await provider.request({ method: 'personal_sign', params: ['0x' + toHex(te.encode(text)), address] });
  const sig = hexToBytes(sigHex);
  if (sig.length !== 65) throw new Error(`metaMaskPossessionProof: expected a 65-byte signature, got ${sig.length}`);
  return sig;
}

/** Throws unless `proof` is a non-empty signature. */
export function requirePossessionProof(fn, proof) {
  const bytes = proof instanceof Uint8Array ? proof : Array.isArray(proof) ? Uint8Array.from(proof) : null;
  if (!bytes || bytes.length === 0) {
    throw new Error(
      `${fn}: possessionProof is required from chain v3.2.8: have the key being linked sign ` +
        'authenticatorLinkMessage({ chainId, account, scheme, pubkey }) (phantomPossessionProof / metaMaskPossessionProof)',
    );
  }
  return bytes;
}

function positiveAmount(v) {
  if (v === undefined || v === null || v === '') return false;
  try { return BigInt(String(v)) > 0n; } catch { return false; }
}

/**
 * Whether a spending rule bounds every denom it admits, as the chain requires
 * from v3.2.8 for a key that moves value: the rule is enabled and sets
 * perTxLimit or dailyLimit above zero, or lists allowedDenoms and gives every
 * one of them a denomLimits entry with an amount.
 */
export function spendingRuleBoundsEveryDenom(rule) {
  if (!rule || rule.enabled !== true) return false;
  if (positiveAmount(rule.perTxLimit) || positiveAmount(rule.dailyLimit)) return true;
  const denoms = rule.allowedDenoms ?? [];
  if (denoms.length === 0) return false;
  const limits = rule.denomLimits ?? [];
  const same = (a, b) => String(a ?? '').toLowerCase() === String(b ?? '').toLowerCase();
  return denoms.every((d) => limits.some((l) => same(l?.denom, d) && (positiveAmount(l.perTxLimit) || positiveAmount(l.dailyLimit))));
}

/** Whether a permission list includes one that moves value. */
export function movesValue(permissions = []) {
  return permissions.some((p) => VALUE_PERMISSIONS.includes(p));
}

/**
 * MsgUpdateSpendingRules, owner-signed. It REPLACES the account's rules
 * wholesale: include every rule the account should keep. From chain v3.2.8 it
 * may be sent before the account exists when `account` is the owner's own
 * address.
 */
export function updateSpendingRulesMsg({ owner, account = owner, rules }) {
  if (!Array.isArray(rules)) throw new Error('updateSpendingRulesMsg: rules must be an array');
  return {
    typeUrl: '/qorechain.abstractaccount.v1.MsgUpdateSpendingRules',
    value: { owner, accountAddress: account, rules },
  };
}

/**
 * The two messages that link a key from chain v3.2.8, in order: the account's
 * spending rules, then MsgRegisterAuthenticator with the possession proof. Send
 * them in ONE transaction signed by the owner (top-level messages, not authz).
 * `rules` replaces the account's rules wholesale, so pass every rule to keep.
 * Refuses a value permission unless the first enabled rule (the one the chain
 * applies) bounds every denom.
 */
export function linkAuthenticatorMsgs({ registerMsg, rules }) {
  const v = registerMsg?.value;
  if (!v || registerMsg.typeUrl !== '/qorechain.abstractaccount.v1.MsgRegisterAuthenticator') {
    throw new Error('linkAuthenticatorMsgs: registerMsg must be a MsgRegisterAuthenticator (registerAuthenticatorMsg / registerEthAuthenticatorMsg)');
  }
  const list = rules ?? [];
  // The chain applies the account's FIRST enabled rule, so that is the one checked.
  if (movesValue(v.permissions ?? []) && !spendingRuleBoundsEveryDenom(list.find((r) => r?.enabled === true))) {
    throw new Error(
      `linkAuthenticatorMsgs: the permissions ${JSON.stringify(v.permissions)} move value, so from chain v3.2.8 the account ` +
        'needs an enabled spending rule that bounds every denom (perTxLimit or dailyLimit, or allowedDenoms each with a denomLimits amount)',
    );
  }
  const out = [];
  if (list.length > 0) out.push(updateSpendingRulesMsg({ owner: v.owner, account: v.accountAddress, rules: list }));
  out.push(registerMsg);
  return out;
}
