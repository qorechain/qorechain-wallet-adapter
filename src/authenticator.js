// @qorechain/wallet-adapter — v3.1.85 authenticator lanes (EVM + Native/Cosmos)
// and same-algorithm PQC key rotation.
//
// v3.1.84 introduced the SVM authenticator lane (see phantom.js). v3.1.85 adds
// two more lanes so a linked external key (Phantom ed25519 / a secp256k1 key)
// can spend from the ONE unified PQC-required account under least-privilege,
// spend-limited, revocable terms — via a relayer, WITHOUT the external key ever
// producing an ML-DSA co-signature:
//
//   • EVM lane    — MsgExecuteEVM:    EVM call/transfer from the account's 0x addr.
//   • Native lane — MsgExecuteCosmos: bank send from the account (Cosmos).
//
// The relayer submits + pays fees (its own hybrid-PQC signature satisfies the
// ante on the envelope); the authenticator's signature over the domain-separated,
// replay-bound sign-bytes IS the authorization. The digests below are rebuilt
// BYTE-FOR-BYTE from the chain (x/abstractaccount/types/{evm,cosmos}_sign.go) — a
// mismatch is rejected on-chain (codespace abstractaccount, code 11 replay / 10
// permission / 5 spending-limit / 6 session-expired).
//
// Chain signature check (keeper.VerifyAuthenticatorSignature): for scheme
// "ed25519" it is ed25519.Verify(pubkey, digest, sig) — so a Phantom
// `signMessage(digest)` matches directly (the builders below). For "secp256k1"
// the chain uses cosmos secp256k1 VerifySignature (sha256-based, NOT MetaMask
// personal_sign), so a MetaMask personal_sign will NOT verify — provide the
// digest to a cosmos-style secp256k1 signer instead.

import { mldsa, shake256 } from '@qorechain/pqc';

// ---- byte helpers (match the chain's binary.BigEndian + length-prefix framing) ----

const enc = new TextEncoder();

function be64(n) {
  const b = new Uint8Array(8);
  let v = BigInt(n);
  for (let i = 7; i >= 0; i--) { b[i] = Number(v & 0xffn); v >>= 8n; }
  return b;
}

function concat(parts) {
  let len = 0; for (const p of parts) len += p.length;
  const out = new Uint8Array(len); let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

// length-prefixed field: BE64(len) ‖ bytes
function lp(bytes) { return concat([be64(bytes.length), bytes]); }

function toBytes(x) {
  if (x instanceof Uint8Array) return x;
  if (typeof x === 'string') return enc.encode(x);
  return new Uint8Array(x);
}

async function sha256(bytes) {
  if (typeof globalThis.crypto?.subtle?.digest === 'function') {
    return new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', bytes));
  }
  const { createHash } = await import('crypto');
  return new Uint8Array(createHash('sha256').update(bytes).digest());
}

function toHexLower(bytes) {
  let s = ''; for (const b of bytes) s += b.toString(16).padStart(2, '0');
  return s;
}

// ---- sign-bytes (the digest an authenticator signs) ----

/**
 * evmAuthSignBytes rebuilds the 32-byte digest the chain re-derives for a
 * MsgExecuteEVM (types.EVMAuthSignBytes):
 *   sha256( "qorechain-evm-auth-v1"
 *           ‖ LP(chainId) ‖ LP(account) ‖ LP(pubkey)
 *           ‖ LP(to) ‖ LP(value) ‖ LP(data) ‖ BE64(nonce) )
 * `to` is the 0x-hex recipient string, `value` is the decimal wei (aqor) string,
 * `data` is the raw calldata (Uint8Array). `pubkey` is the authenticator's raw
 * public key (32 bytes for ed25519). Returns Uint8Array(32) — what the wallet signs.
 *
 * NONCE: the account's CURRENT EVM nonce (eth_getTransactionCount(account0x)).
 * In production the relayer is a DIFFERENT account than the owner, so the relayer
 * envelope does NOT bump the account's nonce — use the current value as-is. (Only
 * if relayer === owner does the envelope pre-increment it, needing current+1.)
 */
export async function evmAuthSignBytes({ chainId, account, pubkey, to = '', value = '0', data = new Uint8Array(0), nonce }) {
  const body = concat([
    enc.encode('qorechain-evm-auth-v1'),
    lp(toBytes(chainId)), lp(toBytes(account)), lp(toBytes(pubkey)),
    lp(toBytes(to)), lp(toBytes(value)), lp(toBytes(data)),
    be64(nonce),
  ]);
  return sha256(body);
}

/**
 * cosmosAuthSignBytes rebuilds the 32-byte digest the chain re-derives for a
 * MsgExecuteCosmos (types.CosmosAuthSignBytes):
 *   sha256( "qorechain-cosmos-auth-v1"
 *           ‖ LP(chainId) ‖ LP(account) ‖ LP(pubkey)
 *           ‖ LP(to) ‖ LP(amount) ‖ BE64(nonce) )
 * `to` is the bech32 recipient, `amount` is the CANONICAL sdk.Coins string
 * (sorted, e.g. "100uqor"). Returns Uint8Array(32).
 *
 * NONCE: the per-authenticator sequence for (account, pubkey) — a store counter
 * distinct from the account's own sequence, incremented on each successful
 * Native-lane spend. (Query it from the chain / track it client-side.)
 */
export async function cosmosAuthSignBytes({ chainId, account, pubkey, to, amount, nonce }) {
  const body = concat([
    enc.encode('qorechain-cosmos-auth-v1'),
    lp(toBytes(chainId)), lp(toBytes(account)), lp(toBytes(pubkey)),
    lp(toBytes(to)), lp(toBytes(amount)),
    be64(nonce),
  ]);
  return sha256(body);
}

/**
 * rotationSignBytes returns the domain-separated STRING both the old and the new
 * key sign for a MsgRotatePQCKey (types.RotationSignBytes):
 *   "qorechain-pqc-rotate-v1|<chainId>|<algorithmId>|<account>|<oldHex>|<newHex>"
 * oldHex/newHex are lowercase hex of the public keys. Sign `utf8(this string)`.
 */
export function rotationSignBytes(chainId, algorithmId, account, oldPub, newPub) {
  return `qorechain-pqc-rotate-v1|${chainId}|${algorithmId}|${account}|${toHexLower(oldPub)}|${toHexLower(newPub)}`;
}

// ---- message composers (shapes for cosmjs registry / *.fromPartial) ----

/** parse a single-coin amount string like "100uqor" → [{denom,amount}]. */
function parseCoins(amount) {
  const m = /^([0-9]+)([a-zA-Z][a-zA-Z0-9/:._-]*)$/.exec(String(amount).trim());
  if (!m) throw new Error(`invalid amount "${amount}" (expected e.g. "100uqor")`);
  return [{ denom: m[2], amount: m[1] }];
}

/** MsgExecuteEVM — the relayer broadcasts this (it is the message `relayer`/fee payer). */
export function executeEvmMsg({ relayer, account, scheme, pubkey, signature, to = '', value = '0', data = new Uint8Array(0), gasLimit, nonce }) {
  return {
    typeUrl: '/qorechain.abstractaccount.v1.MsgExecuteEVM',
    value: {
      relayer, account, scheme,
      pubkey: toBytes(pubkey), signature: toBytes(signature),
      to, value, data: toBytes(data),
      gasLimit: BigInt(gasLimit), nonce: BigInt(nonce),
    },
  };
}

/** MsgExecuteCosmos — the relayer broadcasts this. `amount` is "100uqor"-style. */
export function executeCosmosMsg({ relayer, account, scheme, pubkey, signature, to, amount, nonce }) {
  return {
    typeUrl: '/qorechain.abstractaccount.v1.MsgExecuteCosmos',
    value: {
      relayer, account, scheme,
      pubkey: toBytes(pubkey), signature: toBytes(signature),
      to, amount: parseCoins(amount), nonce: BigInt(nonce),
    },
  };
}

/** MsgRevokeAuthenticator — owner-signed; instantly disables a linked key. */
export function revokeAuthenticatorMsg({ owner, account = owner, scheme, pubkey }) {
  return {
    typeUrl: '/qorechain.abstractaccount.v1.MsgRevokeAuthenticator',
    value: { owner, accountAddress: account, scheme, pubkey: toBytes(pubkey) },
  };
}

/** MsgRotatePQCKey — sender-signed (hybrid, with the OLD key); dual-signed payload. */
export function rotatePqcKeyMsg({ sender, oldPublicKey, newPublicKey, oldSignature, newSignature }) {
  return {
    typeUrl: '/qorechain.pqc.v1.MsgRotatePQCKey',
    value: {
      sender,
      oldPublicKey: toBytes(oldPublicKey), newPublicKey: toBytes(newPublicKey),
      oldSignature: toBytes(oldSignature), newSignature: toBytes(newSignature),
    },
  };
}

// ---- Phantom (ed25519) envelope builders for the EVM + Native lanes ----

function walletPubkey(wallet) {
  return wallet.publicKey?.toBytes ? wallet.publicKey.toBytes() : new Uint8Array(wallet.publicKey);
}

/**
 * buildPhantomExecuteEvm signs the EVM auth digest with a Phantom-style ed25519
 * wallet and returns a MsgExecuteEVM ready for the relayer to broadcast. The
 * relayer address is the fee payer (a DIFFERENT account than `account`).
 */
export async function buildPhantomExecuteEvm({ wallet, relayer, chainId, account, to = '', value = '0', data = new Uint8Array(0), gasLimit = 100000, nonce }) {
  const pubkey = walletPubkey(wallet);
  const digest = await evmAuthSignBytes({ chainId, account, pubkey, to, value, data, nonce });
  const { signature } = await wallet.signMessage(digest);
  return executeEvmMsg({ relayer, account, scheme: 'ed25519', pubkey, signature, to, value, data, gasLimit, nonce });
}

/**
 * buildPhantomExecuteCosmos signs the Native auth digest with a Phantom-style
 * ed25519 wallet and returns a MsgExecuteCosmos ready for the relayer. `amount`
 * is a single-coin string like "100uqor".
 */
export async function buildPhantomExecuteCosmos({ wallet, relayer, chainId, account, to, amount, nonce }) {
  const pubkey = walletPubkey(wallet);
  const digest = await cosmosAuthSignBytes({ chainId, account, pubkey, to, amount, nonce });
  const { signature } = await wallet.signMessage(digest);
  return executeCosmosMsg({ relayer, account, scheme: 'ed25519', pubkey, signature, to, amount, nonce });
}

// ---- MetaMask (EIP-191 personal_sign / secp256k1) envelope builders ----
//
// A browser EVM wallet exposes only its 20-byte address + `personal_sign`, never
// the raw public key, so the account is linked by its ETH ADDRESS (scheme
// "secp256k1", 20-byte pubkey). The chain verifies with EIP-191 + ecrecover
// (v3.1.85). The digest the wallet signs is the SAME one the Phantom/cosmos
// paths use — only the signing scheme differs.

function hexToBytes(hex) {
  hex = String(hex).replace(/^0x/, '');
  const o = new Uint8Array(hex.length / 2);
  for (let i = 0; i < o.length; i++) o[i] = parseInt(hex.substr(i * 2, 2), 16);
  return o;
}
function bytesToHex0x(b) { let s = '0x'; for (const x of b) s += x.toString(16).padStart(2, '0'); return s; }

// personal_sign over the 32-byte digest via an EIP-1193 provider (e.g. MetaMask).
async function ethPersonalSign(provider, address, digest) {
  const sigHex = await provider.request({ method: 'personal_sign', params: [bytesToHex0x(digest), address] });
  return hexToBytes(sigHex); // 65 bytes r‖s‖v (v = 27/28)
}

/**
 * registerEthAuthenticatorMsg builds the owner-signed MsgRegisterAuthenticator
 * that links a MetaMask / EVM key (by its 0x address) to the owner's account.
 * `ethAddress` is the 0x-hex 20-byte address.
 */
export function registerEthAuthenticatorMsg({ owner, account = owner, ethAddress, permissions = ['evm'], expiryUnix, label = 'metamask' }) {
  return {
    typeUrl: '/qorechain.abstractaccount.v1.MsgRegisterAuthenticator',
    value: {
      owner, accountAddress: account, scheme: 'secp256k1',
      pubkey: hexToBytes(ethAddress), permissions, expiryUnix: BigInt(expiryUnix), label,
    },
  };
}

/** buildMetaMaskExecuteEvm: MetaMask (EIP-191) → MsgExecuteEVM ready for the relayer. */
export async function buildMetaMaskExecuteEvm({ provider, address, relayer, chainId, account, to = '', value = '0', data = new Uint8Array(0), gasLimit = 100000, nonce }) {
  const pubkey = hexToBytes(address); // 20-byte eth address = the authenticator pubkey
  const digest = await evmAuthSignBytes({ chainId, account, pubkey, to, value, data, nonce });
  const signature = await ethPersonalSign(provider, address, digest);
  return executeEvmMsg({ relayer, account, scheme: 'secp256k1', pubkey, signature, to, value, data, gasLimit, nonce });
}

/** buildMetaMaskExecuteCosmos: MetaMask (EIP-191) → MsgExecuteCosmos ready for the relayer. */
export async function buildMetaMaskExecuteCosmos({ provider, address, relayer, chainId, account, to, amount, nonce }) {
  const pubkey = hexToBytes(address);
  const digest = await cosmosAuthSignBytes({ chainId, account, pubkey, to, amount, nonce });
  const signature = await ethPersonalSign(provider, address, digest);
  return executeCosmosMsg({ relayer, account, scheme: 'secp256k1', pubkey, signature, to, amount, nonce });
}

// ---- key rotation (legacy → canonical migration) ----

const CANONICAL = 'adapter'; // shake256("qorechain:pqc:v1|addr|mnemonic")  (SDK/wallet-adapter)
const LEGACY = 'bridge';     // shake256(mnemonic)                          (chain-bridge/faucet-api)

function derivePqcByScheme(scheme, account, mnemonic) {
  if (scheme === LEGACY || scheme === 'mnemonic-only') {
    return mldsa.keygen(shake256(enc.encode(mnemonic), 32));
  }
  if (scheme === CANONICAL || scheme === '' || scheme === undefined) {
    return mldsa.keygen(shake256(enc.encode(`qorechain:pqc:v1|${account}|${mnemonic}`), 32));
  }
  throw new Error(`unknown derivation "${scheme}" (use adapter|bridge)`);
}

/**
 * rotatePqcKeyMsgFromMnemonic builds a MsgRotatePQCKey that rotates an account's
 * ML-DSA-87 key (SAME algorithm) from one derivation to another — the canonical
 * use is migrating a LEGACY chain-bridge key (`shake256(mnemonic)`) to the
 * canonical address-bound key (`shake256("qorechain:pqc:v1|addr|mnemonic")`), so
 * a wallet whose key was registered by a backend can move to the standard
 * derivation. Both keys dual-sign the domain-separated rotation bytes.
 *
 * The returned message must be broadcast BY the account, cosigned (hybrid) with
 * the OLD key (it is still the registered key until the rotation lands) — i.e.
 * sign the envelope with a QoreChainSigner whose `pqc` is the OLD keypair.
 *
 * @returns {{ msg: object, oldKeypair: {publicKey,secretKey}, newKeypair: {publicKey,secretKey} }}
 */
export function rotatePqcKeyMsgFromMnemonic({ account, mnemonic, chainId, algorithmId = 1, oldDerivation = LEGACY, newDerivation = CANONICAL }) {
  const oldKp = derivePqcByScheme(oldDerivation, account, mnemonic);
  const newKp = derivePqcByScheme(newDerivation, account, mnemonic);
  if (toHexLower(oldKp.publicKey) === toHexLower(newKp.publicKey)) {
    throw new Error('old and new derivations produce the same key — rotation would be a no-op');
  }
  const sb = enc.encode(rotationSignBytes(chainId, algorithmId, account, oldKp.publicKey, newKp.publicKey));
  const msg = rotatePqcKeyMsg({
    sender: account,
    oldPublicKey: oldKp.publicKey, newPublicKey: newKp.publicKey,
    oldSignature: mldsa.sign(oldKp.secretKey, sb),
    newSignature: mldsa.sign(newKp.secretKey, sb),
  });
  return { msg, oldKeypair: oldKp, newKeypair: newKp };
}

/** derivePqcLegacy exposes the LEGACY (chain-bridge) derivation for a mnemonic. */
export function derivePqcLegacy(mnemonic) {
  return mldsa.keygen(shake256(enc.encode(mnemonic), 32));
}
