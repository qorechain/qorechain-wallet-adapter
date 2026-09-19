// @qorechain/wallet-adapter — Phantom (and any ed25519 wallet) support.
//
// Lets a user drive their ONE unified QoreChain account (same identity + same
// balance across Cosmos/EVM/SVM) from Phantom, by:
//   1) linking their Phantom key once as an on-chain authenticator
//      (MsgRegisterAuthenticator, owner-signed — see registerAuthenticatorMsg), and
//   2) signing SVM actions with Phantom's `signMessage` over the exact bytes the
//      node reconstructs, then posting them to the Solana-compatible `sendTransaction`.
//
// The signed bytes are domain-separated and bound to the exact action + a recent
// blockhash, so a signature cannot be replayed for a different action/account or
// (via the blockhash window) indefinitely. This mirrors the on-chain
// `resolveEnvelopeSigner` / `authSignBytes` in x/svm/rpc.
//
// NOTE: the SVM lane is currently closed on both mainnet and testnet (and the
// authenticator module is disabled), so nothing signed here is accepted yet. When
// the lane reopens it verifies only the v2 digest ("qorechain-svm-auth-v2") built below.

const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const B58MAP = (() => { const m = {}; for (let i = 0; i < B58.length; i++) m[B58[i]] = i; return m; })();

/** base58Encode encodes bytes to a Base58 string (Bitcoin alphabet). */
export function base58Encode(bytes) {
  let n = 0n;
  for (const b of bytes) n = (n << 8n) | BigInt(b);
  let out = '';
  while (n > 0n) { const r = Number(n % 58n); n /= 58n; out = B58[r] + out; }
  for (const b of bytes) { if (b === 0) out = B58[0] + out; else break; }
  return out;
}

/** base58Decode decodes a Base58 string, left-padding to `size` bytes (default 32). */
export function base58Decode(str, size = 32) {
  let n = 0n;
  for (const c of str) { const v = B58MAP[c]; if (v === undefined) throw new Error('invalid base58 char: ' + c); n = n * 58n + BigInt(v); }
  const bytes = [];
  while (n > 0n) { bytes.unshift(Number(n & 0xffn)); n >>= 8n; }
  for (const c of str) { if (c === '1') bytes.unshift(0); else break; }
  while (bytes.length < size) bytes.unshift(0);
  if (bytes.length > size) throw new Error('decoded value exceeds ' + size + ' bytes');
  return new Uint8Array(bytes);
}

function toB64(bytes) {
  if (typeof Buffer !== 'undefined') return Buffer.from(bytes).toString('base64');
  let s = ''; for (const b of bytes) s += String.fromCharCode(b); return btoa(s);
}

async function sha256(bytes) {
  if (typeof globalThis.crypto?.subtle?.digest === 'function') {
    return new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', bytes));
  }
  const { createHash } = await import('crypto'); // Node fallback
  return new Uint8Array(createHash('sha256').update(bytes).digest());
}

/** The System Program id (32 zero bytes) in base58. */
export const SYSTEM_PROGRAM_ID = base58Encode(new Uint8Array(32));

/** systemTransferData encodes a System Program "Transfer" instruction (variant 2). */
export function systemTransferData(lamports) {
  const d = new Uint8Array(12);
  d[0] = 2; // Transfer
  let v = BigInt(lamports);
  for (let i = 0; i < 8; i++) { d[4 + i] = Number(v & 0xffn); v >>= 8n; }
  return d;
}

/**
 * authSignBytes rebuilds, byte-for-byte, the digest the node signs-checks:
 *   sha256( "qorechain-svm-auth-v2" ‖ programId(32) ‖
 *           BE64(accounts.length) ‖ Σ[ addr(32) ‖ flags(1) ] ‖
 *           BE64(data.length) ‖ data ‖
 *           BE64(blockhash.length) ‖ blockhash )
 * where flags = (isSigner?1) | (isWritable?2). All addresses are decoded to
 * their raw 32 bytes; recentBlockhash is the getLatestBlockhash HEX string.
 * Returns a 32-byte Uint8Array (what the wallet actually signs).
 *
 * v1 had no count and no length framing, so the encoding was not injective: the
 * boundary between the fixed-size account entries and `data` was ambiguous (N
 * accounts plus D hashed the same as N-1 accounts plus addr‖flags‖D), and bytes
 * could move between `data` and the blockhash. One approval therefore authorised
 * more than one account set. The count and length prefixes make every field
 * self-delimiting. The tag is bumped so a v1 client fails closed against a v2
 * node rather than signing something ambiguous; keep this in lockstep with
 * qorechain-core/x/svm/types/auth_sign.go.
 */
export async function authSignBytes({ programId, accounts, data, recentBlockhashHex }) {
  const parts = [];
  const enc = new TextEncoder();
  // Big-endian uint64, matching the chain's other sign-bytes helpers.
  const be64 = (n) => {
    const b = new Uint8Array(8);
    let v = BigInt(n);
    for (let i = 7; i >= 0; i--) { b[i] = Number(v & 0xffn); v >>= 8n; }
    return b;
  };
  parts.push(enc.encode('qorechain-svm-auth-v2'));
  parts.push(base58Decode(programId));
  parts.push(be64(accounts.length));
  for (const a of accounts) {
    parts.push(base58Decode(a.pubkey));
    parts.push(new Uint8Array([(a.isSigner ? 1 : 0) | (a.isWritable ? 2 : 0)]));
  }
  const dataBytes = data instanceof Uint8Array ? data : new Uint8Array(data);
  parts.push(be64(dataBytes.length));
  parts.push(dataBytes);
  const bhBytes = hexToBytes(recentBlockhashHex);
  parts.push(be64(bhBytes.length));
  parts.push(bhBytes);
  let len = 0; for (const p of parts) len += p.length;
  const buf = new Uint8Array(len); let o = 0; for (const p of parts) { buf.set(p, o); o += p.length; }
  return sha256(buf);
}

function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}

/**
 * buildPhantomSvmEnvelope produces the `sendTransaction` envelope for an SVM
 * instruction, authorized by a Phantom-style ed25519 wallet.
 *
 * @param {object} p
 * @param {{publicKey:{toBytes:()=>Uint8Array}, signMessage:(m:Uint8Array)=>Promise<{signature:Uint8Array}>}} p.wallet  Phantom provider
 * @param {string} p.programId          base58 program id (default: System Program)
 * @param {Array<{pubkey:string,isSigner:boolean,isWritable:boolean}>} p.accounts
 * @param {Uint8Array} p.data           raw instruction data
 * @param {string} p.recentBlockhashHex value from getLatestBlockhash (.value.blockhash, hex)
 * @returns {Promise<object>} the JSON envelope to POST to sendTransaction
 */
export async function buildPhantomSvmEnvelope({ wallet, programId = SYSTEM_PROGRAM_ID, accounts, data, recentBlockhashHex }) {
  const digest = await authSignBytes({ programId, accounts, data, recentBlockhashHex });
  const { signature } = await wallet.signMessage(digest);
  const pub = wallet.publicKey.toBytes ? wallet.publicKey.toBytes() : new Uint8Array(wallet.publicKey);
  return {
    programId,
    accounts,
    data: toB64(data),
    auth: {
      scheme: 'ed25519',
      pubkey: base58Encode(pub),
      signature: toB64(signature),
      recentBlockhash: base58Encode(hexToBytes(recentBlockhashHex)),
    },
  };
}

/**
 * buildPhantomTransfer is a convenience wrapper: a native-QOR transfer from the
 * Phantom-controlled account to `toSvmAddr`, authorized by Phantom.
 */
export async function buildPhantomTransfer({ wallet, fromSvmAddr, toSvmAddr, lamports, recentBlockhashHex }) {
  return buildPhantomSvmEnvelope({
    wallet,
    programId: SYSTEM_PROGRAM_ID,
    accounts: [
      { pubkey: fromSvmAddr, isSigner: true, isWritable: true },
      { pubkey: toSvmAddr, isSigner: false, isWritable: true },
    ],
    data: systemTransferData(lamports),
    recentBlockhashHex,
  });
}

/**
 * registerAuthenticatorMsg builds the owner-signed MsgRegisterAuthenticator that
 * links a Phantom ed25519 key to the owner's own account. Broadcast it with the
 * standard QoreChainSigner (PQC-hybrid) like any other Cosmos message.
 */
export function registerAuthenticatorMsg({ owner, phantomPubkey, permissions = ['svm'], expiryUnix, label = 'phantom' }) {
  return {
    typeUrl: '/qorechain.abstractaccount.v1.MsgRegisterAuthenticator',
    value: {
      owner,
      accountAddress: owner, // self-custody: link to the owner's own account
      scheme: 'ed25519',
      pubkey: phantomPubkey, // Uint8Array (32 bytes)
      permissions,
      expiryUnix: BigInt(expiryUnix),
      label,
    },
  };
}
