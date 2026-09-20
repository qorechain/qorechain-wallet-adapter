// @qorechain/wallet-adapter — per-network hybrid PQC sign-bytes (v1 / v2).
//
// The ML-DSA-87 key in a hybrid transaction signs one of two byte forms, and a
// network accepts EXACTLY ONE of them at any height (no overlap, by design):
//
//   v1 (legacy):  BE32(len B0) ‖ B0 ‖ BE32(len A) ‖ A
//   v2:           "qorechain-pqc-hybrid-v2" ‖ BE64(len chainId) ‖ chainId ‖
//                   BE32(len B0) ‖ B0 ‖ BE32(len A) ‖ A
//
// B0 = TxBody WITHOUT the PQC extension option, A = AuthInfo bytes verbatim.
// Byte-identical to the chain's x/pqc/types.HybridSignBytesLegacy / HybridSignBytes.
//
// Which form to sign: a network that existed before the release that introduced
// v2 (qorechain-vladi mainnet, qorechain-diana testnet) verifies v1 until that
// upgrade plan is applied on it, and v2 from then on. Any other chain verifies
// v2 from its first block. The two networks upgrade at different heights, so a
// client must ASK the target network (applied_plan) rather than hardcode a form.
// That is what resolveSignBytesVersion does.
//
// The switch ships under TWO plan names: the release is "v3.2.0", but the
// testnet already took the same handler under the earlier name "v3.1.98" and
// keeps that record forever. The chain registers both (x/pqc/types
// SignBytesV2Upgrades), so a client must ask for EVERY name and sign v2 if the
// numeric height of ANY of them is greater than zero. Asking for one name only
// resolves v1 on a network that upgraded under the other, and every hybrid
// transaction is then refused with pqc code 21.

export const HYBRID_SIGN_BYTES_V2_DOMAIN = 'qorechain-pqc-hybrid-v2';
/** Every upgrade plan name that switches a network to v2 sign-bytes, most recent first. */
export const SIGN_BYTES_V2_UPGRADES = Object.freeze(['v3.2.0', 'v3.1.98']);
/** The primary (current release) plan name; see SIGN_BYTES_V2_UPGRADES for all of them. */
export const SIGN_BYTES_V2_UPGRADE = SIGN_BYTES_V2_UPGRADES[0];
export const LEGACY_SIGN_BYTES_CHAINS = Object.freeze(['qorechain-vladi', 'qorechain-diana']);

const te = new TextEncoder();

function assertBytes(name, v) {
  if (!(v instanceof Uint8Array)) throw new TypeError(`${name} must be a Uint8Array`);
}

/** v1 (legacy) hybrid sign-bytes: BE32(len b0) ‖ b0 ‖ BE32(len authInfo) ‖ authInfo. */
export function hybridSignBytesV1(b0, authInfo) {
  assertBytes('b0', b0);
  assertBytes('authInfo', authInfo);
  const out = new Uint8Array(4 + b0.length + 4 + authInfo.length);
  const dv = new DataView(out.buffer);
  let o = 0;
  dv.setUint32(o, b0.length, false); o += 4;
  out.set(b0, o); o += b0.length;
  dv.setUint32(o, authInfo.length, false); o += 4;
  out.set(authInfo, o);
  return out;
}

/** v2 hybrid sign-bytes: domain ‖ BE64(len chainId) ‖ chainId ‖ BE32(len b0) ‖ b0 ‖ BE32(len authInfo) ‖ authInfo. */
export function hybridSignBytesV2(chainId, b0, authInfo) {
  if (typeof chainId !== 'string' || chainId.length === 0) {
    throw new Error('hybridSignBytesV2: chainId is required (v2 sign-bytes bind the chain-id)');
  }
  assertBytes('b0', b0);
  assertBytes('authInfo', authInfo);
  const domain = te.encode(HYBRID_SIGN_BYTES_V2_DOMAIN);
  const cid = te.encode(chainId);
  const out = new Uint8Array(domain.length + 8 + cid.length + 4 + b0.length + 4 + authInfo.length);
  const dv = new DataView(out.buffer);
  let o = 0;
  out.set(domain, o); o += domain.length;
  dv.setBigUint64(o, BigInt(cid.length), false); o += 8;
  out.set(cid, o); o += cid.length;
  dv.setUint32(o, b0.length, false); o += 4;
  out.set(b0, o); o += b0.length;
  dv.setUint32(o, authInfo.length, false); o += 4;
  out.set(authInfo, o);
  return out;
}

function assertVersion(version, fn) {
  if (version !== 'v1' && version !== 'v2') {
    throw new Error(`${fn}: version must be 'v1' or 'v2', got ${JSON.stringify(version)} (resolve it with resolveSignBytesVersion first)`);
  }
}

/** Version-dispatching hybrid sign-bytes. `version` is REQUIRED ('v1' | 'v2'); there is no implicit form. */
export function hybridSignBytes(version, chainId, b0, authInfo) {
  assertVersion(version, 'hybridSignBytes');
  return version === 'v2' ? hybridSignBytesV2(chainId, b0, authInfo) : hybridSignBytesV1(b0, authInfo);
}

function toHeight(h) {
  if (h === undefined || h === null || h === '') return 0n;
  if (typeof h === 'bigint') return h;
  if (typeof h === 'number') {
    if (!Number.isFinite(h)) throw new Error(`invalid applied height ${h}`);
    return BigInt(Math.trunc(h));
  }
  return BigInt(String(h)); // throws on garbage, never guesses
}

/**
 * The form a client must sign for `chainId`, given the height at which a v2
 * sign-bytes upgrade plan was applied on it (0 / "0" / missing = none applied;
 * pass the greatest height over SIGN_BYTES_V2_UPGRADES). Mirrors the chain's
 * SignBytesVersionFor. Heights are compared NUMERICALLY: the node returns the
 * height as a string, and "0" is truthy.
 */
export function signBytesVersionFor(chainId, v2AppliedHeight) {
  if (toHeight(v2AppliedHeight) > 0n) return 'v2';
  return LEGACY_SIGN_BYTES_CHAINS.includes(chainId) ? 'v1' : 'v2';
}

const cache = new Map(); // `${rest}|${chainId}` -> { version, at }

/** Drop every cached resolver answer. */
export function clearSignBytesCache() { cache.clear(); }

function normRest(rest) { return String(rest).replace(/\/+$/, ''); }

/**
 * Resolve the hybrid sign-bytes form for a network.
 *   - 'v1' | 'v2' are returned as-is (no network).
 *   - 'auto' (default): a chain that is not a legacy network gets 'v2' with no
 *     HTTP; a legacy network is asked `GET {rest}/cosmos/upgrade/v1beta1/applied_plan/{name}`
 *     for EVERY name in SIGN_BYTES_V2_UPGRADES and signs v2 iff the numeric
 *     height of ANY of them is > 0. The names are asked in order and the first
 *     positive height wins, so a network on the current release costs one
 *     request and one that upgraded under the earlier name costs two. Answers
 *     are cached per (rest, chainId) for `ttlMs`; `forceRefresh` bypasses the cache.
 * Throws (never guesses) when a legacy network has no `rest` or a query fails.
 */
export async function resolveSignBytesVersion({
  chainId, rest, signBytesVersion = 'auto', fetch = globalThis.fetch, ttlMs = 60_000, forceRefresh = false,
} = {}) {
  const mode = signBytesVersion ?? 'auto';
  if (mode === 'v1' || mode === 'v2') return mode;
  if (mode !== 'auto') {
    throw new Error(`signBytesVersion must be 'auto', 'v1' or 'v2', got ${JSON.stringify(signBytesVersion)}`);
  }
  if (typeof chainId !== 'string' || chainId.length === 0) {
    throw new Error('resolveSignBytesVersion: chainId is required');
  }
  if (!LEGACY_SIGN_BYTES_CHAINS.includes(chainId)) return 'v2';

  const hint = `pass \`rest\` (the network's LCD URL) or an explicit signBytesVersion 'v1' | 'v2'`;
  if (!rest) {
    throw new Error(`Cannot choose the hybrid sign-bytes form for ${chainId} without asking the network: ${hint}.`);
  }
  const base = normRest(rest);
  const key = `${base}|${chainId}`;
  if (!forceRefresh) {
    const hit = cache.get(key);
    if (hit && Date.now() - hit.at < ttlMs) return hit.version;
  }
  if (typeof fetch !== 'function') {
    throw new Error(`Cannot query ${base}: no fetch implementation available; ${hint}.`);
  }
  const plans = `${base}/cosmos/upgrade/v1beta1/applied_plan/{${SIGN_BYTES_V2_UPGRADES.join(',')}}`;
  let version;
  try {
    // Ask for every plan name; the first positive height decides (v2). Only when
    // ALL of them answer 0 / {} is the network still on v1.
    let applied = 0n;
    for (const name of SIGN_BYTES_V2_UPGRADES) {
      const url = `${base}/cosmos/upgrade/v1beta1/applied_plan/${name}`;
      const res = await fetch(url, { headers: { accept: 'application/json' } });
      if (!res || !res.ok) throw new Error(`HTTP ${res ? res.status : 'no response'} for ${name}`);
      const body = await res.json();
      applied = toHeight(body?.height ?? '0');
      if (applied > 0n) break;
    }
    version = signBytesVersionFor(chainId, applied);
  } catch (e) {
    throw new Error(`Cannot determine the hybrid sign-bytes form for ${chainId} from ${plans} (${e && e.message ? e.message : e}); ${hint}.`);
  }
  cache.set(key, { version, at: Date.now() });
  return version;
}

const REJECTION_TEXT = 'hybrid PQC signature verification failed';

/**
 * True iff a broadcast failure is the chain refusing the hybrid PQC signature
 * (x/pqc ErrHybridSigInvalid: codespace "pqc", code 21) — the signal that the
 * wrong sign-bytes form was used. Accepts a cosmjs BroadcastTxError
 * ({ code, codespace, log }), a DeliverTxResponse-like ({ code, rawLog }), a
 * plain Error, or a string. Code 21 from another codespace does NOT match.
 */
export function isHybridSignBytesRejection(errOrResult) {
  if (!errOrResult) return false;
  if (typeof errOrResult === 'string') return errOrResult.includes(REJECTION_TEXT);
  const x = errOrResult;
  if (x.codespace === 'pqc' && Number(x.code) === 21) return true;
  for (const f of [x.log, x.rawLog, x.raw_log, x.message]) {
    if (typeof f === 'string' && f.includes(REJECTION_TEXT)) return true;
  }
  return false;
}
