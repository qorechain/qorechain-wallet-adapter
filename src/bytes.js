// @qorechain/wallet-adapter — strict byte normalisation at the boundaries.
//
// WHY THIS EXISTS. walletFromMnemonic().pubkey is a "0x…" hex
// STRING. It reached a protobuf bytes field through `Uint8Array.from(value)`,
// which walks a string character by character: digits became their numeric
// value and 'x' and 'a'–'f' became NaN → 0. A 33-byte key went on chain as 68
// bytes with 24 of them zeroed, unrecoverable, and the chain refused it. The
// encoders from cosmjs-types do the same thing silently, and authenticator.js's
// helper went the other way — it UTF-8-encoded the string, sending the hex
// characters as ASCII.
//
// Every one of those was "the comment says bytes, the value is a string, and the
// encoder agrees with both". So a key or signature crosses into an encoder only
// through here: it is decoded deliberately or refused loudly, and its length is
// checked, never assumed.

const HEX = /^(?:0x)?[0-9a-fA-F]*$/;

function fromHex(s) {
  const body = s.startsWith('0x') || s.startsWith('0X') ? s.slice(2) : s;
  if (body.length % 2 !== 0) throw new Error('odd-length hex');
  const out = new Uint8Array(body.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(body.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function fromBase64(s) {
  if (!/^[A-Za-z0-9+/_-]*={0,2}$/.test(s)) throw new Error('not base64');
  const norm = s.replace(/-/g, '+').replace(/_/g, '/');
  if (typeof globalThis.Buffer === 'function') return new Uint8Array(globalThis.Buffer.from(norm, 'base64'));
  const bin = globalThis.atob(norm);
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

/**
 * Decode `value` to exactly `length` bytes, or throw naming `what`.
 *
 * Accepts a Uint8Array, an array of byte values, a hex string (with or without
 * 0x), or a base64 string — the chain's REST API reports keys as base64. A
 * string is read as hex only when it is hex of exactly the expected length;
 * otherwise as base64. The decoded length must match, so an ambiguous string
 * cannot quietly decode to the wrong thing.
 */
export function toExactBytes(value, length, what) {
  let out;
  if (value instanceof Uint8Array) {
    out = value;
  } else if (Array.isArray(value)) {
    if (!value.every((b) => Number.isInteger(b) && b >= 0 && b <= 255)) {
      throw new Error(`${what} must contain byte values 0–255`);
    }
    out = Uint8Array.from(value);
  } else if (typeof value === 'string') {
    const body = value.startsWith('0x') || value.startsWith('0X') ? value.slice(2) : value;
    try {
      out = HEX.test(value) && body.length === length * 2 ? fromHex(value) : fromBase64(value);
    } catch {
      throw new Error(`${what} is a string that is neither hex nor base64`);
    }
  } else {
    throw new Error(
      `${what} must be bytes (Uint8Array), a hex string or a base64 string, got ${
        value === null ? 'null' : typeof value
      }`,
    );
  }
  if (out.length !== length) {
    throw new Error(`${what} must be ${length} bytes, got ${out.length}`);
  }
  return out;
}

/** Sizes the chain checks. */
export const SECP256K1_COMPRESSED_PUBKEY_LENGTH = 33;
export const ML_DSA_87_PUBLIC_KEY_LENGTH = 2592;
export const ML_DSA_87_SIGNATURE_LENGTH = 4627;
