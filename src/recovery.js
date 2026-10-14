// @qorechain/wallet-adapter — PQC recovery codes.
//
// WHAT THIS REPLACES. The account's ML-DSA-87 key used to be derived from things
// that are not secret enough: a wallet signature over a public string
// (derivePqcKeyFromWallet, withdrawn) or the classical secp256k1 key itself
// (walletFromSeed). Either way, whoever held the classical key or one signature
// held the post-quantum key too, and the hybrid scheme protected nothing.
//
// A recovery code is a SECOND secret, generated at random and held by the user,
// that the classical key says nothing about. The ML-DSA key is derived from it
// and from the account address, so the post-quantum half finally needs something
// the classical half does not have.
//
// WHY THIS FORMAT AND NOT 24 WORDS. People holding a QoreChain account have
// already been taught to guard, and import, a 24-word seed phrase. A second
// 24-word phrase with a different job gets imported into a wallet as if it were
// the seed. So the code looks nothing like one:
//
//     QRC1-7K3M-9TQX-…            (14 groups of 4, Crockford base32)
//
//   - 256 bits of entropy: ML-DSA-87 is NIST category 5, and Grover halves a
//     key's search space, so 128 bits would undercut the key it protects;
//   - Crockford base32 — no I, L, O or U, case-insensitive, and the letters
//     people confuse are read as what they meant (O→0, I/L→1);
//   - a 24-bit checksum, so a mistyped character is caught (a wrong code would
//     otherwise derive a valid-looking key that matches nothing);
//   - the "QRC1-" prefix names it and versions it.
//
// The code is the secret. Show it once, have the user write it down, and never
// store it next to the account's seed phrase.

import { mldsa, shake256 } from '@qorechain/pqc';

const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'; // Crockford: no I L O U
const PREFIX = 'QRC1';
const SECRET_BYTES = 32;
const CHECKSUM_BYTES = 3;
const PAYLOAD_BYTES = SECRET_BYTES + CHECKSUM_BYTES; // 35 bytes = 280 bits = 56 chars
const CODE_CHARS = (PAYLOAD_BYTES * 8) / 5;
const GROUP = 4;

const CHECKSUM_DOMAIN = 'qorechain:pqc:recovery:v1:checksum';
const KEY_DOMAIN = 'qorechain:pqc:recovery:v1';

const utf8 = (s) => new TextEncoder().encode(s);

function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
}

function checksum(secret) {
  return shake256(concat(utf8(CHECKSUM_DOMAIN), secret), CHECKSUM_BYTES);
}

function encodeBase32(bytes) {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const b of bytes) {
    value = (value << 8) | b;
    bits += 8;
    while (bits >= 5) {
      out += ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += ALPHABET[(value << (5 - bits)) & 31];
  return out;
}

function decodeBase32(chars) {
  const out = [];
  let bits = 0;
  let value = 0;
  for (const c of chars) {
    const v = ALPHABET.indexOf(c);
    if (v < 0) throw new Error(`recovery code contains an invalid character "${c}"`);
    value = (value << 5) | v;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Uint8Array.from(out);
}

/**
 * Normalise what a person typed: drop the prefix, separators and spaces, upper-
 * case it, and read the characters people confuse as what they meant. Returns
 * the 56 data characters, or throws with a message a UI can show.
 */
export function normalizeRecoveryCode(code) {
  if (typeof code !== 'string') throw new Error('recovery code must be a string');
  // Read the confusable letters as what was meant BEFORE looking for the prefix:
  // someone copying "QRC1" off paper can write "QRCI" or "QRCL".
  let s = code.toUpperCase().replace(/[\s\-_.]/g, '').replace(/O/g, '0').replace(/[IL]/g, '1');
  // Strip the prefix only when the length says it is there: 56 data characters
  // can begin with "QRC1" by chance, and cutting those would break a valid code.
  if (s.length === CODE_CHARS + PREFIX.length && s.startsWith(PREFIX)) s = s.slice(PREFIX.length);
  if (s.length !== CODE_CHARS) {
    throw new Error(`recovery code must have ${CODE_CHARS} characters after "${PREFIX}-", got ${s.length}`);
  }
  if (s.includes('U')) throw new Error('recovery code contains an invalid character "U"');
  return s;
}

function decodeRecoveryCode(code) {
  const payload = decodeBase32(normalizeRecoveryCode(code));
  // 56 chars = 280 bits = exactly 35 bytes; anything else is a decoder fault.
  if (payload.length !== PAYLOAD_BYTES) throw new Error('recovery code has the wrong length');
  const secret = payload.slice(0, SECRET_BYTES);
  const given = payload.slice(SECRET_BYTES);
  const want = checksum(secret);
  let diff = 0;
  for (let i = 0; i < CHECKSUM_BYTES; i++) diff |= given[i] ^ want[i];
  payload.fill(0);
  if (diff !== 0) {
    secret.fill(0);
    throw new Error('recovery code checksum does not match — a character is mistyped');
  }
  return secret;
}

function formatCode(chars) {
  const groups = [];
  for (let i = 0; i < chars.length; i += GROUP) groups.push(chars.slice(i, i + GROUP));
  return `${PREFIX}-${groups.join('-')}`;
}

/**
 * Generate a new recovery code from the platform's CSPRNG.
 * Show it to the user once; it is the secret.
 */
export async function generatePqcRecoveryCode() {
  const cryptoApi = globalThis.crypto;
  if (!cryptoApi?.getRandomValues) {
    throw new Error('generatePqcRecoveryCode needs a cryptographically secure random source (globalThis.crypto)');
  }
  const secret = cryptoApi.getRandomValues(new Uint8Array(SECRET_BYTES));
  const code = formatCode(encodeBase32(concat(secret, checksum(secret))));
  secret.fill(0);
  return code;
}

/** True when `code` is a well-formed recovery code with a valid checksum. */
export function isValidRecoveryCode(code) {
  try {
    decodeRecoveryCode(code).fill(0);
    return true;
  } catch {
    return false;
  }
}

/**
 * Derive the account's ML-DSA-87 keypair from its recovery code.
 *
 * Bound to the account address, so one code cannot stand in for another account
 * and the same code never yields the same key twice across accounts. Nothing
 * here depends on the account's classical key.
 *
 * @param {string} code     the QRC1-… recovery code
 * @param {string} address  the account's canonical qor1… address
 * @returns {Promise<{ publicKey: Uint8Array, secretKey: Uint8Array }>}
 * @throws on a malformed code or a checksum mismatch — never silently derives
 *         a key from a mistyped code
 */
export async function pqcKeyFromRecoveryCode(code, address) {
  if (typeof address !== 'string' || !/^qor1[02-9ac-hj-np-z]{38,}$/.test(address.toLowerCase())) {
    throw new Error('pqcKeyFromRecoveryCode: address must be the account\'s qor1… address');
  }
  const secret = decodeRecoveryCode(code);
  const seedInput = concat(utf8(`${KEY_DOMAIN}|${address.toLowerCase()}|`), secret);
  const seed = shake256(seedInput, 32);
  secret.fill(0);
  seedInput.fill(0);
  const keypair = mldsa.keygen(seed);
  seed.fill(0);
  return keypair;
}

export const PQC_RECOVERY_CODE_PREFIX = PREFIX;
