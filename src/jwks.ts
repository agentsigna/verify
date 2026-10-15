/**
 * JWKS validation and retrieval. Internal module: the package exports fetchJwks,
 * assertValidJwks and JWKS_MAX_BYTES from index.ts; the test hooks of fetchJwksWith are not
 * part of the public API.
 */

import { KeyObject } from 'node:crypto';
import type { JWK, JWKS } from './index.js';
import { safeGet, type SafeGetOptions } from './net.js';

/** Largest JWKS response accepted (bytes). */
export const JWKS_MAX_BYTES = 64 * 1024;
/** Most keys accepted in one JWKS. */
const JWKS_MAX_KEYS = 100;

/**
 * Checks that a JWKS is well formed and unambiguous: an object with a non-empty `keys` array
 * (at most 100), every key an object with a string `kty` and a non-empty string `kid` without
 * `:`, no private key material, and no two keys with the same `kid`. Throws otherwise.
 */
export function assertValidJwks(jwks: unknown): asserts jwks is JWKS {
  if (!jwks || typeof jwks !== 'object' || !Array.isArray((jwks as JWKS).keys)) {
    throw new Error('JWKS must be an object with a "keys" array.');
  }
  const keys = (jwks as JWKS).keys as unknown[];
  if (keys.length === 0) throw new Error('JWKS response contains no keys.');
  if (keys.length > JWKS_MAX_KEYS) throw new Error(`JWKS contains more than ${JWKS_MAX_KEYS} keys.`);
  const seen = new Set<string>();
  for (const key of keys) {
    if (!key || typeof key !== 'object' || Array.isArray(key)) throw new Error('JWKS contains a key that is not an object.');
    const k = key as Record<string, unknown>;
    if (typeof k.kty !== 'string' || !k.kty) throw new Error('JWKS contains a key without "kty".');
    if (typeof k.kid !== 'string' || !k.kid || k.kid.includes(':')) {
      throw new Error('JWKS contains a key without a valid "kid"; keys are selected by kid only.');
    }
    if ('d' in k || 'p' in k || 'q' in k || 'k' in k) {
      throw new Error(`JWKS key "${k.kid}" contains private or symmetric key material.`);
    }
    if (seen.has(k.kid)) throw new Error(`JWKS contains more than one key with kid "${k.kid}"; key selection would be ambiguous.`);
    seen.add(k.kid);
  }
}

/**
 * Why a JWK cannot be used to verify an EdDSA (Ed25519) passport signature, or null when it
 * can. Keys that are not JWK objects (PEM strings, KeyObjects) are not checked here.
 */
export function jwkUsageProblem(source: string | JWK | KeyObject): string | null {
  if (!source || typeof source !== 'object' || source instanceof KeyObject) return null;
  const k = source as JWK & Record<string, unknown>;
  const name = typeof k.kid === 'string' ? `JWK "${k.kid}"` : 'JWK';
  if (k.kty !== 'OKP' || k.crv !== 'Ed25519') {
    return `${name} is not an Ed25519 key (kty "${String(k.kty)}", crv "${String(k.crv)}"); EdDSA passports need kty "OKP" and crv "Ed25519".`;
  }
  if (typeof k.x !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(k.x)) {
    return `${name} has no valid 32-byte "x" public key value.`;
  }
  if (k.use !== undefined && k.use !== 'sig') return `${name} has "use" "${String(k.use)}"; a signing key must have "use" "sig".`;
  if (k.alg !== undefined && k.alg !== 'EdDSA' && k.alg !== 'Ed25519') {
    return `${name} has "alg" "${String(k.alg)}", which does not match EdDSA.`;
  }
  if (k.key_ops !== undefined && !(Array.isArray(k.key_ops) && k.key_ops.includes('verify'))) {
    return `${name} has "key_ops" without "verify".`;
  }
  if ('d' in k) return `${name} contains private key material.`;
  return null;
}

/** fetchJwks with the network options of safeGet (tests use its hooks). Not exported by the package. */
export async function fetchJwksWith(jwksUrl: string, options: SafeGetOptions): Promise<JWKS> {
  const res = await safeGet(jwksUrl, { maxBytes: JWKS_MAX_BYTES, timeoutMs: 10_000, ...options });
  let jwks: unknown;
  try {
    jwks = JSON.parse(res.body.toString('utf8'));
  } catch {
    throw new Error('JWKS response is not valid JSON.');
  }
  assertValidJwks(jwks);
  return jwks;
}

