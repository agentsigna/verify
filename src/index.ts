/**
 * @agentsigna/verify
 *
 * Standalone offline verifier for AgentSigna Action Authorization Passports and
 * AgentSigna Ledger Chains (passport format agentsigna-passport/1.0, specification v1.1).
 *
 * Zero runtime dependencies - uses Node.js built-in `crypto` module only.
 * Requires Node.js >= 18.0.0.
 *
 * Security properties:
 *  - Ed25519 signature verification (RFC 8032) - constant-time, no timing oracle
 *  - Canonical JSON serialisation (keys sorted by UTF-16 code units, no whitespace,
 *    ECMAScript JSON.stringify for strings and numbers) - prevents key-ordering bypass
 *  - Key selection by kid - the key id in the signature must match the key's kid
 *  - Chain integrity via SHA-256 hash-chain - tamper detection across full event sequence
 *  - Cross-case isolation - verifyChain rejects events with mismatched actionCaseIds
 *  - Self-describing algorithm version - auto-detects v0 legacy chains and v1 chains
 *  - Fail-closed authorization result: mayProceed (alias valid) is false for DENY and
 *    REQUIRE_APPROVAL passports and for unknown spec identifiers or format major versions
 *  - No network calls in verifyPassport / verifyChain - no SSRF risk (OWASP A10)
 *  - JWKS fetch: HTTPS only, resolve once and pin the connected address (no DNS rebinding),
 *    public addresses only (complete IPv4/IPv6 special-use ranges), no redirects, 64 KB
 *    response limit, 10 s timeout, unambiguous key sets only
 */

import { createHash, createPublicKey, verify as nodeVerify, KeyObject } from 'node:crypto';
import { assertValidJwks, fetchJwksWith, jwkUsageProblem, JWKS_MAX_BYTES } from './jwks.js';

export { assertValidJwks, JWKS_MAX_BYTES };

// Types

export interface PassportPayload {
  spec: 'agentsigna-passport';
  specVersion: '1.0';
  jti: string;
  actionHash: string | null;
  publicKeyRef: string;
  issuer: string;
  actionCaseId: string;
  machineActorId: string;
  policyId: string;
  actionType: string | null;
  amount: number | null;
  currency: string | null;
  counterpartyId: string | null;
  counterpartyName: string | null;
  decision: 'ALLOW' | 'ALLOW_WITH_CONDITIONS' | 'REQUIRE_APPROVAL' | 'DENY';
  rationale: string;
  approvalChain: Array<{
    approverId: string;
    decision: string;
    comment?: string | null;
    createdAt: string;
  }>;
  issuedAt: string;
  expiresAt: string;
}

export interface Passport {
  id: string;
  actionCaseId: string;
  status: 'ACTIVE' | 'REVOKED';
  issuedAt: string | Date;
  expiresAt: string | Date;
  signature: string;
  payload: PassportPayload | Record<string, unknown>;
}

export interface LedgerEvent {
  id: string;
  actionCaseId: string;
  eventType: string;
  payload: Record<string, unknown>;
  eventDigest: string;
  previousDigest: string | null;
  createdAt: string | Date;
}

export interface JWK {
  kty: string;
  crv?: string;
  x?: string;
  kid?: string;
  use?: string;
  alg?: string;
}

export interface JWKS {
  keys: JWK[];
}

/** The parts of a passport signature string `<alg>:<kid>:<base64url signature>`. */
export interface ParsedSignature {
  alg: string;
  kid: string;
  signature: string;
}

// Verification result types

/**
 * Result of verifyPassport.
 *
 * Use `mayProceed` to decide whether the action may be executed. It is true only when the
 * signature, the claims, the decision and the expiry pass and every expectation the caller
 * supplied matched. `valid` is the same value, kept for 1.x callers.
 */
export interface PassportVerificationResult {
  /** Alias of `mayProceed`, kept for 1.x callers. */
  valid: boolean;
  /** True only when every check below passed: the only value to gate execution on. */
  mayProceed: boolean;
  /** The Ed25519 signature verifies over the canonical payload with the key whose kid matches. */
  signatureValid: boolean;
  /**
   * The payload is a supported passport: spec identifier `agentsigna-passport`, format major
   * version 1, issuer equal to `expectedIssuer` when given, and the copy's status is not REVOKED.
   */
  claimsValid: boolean;
  /** The signed decision is ALLOW or ALLOW_WITH_CONDITIONS. DENY and REQUIRE_APPROVAL never authorize. */
  decisionAuthorizes: boolean;
  /** The signed expiresAt is a valid date and has not passed. */
  notExpired: boolean;
  /** actionPayload (hash) and expectedActionType matched; false on mismatch; null when not supplied. */
  actionMatches: boolean | null;
  /** expectedAudience matched; false on mismatch or when the format has no audience claim; null when not supplied. */
  audienceMatches: boolean | null;
  /** expectedEnvironment matched; false on mismatch or when the format has no environment claim; null when not supplied. */
  environmentMatches: boolean | null;
  errors: string[];
  warnings: string[];
  passport?: {
    jti: string;
    actionCaseId: string;
    issuer: string;
    decision: string;
    actionType: string | null;
    amount: number | null;
    currency: string | null;
    counterpartyName: string | null;
    issuedAt: string;
    expiresAt: string;
    actionHashVerified: boolean;
  };
}

export interface VerifyPassportOptions {
  /** The issuer the passport must name. AgentSigna-issued passports carry "agentsigna". */
  expectedIssuer?: string;
  /** The action payload; its canonical SHA-256 must equal the signed actionHash. */
  actionPayload?: unknown;
  /** The action type the passport must carry (signed `actionType`). */
  expectedActionType?: string;
  /**
   * The receiving system the passport must be addressed to. Format agentsigna-passport/1.0 has
   * no audience claim, so with a 1.0 passport this expectation cannot be confirmed and
   * `audienceMatches` is false.
   */
  expectedAudience?: string;
  /**
   * The environment (for example "production") the passport must be issued for. Format
   * agentsigna-passport/1.0 has no environment claim, so with a 1.0 passport this expectation
   * cannot be confirmed and `environmentMatches` is false.
   */
  expectedEnvironment?: string;
  /** Override clock for testing (default: Date.now()). */
  nowMs?: number;
}

export interface ChainVerificationResult {
  valid: boolean;
  errors: string[];
  checkedEvents: number;
  chainVersion: string;
  genesisDigest: string | null;
  tipDigest: string | null;
}

// Canonical JSON (RFC 8785-style)

function stableStringify(value: unknown): string {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${(value as unknown[]).map((item) => stableStringify(item)).join(',')}]`;
  }
  const keys = Object.keys(value as Record<string, unknown>).sort();
  const entries = keys.map(
    (key) =>
      `${JSON.stringify(key)}:${stableStringify((value as Record<string, unknown>)[key])}`,
  );
  return `{${entries.join(',')}}`;
}

// Ed25519 signature verification

function loadPublicKey(source: string | JWK | KeyObject): KeyObject {
  if (typeof source === 'string') {
    return createPublicKey(source);
  }
  if (source && typeof source === 'object' && !('asymmetricKeyType' in source)) {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    return createPublicKey({ key: source as any, format: 'jwk' });
  }
  return source as KeyObject;
}

/**
 * Splits a passport signature string into its algorithm, key id and signature parts.
 * Returns null when the value is not a string of exactly three colon-separated parts.
 *
 * Example: parseSignature('ed25519:key-2026-01:T3Bl...') returns
 *   { alg: 'ed25519', kid: 'key-2026-01', signature: 'T3Bl...' }
 */
export function parseSignature(signature: string): ParsedSignature | null {
  if (typeof signature !== 'string') return null;
  const parts = signature.split(':');
  if (parts.length !== 3) return null;
  const [alg, kid, sig] = parts;
  return { alg, kid, signature: sig };
}

function jwkKid(source: string | JWK | KeyObject): string | undefined {
  if (!source || typeof source !== 'object' || source instanceof KeyObject) return undefined;
  const kid = (source as JWK).kid;
  return typeof kid === 'string' ? kid : undefined;
}

function verifyEd25519(
  payload: unknown,
  signatureStr: string,
  publicKey: KeyObject,
): boolean {
  const parts = signatureStr.split(':');
  if (parts.length !== 3 || parts[0] !== 'ed25519') return false;
  const [, , sigBase64url] = parts;
  try {
    const message = Buffer.from(stableStringify(payload), 'utf8');
    const sigBytes = Buffer.from(sigBase64url, 'base64url');
    // Ed25519 verify is constant-time per RFC 8032 (no timing oracle risk)
    return nodeVerify(null, message, publicKey, sigBytes);
  } catch {
    return false;
  }
}

// Ledger chain digest

function computeDigest(
  version: string,
  actionCaseId: string,
  previousDigest: string | null,
  eventType: string,
  payload: unknown,
): string {
  const canonical = stableStringify(payload);
  if (version === 'v1') {
    return createHash('sha256')
      .update(`v1:${actionCaseId}:${previousDigest ?? 'GENESIS'}:${eventType}:${canonical}`)
      .digest('hex');
  }
  // v0 legacy
  return createHash('sha256')
    .update(`${previousDigest ?? ''}:${eventType}:${canonical}`)
    .digest('hex');
}

function detectChainVersion(genesisEvent: LedgerEvent | undefined): string {
  if (!genesisEvent) return 'v0';
  const v = (genesisEvent.payload as Record<string, unknown>)?._ledgerVersion;
  return typeof v === 'string' ? v : 'v0';
}

function isSha256Hex(value: unknown): value is string {
  return typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
}

// Public API

/** Passport format major versions this verifier implements. */
const SUPPORTED_FORMAT_MAJOR = 1;
/** Decisions that authorize execution. */
const AUTHORIZING_DECISIONS = new Set(['ALLOW', 'ALLOW_WITH_CONDITIONS']);

function failedResult(errors: string[], warnings: string[]): PassportVerificationResult {
  return {
    valid: false,
    mayProceed: false,
    signatureValid: false,
    claimsValid: false,
    decisionAuthorizes: false,
    notExpired: false,
    actionMatches: null,
    audienceMatches: null,
    environmentMatches: null,
    errors,
    warnings,
  };
}

/**
 * Verifies an AgentSigna passport against a public key (Ed25519 only) and evaluates whether
 * the action it describes may proceed. Fails closed.
 *
 * @param passport  - The passport object from the AgentSigna API or export
 * @param publicKey - Ed25519 public key as PEM string, JWK object, or Node.js KeyObject.
 *                    When a JWK with a `kid` is given, the kid must equal the key id in the
 *                    passport signature (`ed25519:<kid>:<sig>`); otherwise the passport is
 *                    rejected without trying the key. Select the key by kid, for example with
 *                    selectJwkForSignature or fetchJwkForPassport.
 * @param options.expectedIssuer - If provided, the passport issuer field must match exactly.
 *                                 AgentSigna-issued passports carry the issuer "agentsigna".
 *                                 Always set this in production.
 * @param options.actionPayload - If provided, re-computes actionHash to verify the passport
 *                                was issued for this exact action payload (section 4.3).
 *                                An error is returned if the passport has no actionHash to compare.
 * @param options.expectedActionType, expectedAudience, expectedEnvironment - Further
 *                                expectations; see VerifyPassportOptions.
 * @param options.nowMs - Override clock for testing (default: Date.now())
 *
 * Only `result.mayProceed` (or its 1.x alias `result.valid`) authorizes execution. It is false
 * for DENY and REQUIRE_APPROVAL passports, unknown spec identifiers and unsupported format
 * major versions, whatever the signature says.
 *
 * Example:
 *   const key = await fetchJwkForPassport(
 *     'https://api.agentsigna.com/.well-known/agentsigna-jwks.json',
 *     passport,
 *   );
 *   const result = verifyPassport(passport, key, { expectedIssuer: 'agentsigna', actionPayload });
 *   if (!result.mayProceed) throw new Error(result.errors.join('; '));
 */
export function verifyPassport(
  passport: Passport,
  publicKey: string | JWK | KeyObject,
  options: VerifyPassportOptions = {},
): PassportVerificationResult {
  const errors: string[] = [];
  const warnings: string[] = [];
  const now = options.nowMs ?? Date.now();

  // 1. Structural validation
  if (!passport || typeof passport !== 'object') {
    return failedResult(['Passport is not a valid object.'], warnings);
  }
  if (!passport.signature || typeof passport.signature !== 'string') {
    errors.push('Passport is missing a signature field.');
  }
  if (!passport.payload || typeof passport.payload !== 'object') {
    errors.push('Passport is missing a payload field.');
    return failedResult(errors, warnings);
  }

  const p = passport.payload as PassportPayload;
  let claimsValid = true;

  // 2. Document type and format version: unknown or unsupported values fail closed.
  if (p.spec !== 'agentsigna-passport') {
    claimsValid = false;
    errors.push(`Unknown spec identifier "${String(p.spec)}". Expected "agentsigna-passport".`);
  }
  const version = typeof p.specVersion === 'string' ? /^(\d+)\.(\d+)$/.exec(p.specVersion) : null;
  if (!version) {
    claimsValid = false;
    errors.push(`Passport specVersion "${String(p.specVersion)}" is not a valid format version.`);
  } else if (Number(version[1]) !== SUPPORTED_FORMAT_MAJOR) {
    claimsValid = false;
    errors.push(
      `Unsupported passport format version "${p.specVersion}": this verifier implements ` +
        `agentsigna-passport/${SUPPORTED_FORMAT_MAJOR}.x only.`,
    );
  } else if (p.specVersion !== '1.0') {
    warnings.push(`Passport spec version "${p.specVersion}" - this verifier targets 1.0.`);
  }

  // 3. Issuer validation
  if (options.expectedIssuer) {
    if (!p.issuer) {
      claimsValid = false;
      errors.push('Passport payload is missing issuer field.');
    } else if (p.issuer !== options.expectedIssuer) {
      claimsValid = false;
      errors.push(
        `Issuer mismatch: expected "${options.expectedIssuer}", got "${p.issuer}". ` +
          'The passport was not issued by the expected issuer.',
      );
    }
  } else {
    warnings.push(
      'No expectedIssuer provided. Set options.expectedIssuer in production ' +
        '(AgentSigna-issued passports use "agentsigna").',
    );
  }

  // 4. Decision: only ALLOW and ALLOW_WITH_CONDITIONS authorize execution.
  const decisionAuthorizes = typeof p.decision === 'string' && AUTHORIZING_DECISIONS.has(p.decision);
  if (!decisionAuthorizes) {
    errors.push(
      `Passport decision "${String(p.decision)}" does not authorize the action. ` +
        'Only ALLOW and ALLOW_WITH_CONDITIONS passports authorize execution.',
    );
  }

  // 5. Revocation check (status in the copy held; unsigned, see the specification).
  if (passport.status === 'REVOKED') {
    claimsValid = false;
    errors.push('Passport has been revoked.');
  }

  // 6. Expiry check
  let notExpired = false;
  const expiresAt = new Date(p.expiresAt).getTime();
  if (Number.isNaN(expiresAt)) {
    errors.push('Passport expiresAt is not a valid date.');
  } else if (now > expiresAt) {
    errors.push(`Passport expired at ${p.expiresAt}.`);
  } else {
    notExpired = true;
  }

  // 7. jti presence (replay protection)
  if (!p.jti || typeof p.jti !== 'string') {
    warnings.push(
      'Passport is missing jti field (replay protection identifier). ' +
        'Use JtiCache to detect replayed passports.',
    );
  }

  // 8. Signature verification
  // Always attempt signature verification regardless of other errors so that
  // tamper evidence is always surfaced in the error list.
  let signatureValid = false;
  if (passport.signature) {
    const parsed = parseSignature(passport.signature);
    const keyKid = jwkKid(publicKey);
    const keyProblem = jwkUsageProblem(publicKey);
    if (parsed && keyKid !== undefined && parsed.kid !== keyKid) {
      // Key selection is by kid only. A key with a different kid is never tried, so a
      // retired or unrelated key cannot stand in for the key that made the signature.
      errors.push(
        `Key id mismatch: the signature was made with kid "${parsed.kid}" but the supplied ` +
          `key has kid "${keyKid}". Select the JWKS key whose kid matches the signature.`,
      );
    } else if (keyProblem) {
      errors.push(`Failed to load public key or verify signature: ${keyProblem}`);
    } else {
      try {
        const key = loadPublicKey(publicKey);
        signatureValid = verifyEd25519(passport.payload, passport.signature, key);
        if (!signatureValid) {
          errors.push('Signature verification failed - payload may have been tampered with.');
        }
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : String(err);
        errors.push(`Failed to load public key or verify signature: ${message}`);
      }
    }
  }

  // 9. Action binding (optional expectations)
  let actionHashVerified = false;
  let actionMatches: boolean | null = null;
  if (options.actionPayload !== undefined) {
    if (!p.actionHash) {
      // Caller requested integrity check but the passport was issued without an actionHash.
      // Surface as an error rather than silently skipping - the caller's expectation was not met.
      errors.push(
        'actionPayload was provided for integrity verification, but the passport has no ' +
          'actionHash. Cannot confirm the passport covers this specific payload.',
      );
      actionMatches = false;
    } else {
      const recomputed = createHash('sha256')
        .update(stableStringify(options.actionPayload))
        .digest('hex');
      actionHashVerified = recomputed === p.actionHash;
      actionMatches = actionHashVerified;
      if (!actionHashVerified) {
        errors.push(
          'actionHash mismatch - the action payload does not match what was authorized. ' +
            'Possible tampering.',
        );
      }
    }
  }
  if (options.expectedActionType !== undefined) {
    const typeMatches = p.actionType === options.expectedActionType;
    if (!typeMatches) {
      errors.push(
        `Action type mismatch: expected "${options.expectedActionType}", got "${String(p.actionType)}".`,
      );
    }
    actionMatches = (actionMatches ?? true) && typeMatches;
  }

  // 10. Audience and environment: format 1.x (frozen at 1.0) carries neither claim, so a
  // supplied expectation cannot be confirmed and fails closed. Format 2.0 will define them.
  const unconfirmable = (field: 'audience' | 'environment', expected: string | undefined): boolean | null => {
    if (expected === undefined) return null;
    errors.push(
      `An expected ${field} was supplied, but passport format agentsigna-passport/1.x has no ` +
        `${field} claim, so it cannot be confirmed.`,
    );
    return false;
  };
  const audienceMatches = unconfirmable('audience', options.expectedAudience);
  const environmentMatches = unconfirmable('environment', options.expectedEnvironment);

  const mayProceed =
    signatureValid &&
    claimsValid &&
    decisionAuthorizes &&
    notExpired &&
    actionMatches !== false &&
    audienceMatches !== false &&
    environmentMatches !== false &&
    errors.length === 0;

  return {
    valid: mayProceed,
    mayProceed,
    signatureValid,
    claimsValid,
    decisionAuthorizes,
    notExpired,
    actionMatches,
    audienceMatches,
    environmentMatches,
    errors,
    warnings,
    passport: {
      jti: p.jti ?? '',
      actionCaseId: p.actionCaseId ?? '',
      issuer: p.issuer ?? '',
      decision: p.decision ?? '',
      actionType: p.actionType ?? null,
      amount: p.amount ?? null,
      currency: p.currency ?? null,
      counterpartyName: p.counterpartyName ?? null,
      issuedAt: p.issuedAt ?? '',
      expiresAt: p.expiresAt ?? '',
      actionHashVerified,
    },
  };
}

/**
 * Verifies the integrity of an AgentSigna ledger event chain.
 *
 * Events may be provided in any order - the verifier reconstructs the chain
 * by following previousDigest links (immune to timestamp manipulation).
 *
 * All events must share the same actionCaseId. Mixed-case event sets are rejected
 * to prevent cross-case chain grafting attacks.
 *
 * @param events - All ledger events for a single action case
 *
 * Example:
 *   const result = verifyChain(events);
 *   console.log(result.valid, result.chainVersion, result.checkedEvents);
 */
export function verifyChain(events: LedgerEvent[]): ChainVerificationResult {
  const errors: string[] = [];

  if (!Array.isArray(events) || events.length === 0) {
    return {
      valid: true,
      errors: [],
      checkedEvents: 0,
      chainVersion: 'unknown',
      genesisDigest: null,
      tipDigest: null,
    };
  }

  // Cross-case isolation - all events must belong to the same action case
  const caseIds = new Set(events.map((e) => e.actionCaseId));
  if (caseIds.size > 1) {
    return {
      valid: false,
      errors: [
        `Cross-case isolation violation: events from ${caseIds.size} different actionCaseIds ` +
          `were supplied (${[...caseIds].join(', ')}). ` +
          'verifyChain must be called with events from a single action case.',
      ],
      checkedEvents: 0,
      chainVersion: 'unknown',
      genesisDigest: null,
      tipDigest: null,
    };
  }

  for (const event of events) {
    if (!isSha256Hex(event.eventDigest)) {
      return {
        valid: false,
        errors: [`Event ${event.id}: eventDigest must be a 64-character lowercase hex digest.`],
        checkedEvents: 0,
        chainVersion: 'unknown',
        genesisDigest: null,
        tipDigest: null,
      };
    }
    if (event.previousDigest !== null && !isSha256Hex(event.previousDigest)) {
      return {
        valid: false,
        errors: [
          `Event ${event.id}: previousDigest must be null or a 64-character lowercase hex digest.`,
        ],
        checkedEvents: 0,
        chainVersion: 'unknown',
        genesisDigest: null,
        tipDigest: null,
      };
    }
  }

  // Reconstruct chain from genesis by following previousDigest links
  const byPreviousDigest = new Map<string | null, LedgerEvent>();
  for (const event of events) {
    byPreviousDigest.set(event.previousDigest, event);
  }

  const ordered: LedgerEvent[] = [];
  const visitedDigests = new Set<string>();
  let current = byPreviousDigest.get(null);
  while (current) {
    // Cycle detection - a self-referential or looping chain would otherwise hang indefinitely
    if (visitedDigests.has(current.eventDigest)) {
      errors.push(
        `Cycle detected at event ${current.id} (digest ${current.eventDigest.slice(0, 16)}...) - ` +
          'chain is self-referential or contains a loop. Possible tampering.',
      );
      break;
    }
    visitedDigests.add(current.eventDigest);
    ordered.push(current);
    current = byPreviousDigest.get(current.eventDigest);
  }

  // If we can't reach all events from genesis, the chain is broken
  if (errors.length === 0 && ordered.length !== events.length) {
    errors.push(
      `Chain is broken: only ${ordered.length} of ${events.length} events are reachable from genesis.`,
    );
  }

  // Detect algorithm version from genesis event
  const chainVersion = detectChainVersion(ordered[0]);
  const actionCaseId = ordered[0]?.actionCaseId ?? '';

  // Re-compute and verify every digest
  let previousDigest: string | null = null;
  for (const event of ordered) {
    const expected = computeDigest(
      chainVersion,
      actionCaseId,
      previousDigest,
      event.eventType,
      event.payload,
    );

    if (event.previousDigest !== previousDigest) {
      errors.push(
        `Event ${event.id}: previousDigest mismatch. ` +
          `Expected "${previousDigest}" got "${event.previousDigest}".`,
      );
      break;
    }
    if (event.eventDigest !== expected) {
      errors.push(
        `Event ${event.id} (${event.eventType}): digest mismatch - event was tampered with.`,
      );
      break;
    }
    previousDigest = event.eventDigest;
  }

  return {
    valid: errors.length === 0,
    errors,
    checkedEvents: ordered.length,
    chainVersion,
    genesisDigest: ordered[0]?.eventDigest ?? null,
    tipDigest: ordered[ordered.length - 1]?.eventDigest ?? null,
  };
}

/**
 * Fetches a JSON Web Key Set from a trusted HTTPS URL.
 *
 * Security:
 * - HTTPS only; URLs with credentials are refused
 * - the hostname is resolved once and every resolved address must be public; the connection
 *   is pinned to that address, so DNS rebinding cannot switch the target
 * - loopback, private, link-local (including 169.254.169.254 and fe80::/10), unique local,
 *   CGNAT, multicast, unspecified, documentation, benchmarking, reserved, NAT64 and
 *   IPv4-mapped, IPv4-compatible and other IPv4-embedding IPv6 addresses are refused
 * - redirects are refused, the response is limited to 64 KB, and the request times out
 *   after 10 seconds
 * - the key set must be well formed and unambiguous (see assertValidJwks)
 * - does not execute fetched content
 *
 * Only pass JWKS URLs you trust (for AgentSigna:
 * https://api.agentsigna.com/.well-known/agentsigna-jwks.json). Never pass the
 * passport's publicKeyRef or any other user-controlled URL.
 */
export async function fetchJwks(jwksUrl: string): Promise<JWKS> {
  return fetchJwksWith(jwksUrl, {});
}

/**
 * Selects the key that signed a passport from a JWKS: the Ed25519 key whose kid equals
 * the key id in the signature (`ed25519:<kid>:<sig>`). No other key is ever returned,
 * so after a key rotation older passports are checked with the retired key and newer
 * ones with the current key.
 *
 * Throws when the signature is not an Ed25519 passport signature with a kid, when the JWKS is
 * malformed or ambiguous (for example two keys with the same kid), when no key with that kid is
 * in the set, or when the key with that kid is not usable for EdDSA (not OKP/Ed25519, or a
 * `use` or `alg` that does not match).
 *
 * @param jwks      - A JWKS object ({ keys: [...] }), for example a pinned copy
 * @param signature - The passport signature string, or the passport itself
 */
export function selectJwkForSignature(
  jwks: JWKS,
  signature: string | Pick<Passport, 'signature'>,
): JWK {
  const sig = typeof signature === 'string' ? signature : signature?.signature;
  const parsed = parseSignature(sig as string);
  if (!parsed || parsed.alg !== 'ed25519' || !parsed.kid) {
    throw new Error(
      'Signature is not in the form "ed25519:<kid>:<signature>"; no public key can be selected.',
    );
  }
  assertValidJwks(jwks);
  const key = jwks.keys.find((k) => k.kid === parsed.kid);
  if (!key) {
    throw new Error(
      `No Ed25519 key with kid "${parsed.kid}" found in JWKS. If you cache the key set, ` +
        'fetch it again once before rejecting the passport.',
    );
  }
  const problem = jwkUsageProblem(key);
  if (problem) {
    throw new Error(`No Ed25519 key with kid "${parsed.kid}" usable for EdDSA in JWKS: ${problem}`);
  }
  return key;
}

/**
 * Fetches a JWKS (with the protections of fetchJwks) and returns the JWK whose kid matches
 * the passport's signature. Pass the result to verifyPassport; because the JWK carries its
 * kid, verifyPassport also confirms the kid match.
 *
 * Example:
 *   const key = await fetchJwkForPassport(
 *     'https://api.agentsigna.com/.well-known/agentsigna-jwks.json',
 *     passport,
 *   );
 *   const result = verifyPassport(passport, key, { expectedIssuer: 'agentsigna' });
 *   if (!result.mayProceed) throw new Error(result.errors.join('; '));
 */
export async function fetchJwkForPassport(
  jwksUrl: string,
  passport: string | Pick<Passport, 'signature'>,
): Promise<JWK> {
  const jwks = await fetchJwks(jwksUrl);
  return selectJwkForSignature(jwks, passport);
}

/**
 * Fetches a JWKS and returns one key as a KeyObject.
 *
 * With keyId: the key whose kid equals keyId, which must be usable for EdDSA. Without keyId:
 * the first Ed25519 key, which after a key rotation is usually NOT the key that signed older
 * passports. Prefer fetchJwkForPassport, which selects by the signature's kid.
 *
 * Same network protections as fetchJwks.
 */
export async function fetchPublicKeyFromJwks(
  jwksUrl: string,
  keyId?: string,
): Promise<KeyObject> {
  if (keyId !== undefined && (typeof keyId !== 'string' || !keyId)) {
    throw new Error('keyId must be a non-empty string when given.');
  }
  const jwks = await fetchJwks(jwksUrl);

  const key = keyId
    ? jwks.keys.find((k) => k.kid === keyId)
    : jwks.keys.find((k) => jwkUsageProblem(k) === null);

  if (!key) {
    throw new Error(
      keyId
        ? `No key with kid "${keyId}" found in JWKS.`
        : 'No Ed25519 key found in JWKS.',
    );
  }
  const problem = jwkUsageProblem(key);
  if (problem) throw new Error(problem);

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  return createPublicKey({ key: key as any, format: 'jwk' });
}

/**
 * In-memory jti cache for replay attack detection.
 *
 * Passports are single-use - if you receive the same jti twice, it is a replay.
 * This cache automatically evicts expired entries to prevent unbounded memory growth.
 *
 * Usage:
 *   const cache = new JtiCache();
 *   const result = verifyPassport(passport, publicKey, { expectedIssuer: 'agentsigna' });
 *   if (result.mayProceed) {
 *     if (cache.seen(result.passport!.jti, result.passport!.expiresAt)) {
 *       throw new Error('Replayed passport');
 *     }
 *   }
 *
 * For distributed deployments, replace with a Redis SET with TTL expiry.
 */
export class JtiCache {
  private readonly store = new Map<string, number>();

  /**
   * Returns true if this jti has been seen before (replay detected).
   * Records it if not seen. Evicts entries whose expiresAt has passed.
   */
  seen(jti: string, expiresAt: string | Date, nowMs = Date.now()): boolean {
    this.evict(nowMs);
    if (this.store.has(jti)) return true;
    const exp = new Date(expiresAt).getTime();
    if (!Number.isNaN(exp) && exp > nowMs) {
      this.store.set(jti, exp);
    }
    return false;
  }

  private evict(nowMs: number): void {
    for (const [jti, exp] of this.store) {
      if (exp <= nowMs) this.store.delete(jti);
    }
  }

  get size(): number {
    return this.store.size;
  }

  clear(): void {
    this.store.clear();
  }
}
