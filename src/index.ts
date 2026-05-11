/**
 * @agentsigna/verify
 *
 * Standalone offline verifier for AgentSigna Action Authorization Passports (ASAAP v1.0)
 * and AgentSigna Ledger Chains (ASLC v1.0).
 *
 * Zero runtime dependencies — uses Node.js built-in `crypto` module only.
 * Requires Node.js >= 18.0.0.
 *
 * Security properties:
 *  - Ed25519 signature verification (RFC 8032) — constant-time, no timing oracle
 *  - Canonical JSON serialisation (RFC 8785-style, key-sorted) — prevents key-ordering bypass
 *  - Chain integrity via SHA-256 hash-chain — tamper detection across full event sequence
 *  - Cross-case isolation — verifyChain rejects events with mismatched actionCaseIds
 *  - Self-describing algorithm version — auto-detects v0 legacy chains and v1 chains
 *  - No network calls in verifyPassport / verifyChain — no SSRF risk (OWASP A10)
 *  - HTTPS-only JWKS fetch, redirect:error — prevents HTTPS→HTTP downgrade attacks
 */

import { createHash, createPublicKey, verify as nodeVerify, KeyObject } from 'node:crypto';
import { lookup } from 'node:dns/promises';
import { isIP } from 'node:net';

// ── Types ────────────────────────────────────────────────────────────────────

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

// ── Verification result types ─────────────────────────────────────────────────

export interface PassportVerificationResult {
  valid: boolean;
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

export interface ChainVerificationResult {
  valid: boolean;
  errors: string[];
  checkedEvents: number;
  chainVersion: string;
  genesisDigest: string | null;
  tipDigest: string | null;
}

// ── Canonical JSON (RFC 8785-style) ──────────────────────────────────────────

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

// ── Ed25519 signature verification ───────────────────────────────────────────

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

// ── Ledger chain digest ───────────────────────────────────────────────────────

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

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Verifies an AgentSigna passport against a public key (Ed25519 only).
 *
 * @param passport  - The passport object from the AgentSigna API or export
 * @param publicKey - Ed25519 public key as PEM string, JWK object, or Node.js KeyObject
 * @param options.expectedIssuer - If provided, the passport issuer field must match exactly.
 *                                 Always set this in production to prevent cross-tenant substitution.
 * @param options.actionPayload - If provided, re-computes actionHash to verify the passport
 *                                was issued for this exact action payload (ASAAP §4.3).
 *                                An error is returned if the passport has no actionHash to compare.
 * @param options.nowMs - Override clock for testing (default: Date.now())
 *
 * Example:
 *   const result = verifyPassport(passport, publicKey, {
 *     expectedIssuer: 'https://api.agentsigna.com/orgs/acme-corp',
 *   });
 *   if (!result.valid) console.error(result.errors);
 */
export function verifyPassport(
  passport: Passport,
  publicKey: string | JWK | KeyObject,
  options: {
    expectedIssuer?: string;
    actionPayload?: unknown;
    nowMs?: number;
  } = {},
): PassportVerificationResult {
  const errors: string[] = [];
  const warnings: string[] = [];
  const now = options.nowMs ?? Date.now();

  // ── 1. Structural validation ──────────────────────────────────────────────
  if (!passport || typeof passport !== 'object') {
    return { valid: false, errors: ['Passport is not a valid object.'], warnings };
  }
  if (!passport.signature || typeof passport.signature !== 'string') {
    errors.push('Passport is missing a signature field.');
  }
  if (!passport.payload || typeof passport.payload !== 'object') {
    errors.push('Passport is missing a payload field.');
    return { valid: false, errors, warnings };
  }

  const p = passport.payload as PassportPayload;

  // ── 2. Spec version check ─────────────────────────────────────────────────
  if (p.spec !== 'agentsigna-passport') {
    warnings.push(`Unknown spec identifier "${p.spec}". Expected "agentsigna-passport".`);
  }
  if (p.specVersion !== '1.0') {
    warnings.push(`Passport spec version "${p.specVersion}" — this verifier targets 1.0.`);
  }

  // ── 3. Issuer validation ──────────────────────────────────────────────────
  if (options.expectedIssuer) {
    if (!p.issuer) {
      errors.push('Passport payload is missing issuer field.');
    } else if (p.issuer !== options.expectedIssuer) {
      errors.push(
        `Issuer mismatch: expected "${options.expectedIssuer}", got "${p.issuer}". ` +
          'Possible cross-tenant passport substitution.',
      );
    }
  } else {
    warnings.push(
      'No expectedIssuer provided. Set options.expectedIssuer in production to prevent ' +
        'cross-tenant passport substitution.',
    );
  }

  // ── 4. Revocation check ───────────────────────────────────────────────────
  if (passport.status === 'REVOKED') {
    errors.push('Passport has been revoked.');
  }

  // ── 5. Expiry check ───────────────────────────────────────────────────────
  const expiresAt = new Date(p.expiresAt).getTime();
  if (Number.isNaN(expiresAt)) {
    errors.push('Passport expiresAt is not a valid date.');
  } else if (now > expiresAt) {
    errors.push(`Passport expired at ${p.expiresAt}.`);
  }

  // ── 6. jti presence (replay protection) ───────────────────────────────────
  if (!p.jti || typeof p.jti !== 'string') {
    warnings.push(
      'Passport is missing jti field (replay protection identifier). ' +
        'Use JtiCache to detect replayed passports.',
    );
  }

  // ── 7. Signature verification ─────────────────────────────────────────────
  // Always attempt signature verification regardless of other errors so that
  // tamper evidence is always surfaced in the error list.
  if (passport.signature) {
    try {
      const key = loadPublicKey(publicKey);
      const sigValid = verifyEd25519(passport.payload, passport.signature, key);
      if (!sigValid) {
        errors.push('Signature verification failed — payload may have been tampered with.');
      }
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      errors.push(`Failed to load public key or verify signature: ${message}`);
    }
  }

  // ── 8. Action payload integrity (optional) ────────────────────────────────
  let actionHashVerified = false;
  if (options.actionPayload !== undefined) {
    if (!p.actionHash) {
      // Caller requested integrity check but the passport was issued without an actionHash.
      // Surface as an error rather than silently skipping — the caller's expectation was not met.
      errors.push(
        'actionPayload was provided for integrity verification, but the passport has no ' +
          'actionHash. Cannot confirm the passport covers this specific payload.',
      );
    } else {
      const recomputed = createHash('sha256')
        .update(stableStringify(options.actionPayload))
        .digest('hex');
      actionHashVerified = recomputed === p.actionHash;
      if (!actionHashVerified) {
        errors.push(
          'actionHash mismatch — the action payload does not match what was authorized. ' +
            'Possible tampering.',
        );
      }
    }
  }

  return {
    valid: errors.length === 0,
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
 * Events may be provided in any order — the verifier reconstructs the chain
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

  // ── Cross-case isolation — all events must belong to the same action case ──
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

  // ── Reconstruct chain from genesis by following previousDigest links ───────
  const byPreviousDigest = new Map<string | null, LedgerEvent>();
  for (const event of events) {
    byPreviousDigest.set(event.previousDigest, event);
  }

  const ordered: LedgerEvent[] = [];
  const visitedDigests = new Set<string>();
  let current = byPreviousDigest.get(null);
  while (current) {
    // Cycle detection — a self-referential or looping chain would otherwise hang indefinitely
    if (visitedDigests.has(current.eventDigest)) {
      errors.push(
        `Cycle detected at event ${current.id} (digest ${current.eventDigest.slice(0, 16)}…) — ` +
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

  // ── Detect algorithm version from genesis event ───────────────────────────
  const chainVersion = detectChainVersion(ordered[0]);
  const actionCaseId = ordered[0]?.actionCaseId ?? '';

  // ── Re-compute and verify every digest ────────────────────────────────────
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
        `Event ${event.id} (${event.eventType}): digest mismatch — event was tampered with.`,
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
 * Fetches a JWKS from a URL and returns the first Ed25519 key.
 * For auditor tooling — call once and cache the result.
 *
 * Security:
 * - HTTPS-only input URL (rejects HTTP to prevent initial MITM, OWASP A10)
 * - redirect:'error' (prevents HTTPS→HTTP downgrade via redirect)
 * - 10-second timeout (AbortSignal.timeout, Node 18+)
 * - Does NOT execute fetched content
 */
export async function fetchPublicKeyFromJwks(
  jwksUrl: string,
  keyId?: string,
): Promise<KeyObject> {
  const url = validateHttpsUrl(jwksUrl);
  await assertPublicHostname(url.hostname);

  const res = await fetch(url.toString(), {
    headers: { Accept: 'application/json' },
    // Prevent HTTPS→HTTP downgrade attacks via redirect chains
    redirect: 'error',
    signal: AbortSignal.timeout(10_000),
  });

  if (!res.ok) {
    throw new Error(`Failed to fetch JWKS from ${url.toString()}: HTTP ${res.status}`);
  }

  const jwks = (await res.json()) as JWKS;
  if (!Array.isArray(jwks.keys) || jwks.keys.length === 0) {
    throw new Error('JWKS response contains no keys.');
  }

  const key = keyId
    ? jwks.keys.find((k) => k.kid === keyId)
    : jwks.keys.find((k) => k.kty === 'OKP' && k.crv === 'Ed25519');

  if (!key) {
    throw new Error(
      keyId
        ? `No key with kid "${keyId}" found in JWKS.`
        : 'No Ed25519 key found in JWKS.',
    );
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  return createPublicKey({ key: key as any, format: 'jwk' });
}

function validateHttpsUrl(rawUrl: string): URL {
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    throw new Error(`Invalid JWKS URL: ${rawUrl}`);
  }

  if (url.protocol !== 'https:') {
    throw new Error(
      `SSRF/MITM protection: JWKS URL must use HTTPS. Got: ${rawUrl}`,
    );
  }

  return url;
}

async function assertPublicHostname(hostname: string): Promise<void> {
  if (isPrivateHostnameLiteral(hostname)) {
    throw new Error(`SSRF protection: JWKS hostname is private or loopback: ${hostname}`);
  }

  const addresses = await lookup(hostname, { all: true, verbatim: true });
  if (addresses.length === 0) {
    throw new Error(`JWKS hostname did not resolve: ${hostname}`);
  }

  const privateAddress = addresses.find((entry) => isPrivateIp(entry.address));
  if (privateAddress) {
    throw new Error(
      `SSRF protection: JWKS hostname resolved to private or loopback address: ${privateAddress.address}`,
    );
  }
}

function isPrivateHostnameLiteral(hostname: string): boolean {
  const normalized = hostname.toLowerCase().replace(/^\[|\]$/g, '');
  if (normalized === 'localhost') return true;

  const ipv4 = parseIpv4(normalized);
  if (ipv4) return isPrivateIpv4(ipv4);

  if (isIP(normalized) === 6) {
    return isPrivateIpv6(normalized);
  }

  return false;
}

function isPrivateIp(address: string): boolean {
  const normalized = address.toLowerCase();
  const ipv4 = parseIpv4(normalized);
  if (ipv4) return isPrivateIpv4(ipv4);
  return isPrivateIpv6(normalized);
}

function parseIpv4(value: string): number[] | null {
  const parts = value.split('.');
  if (parts.length !== 4) return null;
  const octets = parts.map((part) => Number(part));
  if (octets.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return null;
  return octets;
}

function isPrivateIpv4([a, b]: number[]): boolean {
  return (
    a === 0 ||
    a === 10 ||
    a === 127 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    a >= 224
  );
}

function isPrivateIpv6(address: string): boolean {
  const normalized = address.replace(/^::ffff:/, '');
  const mappedIpv4 = parseIpv4(normalized);
  if (mappedIpv4) return isPrivateIpv4(mappedIpv4);

  return (
    normalized === '::1' ||
    normalized === '::' ||
    normalized.startsWith('fc') ||
    normalized.startsWith('fd') ||
    normalized.startsWith('fe80:') ||
    normalized.startsWith('ff')
  );
}

/**
 * In-memory jti cache for replay attack detection.
 *
 * Passports are single-use — if you receive the same jti twice, it is a replay.
 * This cache automatically evicts expired entries to prevent unbounded memory growth.
 *
 * Usage:
 *   const cache = new JtiCache();
 *   const result = verifyPassport(passport, publicKey);
 *   if (result.valid) {
 *     if (cache.seen(result.passport.jti, result.passport.expiresAt)) {
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
