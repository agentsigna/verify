/**
 * @agentsigna/verify test suite
 * Run: npm test (requires npm run build first)
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  generateKeyPairSync,
  createHash,
  sign as nodeCryptoSign,
  KeyObject,
  createPrivateKey,
  createPublicKey,
} from 'node:crypto';
import { readFileSync } from 'node:fs';
import * as http from 'node:http';
import type { AddressInfo } from 'node:net';
import { join } from 'node:path';
import {
  assertValidJwks,
  JWKS_MAX_BYTES,
  verifyPassport,
  verifyChain,
  JtiCache,
  fetchPublicKeyFromJwks,
  fetchJwks,
  fetchJwkForPassport,
  selectJwkForSignature,
  parseSignature,
  Passport,
  PassportPayload,
  LedgerEvent,
  JWK,
  JWKS,
} from './index.js';
import { fetchJwksWith } from './jwks.js';
import { isBlockedAddress, safeGet } from './net.js';

// Test key pair

const { privateKey, publicKey } = generateKeyPairSync('ed25519');

// Helpers

function stableStringify(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) {
    return `[${(value as unknown[]).map(stableStringify).join(',')}]`;
  }
  const keys = Object.keys(value as Record<string, unknown>).sort();
  const entries = keys.map(
    (k) => `${JSON.stringify(k)}:${stableStringify((value as Record<string, unknown>)[k])}`,
  );
  return `{${entries.join(',')}}`;
}

function signPayload(payload: unknown, key: KeyObject): string {
  const message = Buffer.from(stableStringify(payload), 'utf8');
  // Ed25519 requires null digest - createSign('ed25519') is invalid in Node.js crypto
  const sig = nodeCryptoSign(null, message, key).toString('base64url');
  return `ed25519:v1:${sig}`;
}

function makePayload(overrides: Partial<PassportPayload> = {}): PassportPayload {
  return {
    spec: 'agentsigna-passport',
    specVersion: '1.0',
    jti: 'test-jti-001',
    actionHash: null,
    publicKeyRef: 'key-1',
    issuer: 'agentsigna',
    actionCaseId: 'case-001',
    machineActorId: 'actor-001',
    policyId: 'policy-001',
    actionType: 'PURCHASE_ORDER',
    amount: 5000,
    currency: 'USD',
    counterpartyId: 'vendor-001',
    counterpartyName: 'Acme Supplies',
    decision: 'ALLOW',
    rationale: 'Within policy limits.',
    approvalChain: [],
    issuedAt: new Date(Date.now() - 60_000).toISOString(),
    expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
    ...overrides,
  };
}

function makePassport(payload: PassportPayload, key: KeyObject = privateKey): Passport {
  return {
    id: 'passport-001',
    actionCaseId: payload.actionCaseId,
    status: 'ACTIVE',
    issuedAt: payload.issuedAt,
    expiresAt: payload.expiresAt,
    signature: signPayload(payload, key),
    payload,
  };
}

// verifyPassport

describe('verifyPassport', () => {
  it('accepts a valid passport', () => {
    const payload = makePayload();
    const passport = makePassport(payload);
    const result = verifyPassport(passport, publicKey, {
      expectedIssuer: 'agentsigna',
    });
    assert.equal(result.valid, true);
    assert.equal(result.errors.length, 0);
    assert.equal(result.passport?.decision, 'ALLOW');
    assert.equal(result.passport?.issuer, 'agentsigna');
  });

  it('rejects a tampered payload', () => {
    const payload = makePayload();
    const passport = makePassport(payload);
    // Tamper with amount after signing
    (passport.payload as PassportPayload).amount = 999999;
    const result = verifyPassport(passport, publicKey);
    assert.equal(result.valid, false);
    assert.ok(result.errors.some((e) => e.includes('Signature verification failed')));
  });

  it('rejects a revoked passport', () => {
    const payload = makePayload();
    const passport = { ...makePassport(payload), status: 'REVOKED' as const };
    const result = verifyPassport(passport, publicKey);
    assert.equal(result.valid, false);
    assert.ok(result.errors.some((e) => e.includes('revoked')));
  });

  it('rejects an expired passport', () => {
    const payload = makePayload({ expiresAt: new Date(Date.now() - 1000).toISOString() });
    const passport = makePassport(payload);
    const result = verifyPassport(passport, publicKey);
    assert.equal(result.valid, false);
    assert.ok(result.errors.some((e) => e.includes('expired')));
  });

  it('rejects issuer mismatch', () => {
    const payload = makePayload({ issuer: 'agentsigna' });
    const passport = makePassport(payload);
    const result = verifyPassport(passport, publicKey, {
      expectedIssuer: 'another-issuer',
    });
    assert.equal(result.valid, false);
    assert.ok(result.errors.some((e) => e.includes('Issuer mismatch')));
  });

  it('warns when no expectedIssuer is provided', () => {
    const payload = makePayload();
    const passport = makePassport(payload);
    const result = verifyPassport(passport, publicKey);
    assert.ok(result.warnings.some((w) => w.includes('expectedIssuer')));
  });

  it('verifies action payload hash', () => {
    const actionPayload = { orderId: 'PO-001', amount: 5000 };
    const hash = createHash('sha256')
      .update(stableStringify(actionPayload))
      .digest('hex');
    const payload = makePayload({ actionHash: hash });
    const passport = makePassport(payload);
    const result = verifyPassport(passport, publicKey, { actionPayload });
    assert.equal(result.valid, true);
    assert.equal(result.passport?.actionHashVerified, true);
  });

  it('rejects mismatched action payload hash', () => {
    const actionPayload = { orderId: 'PO-001', amount: 5000 };
    const hash = createHash('sha256')
      .update(stableStringify(actionPayload))
      .digest('hex');
    const payload = makePayload({ actionHash: hash });
    const passport = makePassport(payload);
    // Supply a different payload than what was signed
    const result = verifyPassport(passport, publicKey, {
      actionPayload: { orderId: 'PO-001', amount: 99999 },
    });
    assert.equal(result.valid, false);
    assert.ok(result.errors.some((e) => e.includes('actionHash mismatch')));
  });

  it('errors when actionPayload provided but passport has no actionHash', () => {
    const payload = makePayload({ actionHash: null });
    const passport = makePassport(payload);
    const result = verifyPassport(passport, publicKey, {
      actionPayload: { orderId: 'PO-001' },
    });
    assert.equal(result.valid, false);
    assert.ok(result.errors.some((e) => e.includes('no actionHash')));
  });

  it('always reports tamper even when passport is also revoked', () => {
    const payload = makePayload();
    const passport = makePassport(payload);
    (passport.payload as PassportPayload).amount = 999999;
    (passport as { status: string }).status = 'REVOKED';
    const result = verifyPassport(passport, publicKey);
    assert.equal(result.valid, false);
    assert.ok(result.errors.some((e) => e.includes('revoked')));
    assert.ok(result.errors.some((e) => e.includes('Signature verification failed')));
  });

  it('rejects non-object input', () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const result = verifyPassport(null as any, publicKey);
    assert.equal(result.valid, false);
    assert.ok(result.errors.some((e) => e.includes('not a valid object')));
  });

  it('accepts a JWK object as the public key', () => {
    const jwk = publicKey.export({ format: 'jwk' }) as { kty: string; crv: string; x: string };
    const payload = makePayload();
    const passport = makePassport(payload);
    const result = verifyPassport(passport, jwk, {
      expectedIssuer: 'agentsigna',
    });
    assert.equal(result.valid, true);
  });

  it('accepts a PEM string as the public key', () => {
    const pem = publicKey.export({ type: 'spki', format: 'pem' }) as string;
    const payload = makePayload();
    const passport = makePassport(payload);
    const result = verifyPassport(passport, pem, {
      expectedIssuer: 'agentsigna',
    });
    assert.equal(result.valid, true);
  });

  it('rejects a passport signed with a different key', () => {
    const { privateKey: otherPrivate } = generateKeyPairSync('ed25519');
    const payload = makePayload();
    const passport = makePassport(payload, otherPrivate);
    const result = verifyPassport(passport, publicKey, {
      expectedIssuer: 'agentsigna',
    });
    assert.equal(result.valid, false);
    assert.ok(result.errors.some((e) => e.includes('Signature verification failed')));
  });

  it('fails gracefully with a wrong key type (RSA instead of Ed25519)', () => {
    const { publicKey: rsaPublic } = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const payload = makePayload();
    const passport = makePassport(payload);
    const result = verifyPassport(passport, rsaPublic as unknown as KeyObject, {
      expectedIssuer: 'agentsigna',
    });
    assert.equal(result.valid, false);
    // Must not throw - must produce a clean error string
    assert.ok(result.errors.some((e) =>
      e.includes('Signature verification failed') || e.includes('Failed to load')
    ));
  });

  it('includes issuer in the passport summary even when invalid', () => {
    const payload = makePayload({ issuer: 'agentsigna' });
    const passport = { ...makePassport(payload), status: 'REVOKED' as const };
    const result = verifyPassport(passport, publicKey);
    assert.equal(result.passport?.issuer, 'agentsigna');
  });
});

// verifyChain

function sha256(data: string): string {
  return createHash('sha256').update(data).digest('hex');
}

function makeChain(caseId: string, count: number): LedgerEvent[] {
  const events: LedgerEvent[] = [];
  let prev: string | null = null;
  for (let i = 0; i < count; i++) {
    const eventType = i === 0 ? 'CASE_OPENED' : 'STATUS_CHANGED';
    const payload =
      i === 0
        ? { _ledgerVersion: 'v1', action: 'open' }
        : { status: `step-${i}` };
    const digest = sha256(
      `v1:${caseId}:${prev ?? 'GENESIS'}:${eventType}:${stableStringify(payload)}`,
    );
    events.push({
      id: `evt-${i}`,
      actionCaseId: caseId,
      eventType,
      payload,
      eventDigest: digest,
      previousDigest: prev,
      createdAt: new Date().toISOString(),
    });
    prev = digest;
  }
  return events;
}

describe('verifyChain', () => {
  it('accepts an empty event list', () => {
    const result = verifyChain([]);
    assert.equal(result.valid, true);
    assert.equal(result.checkedEvents, 0);
  });

  it('accepts a valid chain', () => {
    const events = makeChain('case-001', 3);
    const result = verifyChain(events);
    assert.equal(result.valid, true);
    assert.equal(result.checkedEvents, 3);
    assert.equal(result.chainVersion, 'v1');
  });

  it('accepts events supplied in reverse order', () => {
    const events = makeChain('case-001', 4).reverse();
    const result = verifyChain(events);
    assert.equal(result.valid, true);
    assert.equal(result.checkedEvents, 4);
  });

  it('rejects a tampered event', () => {
    const events = makeChain('case-001', 3);
    events[1].payload = { status: 'tampered' };
    const result = verifyChain(events);
    assert.equal(result.valid, false);
    assert.ok(result.errors.some((e) => e.includes('digest mismatch')));
  });

  it('rejects cross-case event mixing', () => {
    const eventsA = makeChain('case-001', 2);
    const eventsB = makeChain('case-002', 2);
    const result = verifyChain([...eventsA, ...eventsB]);
    assert.equal(result.valid, false);
    assert.ok(result.errors.some((e) => e.includes('Cross-case isolation violation')));
  });

  it('rejects a broken chain (missing link)', () => {
    const events = makeChain('case-001', 4);
    // Remove middle event
    events.splice(2, 1);
    const result = verifyChain(events);
    assert.equal(result.valid, false);
    assert.ok(result.errors.some((e) => e.includes('broken')));
  });

  it('rejects an empty string previousDigest explicitly', () => {
    const events = makeChain('case-001', 1);
    events[0].previousDigest = '';
    const result = verifyChain(events);
    assert.equal(result.valid, false);
    assert.ok(result.errors.some((e) => e.includes('previousDigest must be null or a 64-character lowercase hex digest')));
  });

  it('accepts a single-event chain', () => {
    const events = makeChain('case-001', 1);
    const result = verifyChain(events);
    assert.equal(result.valid, true);
    assert.equal(result.checkedEvents, 1);
    assert.equal(result.genesisDigest, result.tipDigest);
  });

  it('rejects a self-referential event without hanging (DoS prevention)', () => {
    const events = makeChain('case-001', 2);
    // Make event[1].previousDigest point to itself - breaks the chain linkage,
    // exits the traversal loop, surfaces as "broken" not an infinite loop
    events[1].previousDigest = events[1].eventDigest;
    const result = verifyChain(events);
    assert.equal(result.valid, false);
    assert.ok(result.errors.some((e) => e.includes('broken') || e.includes('Cycle')));
  });

  it('rejects a multi-event cycle without hanging (DoS prevention)', () => {
    // Build three events manually so event[2]'s digest equals event[0]'s digest,
    // creating a traversal loop: event[0] -> event[1] -> event[2] -> event[0] again
    const caseId = 'cycle-case';
    const digest0 = sha256(`v1:${caseId}:GENESIS:CASE_OPENED:${stableStringify({ _ledgerVersion: 'v1' })}`);
    const digest1 = sha256(`v1:${caseId}:${digest0}:STATUS_CHANGED:${stableStringify({ step: 1 })}`);
    const events: LedgerEvent[] = [
      { id: 'e0', actionCaseId: caseId, eventType: 'CASE_OPENED', payload: { _ledgerVersion: 'v1' }, eventDigest: digest0, previousDigest: null, createdAt: new Date().toISOString() },
      { id: 'e1', actionCaseId: caseId, eventType: 'STATUS_CHANGED', payload: { step: 1 }, eventDigest: digest1, previousDigest: digest0, createdAt: new Date().toISOString() },
      // Cycle: previousDigest points back to genesis, eventDigest equals digest0
      { id: 'e2', actionCaseId: caseId, eventType: 'STATUS_CHANGED', payload: { step: 2 }, eventDigest: digest0, previousDigest: digest1, createdAt: new Date().toISOString() },
    ];
    const result = verifyChain(events);
    assert.equal(result.valid, false);
    assert.ok(result.errors.some((e) => e.includes('Cycle detected') || e.includes('broken')));
  });

  it('verifies a v0 legacy chain', () => {
    // v0 chains have no _ledgerVersion in genesis payload
    const events: LedgerEvent[] = [];
    let prev: string | null = null;
    const caseId = 'case-v0';
    for (let i = 0; i < 3; i++) {
      const eventType = i === 0 ? 'CASE_OPENED' : 'STATUS_CHANGED';
      const payload = { action: `step-${i}` };
      // v0 digest: no version prefix, no actionCaseId
      const digest = sha256(`${prev ?? ''}:${eventType}:${stableStringify(payload)}`);
      events.push({
        id: `evt-v0-${i}`,
        actionCaseId: caseId,
        eventType,
        payload,
        eventDigest: digest,
        previousDigest: prev,
        createdAt: new Date().toISOString(),
      });
      prev = digest;
    }
    const result = verifyChain(events);
    assert.equal(result.valid, true);
    assert.equal(result.chainVersion, 'v0');
    assert.equal(result.checkedEvents, 3);
  });

  it('returns unknown chainVersion for empty input', () => {
    const result = verifyChain([]);
    assert.equal(result.chainVersion, 'unknown');
  });
});

// JtiCache

describe('JtiCache', () => {
  it('returns false on first sight of a jti', () => {
    const cache = new JtiCache();
    const exp = new Date(Date.now() + 3_600_000).toISOString();
    assert.equal(cache.seen('jti-001', exp), false);
  });

  it('returns true (replay) on second sight of a jti', () => {
    const cache = new JtiCache();
    const exp = new Date(Date.now() + 3_600_000).toISOString();
    cache.seen('jti-001', exp);
    assert.equal(cache.seen('jti-001', exp), true);
  });

  it('does not store already-expired jtis', () => {
    const cache = new JtiCache();
    const exp = new Date(Date.now() - 1000).toISOString();
    cache.seen('jti-expired', exp);
    assert.equal(cache.size, 0);
  });

  it('evicts expired entries', () => {
    const cache = new JtiCache();
    const nowMs = Date.now();
    const pastExp = new Date(nowMs + 100).toISOString();
    cache.seen('jti-001', pastExp, nowMs);
    assert.equal(cache.size, 1);
    // Advance clock past expiry
    cache.seen('jti-002', new Date(nowMs + 3_600_000).toISOString(), nowMs + 200);
    assert.equal(cache.size, 1); // jti-001 evicted, jti-002 added
  });

  it('clear empties the store', () => {
    const cache = new JtiCache();
    const exp = new Date(Date.now() + 3_600_000).toISOString();
    cache.seen('jti-001', exp);
    cache.clear();
    assert.equal(cache.size, 0);
  });

  it('accepts a Date object for expiresAt', () => {
    const cache = new JtiCache();
    const exp = new Date(Date.now() + 3_600_000);
    assert.equal(cache.seen('jti-date', exp), false);
    assert.equal(cache.seen('jti-date', exp), true);
  });

  it('does not store a jti with an invalid expiresAt date', () => {
    const cache = new JtiCache();
    cache.seen('jti-bad-date', 'not-a-date');
    assert.equal(cache.size, 0);
  });
});

// fetchPublicKeyFromJwks

describe('fetchPublicKeyFromJwks', () => {
  it('rejects non-HTTPS JWKS URLs', async () => {
    await assert.rejects(
      () => fetchPublicKeyFromJwks('http://keys.example.test/.well-known/jwks.json'),
      /must use HTTPS/,
    );
  });

  it('rejects loopback JWKS URLs before fetch', async () => {
    const originalFetch = globalThis.fetch;
    let called = false;
    globalThis.fetch = (async () => {
      called = true;
      throw new Error('fetch should not be called');
    }) as typeof fetch;

    try {
      await assert.rejects(
        () => fetchPublicKeyFromJwks('https://127.0.0.1/.well-known/jwks.json'),
        /private or loopback/,
      );
      assert.equal(called, false);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});

// 1.2.0: key selection by kid

interface FixtureCase {
  name: string;
  kid: string;
  passport: Passport;
  actionPayload: unknown;
}

interface RegressionCase {
  case: string;
  variant: string;
  keyForm: 'pem' | 'jwk' | 'jwk-without-kid';
  keyKid: string;
  passport: Passport;
  actionPayload?: unknown;
  nowMs: number;
  v111Valid: boolean;
  v111Errors: string[];
}

interface Fixtures {
  jwks: JWKS;
  keys: Record<string, { publicKeyPem: string }>;
  cases: FixtureCase[];
  regression: RegressionCase[];
}

// Passports issued by the AgentSigna issuing code path with deterministic test keys
// (see test-fixtures/README.md). dist-test/index.test.js reads ../test-fixtures.
const fixtures: Fixtures = JSON.parse(
  readFileSync(join(__dirname, '..', 'test-fixtures', 'passports.json'), 'utf8'),
);

function verifyAt(p: Passport): number {
  return new Date((p.payload as PassportPayload).issuedAt).getTime() + 60_000;
}

function signWithKid(payload: PassportPayload, kid: string, key: KeyObject = privateKey): Passport {
  const message = Buffer.from(stableStringify(payload), 'utf8');
  const sig = nodeCryptoSign(null, message, key).toString('base64url');
  return { ...makePassport(payload, key), signature: `ed25519:${kid}:${sig}` };
}

describe('parseSignature', () => {
  it('splits an Ed25519 signature into alg, kid and signature', () => {
    assert.deepEqual(parseSignature('ed25519:key-2026-01:abc_-'), {
      alg: 'ed25519',
      kid: 'key-2026-01',
      signature: 'abc_-',
    });
  });

  it('returns null for malformed values', () => {
    assert.equal(parseSignature('ed25519:only-two'), null);
    assert.equal(parseSignature('a:b:c:d'), null);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    assert.equal(parseSignature(undefined as any), null);
  });
});

describe('verifyPassport kid check', () => {
  const jwk = publicKey.export({ format: 'jwk' }) as JWK;

  it('accepts a JWK whose kid matches the signature kid', () => {
    const passport = signWithKid(makePayload(), 'key-2026-01');
    const result = verifyPassport(passport, { ...jwk, kid: 'key-2026-01' }, { expectedIssuer: 'agentsigna' });
    assert.equal(result.valid, true, result.errors.join('; '));
  });

  it('rejects a JWK whose kid differs from the signature kid, without trying the key', () => {
    // Same key material, different kid: the signature itself would verify.
    const passport = signWithKid(makePayload(), 'key-2026-01');
    const result = verifyPassport(passport, { ...jwk, kid: 'key-2026-02' }, { expectedIssuer: 'agentsigna' });
    assert.equal(result.valid, false);
    assert.equal(result.errors.length, 1);
    assert.match(
      result.errors[0],
      /Key id mismatch: the signature was made with kid "key-2026-01" but the supplied key has kid "key-2026-02"/,
    );
  });

  it('still reports other failures next to a kid mismatch', () => {
    const passport = signWithKid(makePayload(), 'key-2026-01');
    passport.status = 'REVOKED';
    const result = verifyPassport(passport, { ...jwk, kid: 'other' }, { expectedIssuer: 'agentsigna' });
    assert.equal(result.valid, false);
    assert.ok(result.errors.some((e) => e.includes('revoked')));
    assert.ok(result.errors.some((e) => e.includes('Key id mismatch')));
  });

  it('does not apply the kid check to keys without a kid (JWK without kid, PEM, KeyObject)', () => {
    const passport = signWithKid(makePayload(), 'key-2026-01');
    const pem = publicKey.export({ type: 'spki', format: 'pem' }) as string;
    for (const key of [jwk, pem, publicKey]) {
      const result = verifyPassport(passport, key, { expectedIssuer: 'agentsigna' });
      assert.equal(result.valid, true, result.errors.join('; '));
    }
  });
});

describe('selectJwkForSignature', () => {
  it('selects the key whose kid matches, not the first key', () => {
    const old = fixtures.cases.find((c) => c.kid === 'fixture-2026-a')!;
    assert.equal(fixtures.jwks.keys[0].kid, 'fixture-2026-b');
    const key = selectJwkForSignature(fixtures.jwks, old.passport);
    assert.equal(key.kid, 'fixture-2026-a');
    assert.equal(selectJwkForSignature(fixtures.jwks, old.passport.signature).kid, 'fixture-2026-a');
  });

  it('throws for an unknown kid instead of falling back to another key', () => {
    const passport = signWithKid(makePayload(), 'not-published');
    assert.throws(
      () => selectJwkForSignature(fixtures.jwks, passport),
      /No Ed25519 key with kid "not-published"/,
    );
  });

  it('throws for non-Ed25519 signatures', () => {
    assert.throws(() => selectJwkForSignature(fixtures.jwks, 'hmac-sha256:k1:abc'), /ed25519:<kid>:<signature>/);
    assert.throws(() => selectJwkForSignature(fixtures.jwks, 'garbage'), /ed25519:<kid>:<signature>/);
  });

  it('refuses a key with the right kid but the wrong key type', () => {
    const jwks: JWKS = { keys: [{ kty: 'RSA', kid: 'k1' }] };
    assert.throws(() => selectJwkForSignature(jwks, 'ed25519:k1:abc'), /No Ed25519 key with kid "k1"/);
  });
});

describe('fixtures from the issuing code path', () => {
  it('cover both keys of a rotation', () => {
    const kids = new Set(fixtures.cases.map((c) => c.kid));
    assert.deepEqual([...kids].sort(), ['fixture-2026-a', 'fixture-2026-b']);
  });

  for (const c of fixtures.cases) {
    it(`verifies with the JWKS key selected by kid: ${c.name}`, () => {
      const key = selectJwkForSignature(fixtures.jwks, c.passport);
      assert.equal(key.kid, c.kid);
      const options: Parameters<typeof verifyPassport>[2] = {
        expectedIssuer: 'agentsigna',
        nowMs: verifyAt(c.passport),
      };
      if (c.actionPayload !== null) options.actionPayload = c.actionPayload;
      const result = verifyPassport(c.passport, key, options);
      assert.equal(result.valid, true, result.errors.join('; '));
      assert.equal(result.warnings.length, 0, result.warnings.join('; '));
      assert.equal(result.passport?.actionHashVerified, c.actionPayload !== null);
    });

    it(`rejects the other rotation key by kid: ${c.name}`, () => {
      const other = fixtures.jwks.keys.find((k) => k.kid !== c.kid)!;
      const result = verifyPassport(c.passport, other, {
        expectedIssuer: 'agentsigna',
        nowMs: verifyAt(c.passport),
      });
      assert.equal(result.valid, false);
      assert.ok(result.errors.some((e) => e.includes('Key id mismatch')));
    });
  }
});

describe('regression: every passport 1.1.1 accepted still verifies (valid and mayProceed)', () => {
  it('has recorded 1.1.1 results', () => {
    assert.ok(fixtures.regression.length > 0);
    assert.ok(fixtures.regression.some((r) => r.v111Valid));
    assert.ok(fixtures.regression.some((r) => !r.v111Valid));
  });

  for (const r of fixtures.regression) {
    it(`${r.case} / ${r.variant} / ${r.keyForm}: same result as 1.1.1 (${r.v111Valid})`, () => {
      const jwk = fixtures.jwks.keys.find((k) => k.kid === r.keyKid);
      let key: string | JWK;
      if (r.keyForm === 'pem') key = fixtures.keys[r.keyKid].publicKeyPem;
      else if (r.keyForm === 'jwk') key = jwk!;
      else {
        const { kid: _kid, ...rest } = jwk!;
        key = rest as JWK;
      }
      const options: Parameters<typeof verifyPassport>[2] = { expectedIssuer: 'agentsigna', nowMs: r.nowMs };
      if (r.actionPayload !== undefined) options.actionPayload = r.actionPayload;
      const result = verifyPassport(r.passport, key, options);
      assert.equal(result.valid, r.v111Valid, result.errors.join('; '));
      assert.equal(result.mayProceed, r.v111Valid, result.errors.join('; '));
      assert.deepEqual(result.errors, r.v111Errors);
      if (r.v111Valid) {
        assert.equal(result.signatureValid, true);
        assert.equal(result.claimsValid, true);
        assert.equal(result.decisionAuthorizes, true);
        assert.equal(result.notExpired, true);
        assert.equal(result.actionMatches, r.actionPayload !== undefined ? true : null);
      }
    });
  }
});

// JWKS retrieval: SSRF protections, pinning and key-set validation

type LookupAddr = { address: string; family: number };
function fakeLookup(answers: LookupAddr[][]) {
  const calls: string[] = [];
  const lookup = (hostname: string, _opts: unknown, cb: (err: NodeJS.ErrnoException | null, a: LookupAddr[]) => void) => {
    calls.push(hostname);
    const answer = answers[Math.min(calls.length - 1, answers.length - 1)];
    setImmediate(() => cb(null, answer));
  };
  return { lookup, calls };
}

/** A plain HTTP server on 127.0.0.1 standing in for a JWKS host (tests only allow HTTP via hooks). */
async function withServer(
  handler: http.RequestListener,
  fn: (port: number, seen: http.IncomingMessage[]) => Promise<void>,
): Promise<void> {
  const seen: http.IncomingMessage[] = [];
  const server = http.createServer((req, res) => {
    seen.push(req);
    handler(req, res);
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address() as AddressInfo;
  try {
    await fn(port, seen);
  } finally {
    server.closeAllConnections?.();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
}

const v4 = (address: string): LookupAddr => ({ address, family: 4 });
const v6 = (address: string): LookupAddr => ({ address, family: 6 });
/** Test policy: 127.0.0.1 plays the role of a public address; everything else uses the real policy. */
const testPolicy = (a: string) => a === '127.0.0.1' || !isBlockedAddress(a);
const jwksBody = JSON.stringify(fixtures.jwks);

describe('isBlockedAddress: complete IPv4 and IPv6 special-use ranges', () => {
  const blocked = [
    // IPv6 link-local fe80::/10, all of it
    'fe80::1', 'fe90::1', 'fea0::1', 'febf::1', 'febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff', 'fe80::1%eth0',
    // unique local fc00::/7, site-local, multicast, loopback, unspecified
    'fc00::1', 'fd12:3456::1', 'fec0::1', 'ff02::1', 'ff0e::1', '::1', '::',
    // IPv4-mapped, IPv4-compatible, IPv4-translated, NAT64, 6to4, Teredo
    '::ffff:127.0.0.1', '::ffff:7f00:1', '::ffff:169.254.169.254', '::ffff:a9fe:a9fe', '::ffff:10.0.0.1',
    '::ffff:8.8.8.8', '::127.0.0.1', '::ffff:0:7f00:1', '64:ff9b::7f00:1', '64:ff9b::808:808', '64:ff9b:1::1',
    '2002:7f00:1::1', '2001::1', '2001:0:4136:e378::1',
    // documentation, discard, benchmarking, SRv6, outside global unicast
    '2001:db8::1', '3fff::1', '100::1', '2001:2::1', '5f00::1', 'fe7f::1', '4000::1', 'e000::1',
    // IPv4: this network, private, loopback, link-local and metadata, CGNAT
    '0.0.0.0', '0.1.2.3', '10.0.0.1', '10.255.255.255', '127.0.0.1', '127.255.255.254',
    '169.254.169.254', '169.254.0.1', '169.254.255.255', '172.16.0.1', '172.31.255.255', '192.168.1.1',
    '100.64.0.1', '100.127.255.255',
    // IPv4: documentation, benchmarking, IETF, 6to4 relay, multicast, reserved, broadcast
    '192.0.2.1', '198.51.100.1', '203.0.113.1', '198.18.0.1', '198.19.255.255', '192.0.0.1', '192.88.99.1',
    '224.0.0.1', '239.255.255.255', '240.0.0.1', '255.255.255.255',
    // not an IP at all
    'not-an-ip', '', '0177.0.0.1', '2130706433', '0x7f000001',
  ];
  for (const address of blocked) {
    it(`blocks ${address || '(empty)'}`, () => assert.equal(isBlockedAddress(address), true));
  }
  const allowed = [
    '93.184.216.34', '8.8.8.8', '1.1.1.1', '100.63.255.255', '100.128.0.1', '172.15.255.255', '172.32.0.1',
    '169.253.255.255', '169.255.0.1', '11.0.0.1', '2606:4700:4700::1111', '2a00:1450:4001:80b::200e', '2001:4860:4860::8888',
  ];
  for (const address of allowed) {
    it(`allows public ${address}`, () => assert.equal(isBlockedAddress(address), false));
  }
});

describe('fetchJwks: URL and literal-address protections (no network)', () => {
  const refused = [
    ['http://keys.example.test/jwks.json', /must use HTTPS/],
    ['https://user:pw@keys.example.test/jwks.json', /credentials/],
    ['https://localhost/jwks.json', /private or loopback/],
    ['https://jwks.localhost/jwks.json', /private or loopback/],
    ['https://[fe90::1]/jwks.json', /private or loopback/],
    ['https://[febf::1]/jwks.json', /private or loopback/],
    ['https://[fe80::1]/jwks.json', /private or loopback/],
    ['https://[::ffff:127.0.0.1]/jwks.json', /private or loopback/],
    ['https://[::ffff:169.254.169.254]/jwks.json', /private or loopback/],
    ['https://[::ffff:a9fe:a9fe]/jwks.json', /private or loopback/],
    ['https://[::127.0.0.1]/jwks.json', /private or loopback/],
    ['https://[64:ff9b::a9fe:a9fe]/jwks.json', /private or loopback/],
    ['https://[::1]/jwks.json', /private or loopback/],
    ['https://169.254.169.254/latest/meta-data/', /private or loopback/],
    // Decimal, hexadecimal, octal and shortened IPv4 forms (normalized by the URL parser)
    ['https://2130706433/jwks.json', /private or loopback/],
    ['https://0x7f000001/jwks.json', /private or loopback/],
    ['https://0177.0.0.1/jwks.json', /private or loopback/],
    ['https://0x7f.0.0.1/jwks.json', /private or loopback/],
    ['https://127.1/jwks.json', /private or loopback/],
    ['https://2852039166/jwks.json', /private or loopback/], // 169.254.169.254
    ['https://0xa9fea9fe/jwks.json', /private or loopback/], // 169.254.169.254
    ['https://0251.0376.0251.0376/jwks.json', /private or loopback/], // 169.254.169.254
    ['https://10.0.0.5/jwks.json', /private or loopback/],
    ['https://100.64.0.1/jwks.json', /private or loopback/],
    ['https://0.0.0.0/jwks.json', /private or loopback/],
  ] as const;
  for (const [url, err] of refused) {
    it(`refuses ${url}`, async () => {
      await assert.rejects(() => fetchJwks(url), err);
      await assert.rejects(() => fetchJwkForPassport(url, 'ed25519:k:s'), err);
      await assert.rejects(() => fetchPublicKeyFromJwks(url, 'k'), err);
    });
  }
});

describe('fetchJwks: DNS answers are checked and the connection is pinned', () => {
  for (const answer of [
    [v4('169.254.169.254')], [v4('10.0.0.1')], [v4('127.0.0.1')], [v4('100.64.1.1')], [v4('0.0.0.0')],
    [v6('fe90::1')], [v6('febf::1')], [v6('::ffff:127.0.0.1')], [v6('::ffff:169.254.169.254')], [v6('fd00::1')],
    [v4('93.184.216.34'), v4('10.0.0.1')], // one private address among public ones
    [],
  ]) {
    it(`refuses a hostname resolving to ${answer.map((a) => a.address).join(', ') || 'nothing'}`, async () => {
      const { lookup, calls } = fakeLookup([answer]);
      await assert.rejects(
        () => fetchJwksWith('https://jwks.example.test/jwks.json', { lookup }),
        answer.length ? /resolved to private or loopback/ : /did not resolve/,
      );
      assert.equal(calls.length, 1);
    });
  }

  it('DNS rebinding: resolves once and connects to the pinned address even if DNS changes', async () => {
    // First answer is "public" (127.0.0.1 under the test policy), every later answer is private.
    const { lookup, calls } = fakeLookup([[v4('127.0.0.1')], [v4('10.0.0.1')], [v4('169.254.169.254')]]);
    await withServer((_req, res) => res.end(jwksBody), async (port, seen) => {
      const res = await safeGet(`http://jwks.rebind.test:${port}/jwks.json`, { lookup, isAllowedAddress: testPolicy, allowHttp: true });
      assert.equal(res.status, 200);
      assert.equal(res.remoteAddress, '127.0.0.1');
      assert.equal(calls.length, 1, 'the hostname must be resolved exactly once');
      assert.equal(seen.length, 1);
      assert.equal(seen[0].headers.host, `jwks.rebind.test:${port}`);
      // A new request resolves again, and that answer is checked too: it is now private.
      await assert.rejects(
        () => fetchJwksWith(`http://jwks.rebind.test:${port}/jwks.json`, { lookup, isAllowedAddress: testPolicy, allowHttp: true }),
        /resolved to private or loopback address: 10\.0\.0\.1/,
      );
      assert.equal(seen.length, 1);
      // Through the JWKS helper with a fresh rebinding resolver: one resolution, pinned.
      const fresh = fakeLookup([[v4('127.0.0.1')], [v4('169.254.169.254')]]);
      const jwks = await fetchJwksWith(`http://jwks.rebind.test:${port}/jwks.json`, { lookup: fresh.lookup, isAllowedAddress: testPolicy, allowHttp: true });
      assert.equal(jwks.keys.length, 2);
      assert.equal(fresh.calls.length, 1);
      assert.equal(seen.length, 2);
    });
  });

  it('fetches, validates and selects the key by kid', async () => {
    const { lookup } = fakeLookup([[v4('127.0.0.1')]]);
    await withServer((_req, res) => res.end(jwksBody), async (port) => {
      const jwks = await fetchJwksWith(`http://jwks.test:${port}/jwks.json`, { lookup, isAllowedAddress: testPolicy, allowHttp: true });
      const old = fixtures.cases.find((c) => c.kid === 'fixture-2026-a')!;
      const key = selectJwkForSignature(jwks, old.passport);
      assert.equal(key.kid, 'fixture-2026-a');
      const result = verifyPassport(old.passport, key, { expectedIssuer: 'agentsigna', nowMs: verifyAt(old.passport) });
      assert.equal(result.mayProceed, true, result.errors.join('; '));
    });
  });

  it('refuses redirects', async () => {
    const { lookup } = fakeLookup([[v4('127.0.0.1')]]);
    await withServer((_req, res) => {
      res.writeHead(302, { location: 'http://169.254.169.254/latest/meta-data/' });
      res.end();
    }, async (port, seen) => {
      await assert.rejects(
        () => fetchJwksWith(`http://jwks.test:${port}/jwks.json`, { lookup, isAllowedAddress: testPolicy, allowHttp: true }),
        /redirected \(HTTP 302\); redirects are not followed/,
      );
      assert.equal(seen.length, 1);
    });
  });

  it('refuses oversized responses (declared and streamed) and HTTP errors', async () => {
    const { lookup } = fakeLookup([[v4('127.0.0.1')]]);
    const opts = { lookup, isAllowedAddress: testPolicy, allowHttp: true };
    const big = JSON.stringify({ keys: fixtures.jwks.keys, pad: 'x'.repeat(JWKS_MAX_BYTES) });
    await withServer((req, res) => {
      if (req.url === '/declared') res.end(big);
      else if (req.url === '/streamed') {
        res.writeHead(200, { 'content-type': 'application/json' });
        for (let i = 0; i < 20; i++) res.write('x'.repeat(8 * 1024));
        res.end();
      } else if (req.url === '/notfound') {
        res.writeHead(404);
        res.end('not found');
      } else if (req.url === '/notjson') res.end('<html>');
      else res.end(JSON.stringify({ keys: [] }));
    }, async (port) => {
      await assert.rejects(() => fetchJwksWith(`http://j.test:${port}/declared`, opts), /larger than 65536 bytes/);
      await assert.rejects(() => fetchJwksWith(`http://j.test:${port}/streamed`, opts), /larger than 65536 bytes/);
      await assert.rejects(() => fetchJwksWith(`http://j.test:${port}/notfound`, opts), /HTTP 404/);
      await assert.rejects(() => fetchJwksWith(`http://j.test:${port}/notjson`, opts), /not valid JSON/);
      await assert.rejects(() => fetchJwksWith(`http://j.test:${port}/empty`, opts), /contains no keys/);
    });
  });

  it('times out', async () => {
    const { lookup } = fakeLookup([[v4('127.0.0.1')]]);
    await withServer(() => { /* never answers */ }, async (port) => {
      const started = Date.now();
      await assert.rejects(
        () => safeGet(`http://j.test:${port}/slow`, { lookup, isAllowedAddress: testPolicy, allowHttp: true, timeoutMs: 300 }),
        /timed out/,
      );
      assert.ok(Date.now() - started < 5_000);
    });
  });

  it('refuses ambiguous key sets: duplicate kids', async () => {
    const { lookup } = fakeLookup([[v4('127.0.0.1')]]);
    const [b, a] = fixtures.jwks.keys;
    await withServer((_req, res) => res.end(JSON.stringify({ keys: [a, { ...b, kid: a.kid }] })), async (port) => {
      await assert.rejects(
        () => fetchJwksWith(`http://j.test:${port}/jwks.json`, { lookup, isAllowedAddress: testPolicy, allowHttp: true }),
        /more than one key with kid "fixture-2026-a"/,
      );
    });
  });
});

describe('JWKS validation and key selection', () => {
  const [b, a] = fixtures.jwks.keys;
  const sigA = fixtures.cases.find((c) => c.kid === 'fixture-2026-a')!.passport.signature;

  it('rejects duplicate kids, keys without kid, private material and malformed sets', () => {
    assert.throws(() => assertValidJwks({ keys: [a, { ...b, kid: a.kid }] }), /more than one key with kid/);
    assert.throws(() => selectJwkForSignature({ keys: [a, { ...a }] }, sigA), /more than one key with kid/);
    const { kid: _kid, ...noKid } = b;
    assert.throws(() => assertValidJwks({ keys: [a, noKid as JWK] }), /without a valid "kid"/);
    assert.throws(() => assertValidJwks({ keys: [{ ...a, d: 'secret' } as JWK] }), /private or symmetric key material/);
    assert.throws(() => assertValidJwks({ keys: [{ kty: 'oct', kid: 'h', k: 'c2VjcmV0' } as JWK] }), /private or symmetric/);
    assert.throws(() => assertValidJwks({ keys: [] }), /contains no keys/);
    assert.throws(() => assertValidJwks({}), /"keys" array/);
    assert.throws(() => assertValidJwks({ keys: [null] }), /not an object/);
    assert.doesNotThrow(() => assertValidJwks(fixtures.jwks));
  });

  it('rejects a key with the right kid that is not usable for EdDSA', () => {
    assert.throws(() => selectJwkForSignature({ keys: [{ kty: 'RSA', kid: 'k1' }] }, 'ed25519:k1:abc'), /No Ed25519 key with kid "k1"/);
    assert.throws(() => selectJwkForSignature({ keys: [{ ...a, crv: 'X25519' }] }, sigA), /not an Ed25519 key/);
    assert.throws(() => selectJwkForSignature({ keys: [{ ...a, use: 'enc' }] }, sigA), /"use" "enc"/);
    assert.throws(() => selectJwkForSignature({ keys: [{ ...a, alg: 'RS256' }] }, sigA), /"alg" "RS256"/);
    assert.throws(() => selectJwkForSignature({ keys: [{ ...a, x: 'short' }] }, sigA), /valid 32-byte "x"/);
    assert.throws(() => selectJwkForSignature({ keys: [{ ...a, key_ops: ['encrypt'] } as JWK] }, sigA), /key_ops/);
    // use and alg may be absent; "Ed25519" is accepted as the fully-specified alg name.
    const { use: _u, alg: _a, ...bare } = a;
    assert.equal(selectJwkForSignature({ keys: [bare as JWK] }, sigA).kid, a.kid);
    assert.equal(selectJwkForSignature({ keys: [{ ...a, alg: 'Ed25519' }] }, sigA).kid, a.kid);
  });

  it('requires a kid in the signature when selecting by kid', () => {
    assert.throws(() => selectJwkForSignature(fixtures.jwks, 'ed25519::abc'), /ed25519:<kid>:<signature>/);
    assert.throws(() => selectJwkForSignature(fixtures.jwks, 'ed25519:abc'), /ed25519:<kid>:<signature>/);
  });

  it('verifyPassport refuses a JWK whose use or alg does not match EdDSA', () => {
    const c = fixtures.cases[0];
    const key = fixtures.jwks.keys.find((k) => k.kid === c.kid)!;
    for (const bad of [{ ...key, use: 'enc' }, { ...key, alg: 'ES256' }, { ...key, kty: 'EC', crv: 'P-256' }]) {
      const result = verifyPassport(c.passport, bad, { expectedIssuer: 'agentsigna', nowMs: verifyAt(c.passport) });
      assert.equal(result.mayProceed, false);
      assert.equal(result.signatureValid, false);
      assert.ok(result.errors.some((e) => e.startsWith('Failed to load public key')));
    }
  });
});

// Fail-closed authorization contract

describe('verification result contract', () => {
  const opts = { expectedIssuer: 'agentsigna' };

  it('a valid ALLOW passport: every check passes, unchecked expectations are null', () => {
    const result = verifyPassport(makePassport(makePayload()), publicKey, opts);
    assert.deepEqual(
      {
        valid: result.valid, mayProceed: result.mayProceed, signatureValid: result.signatureValid,
        claimsValid: result.claimsValid, decisionAuthorizes: result.decisionAuthorizes, notExpired: result.notExpired,
        actionMatches: result.actionMatches, audienceMatches: result.audienceMatches, environmentMatches: result.environmentMatches,
      },
      {
        valid: true, mayProceed: true, signatureValid: true, claimsValid: true, decisionAuthorizes: true,
        notExpired: true, actionMatches: null, audienceMatches: null, environmentMatches: null,
      },
    );
    assert.deepEqual(result.errors, []);
  });

  for (const decision of ['DENY', 'REQUIRE_APPROVAL', 'SOMETHING_ELSE', undefined] as const) {
    it(`a correctly signed ${String(decision)} passport never authorizes`, () => {
      const payload = makePayload({ decision: decision as PassportPayload['decision'] });
      const result = verifyPassport(makePassport(payload), publicKey, opts);
      assert.equal(result.signatureValid, true);
      assert.equal(result.claimsValid, true);
      assert.equal(result.decisionAuthorizes, false);
      assert.equal(result.mayProceed, false);
      assert.equal(result.valid, false);
      assert.ok(result.errors.some((e) => e.includes(`decision "${String(decision)}" does not authorize`)));
    });
  }

  it('ALLOW and ALLOW_WITH_CONDITIONS authorize', () => {
    for (const decision of ['ALLOW', 'ALLOW_WITH_CONDITIONS'] as const) {
      const result = verifyPassport(makePassport(makePayload({ decision })), publicKey, opts);
      assert.equal(result.decisionAuthorizes, true);
      assert.equal(result.mayProceed, true, result.errors.join('; '));
      assert.equal(result.warnings.length, 0);
    }
  });

  for (const [field, value, message] of [
    ['spec', 'agentsigna-passport-v2', /Unknown spec identifier "agentsigna-passport-v2"/],
    ['spec', undefined, /Unknown spec identifier "undefined"/],
    ['specVersion', '2.0', /Unsupported passport format version "2.0"/],
    ['specVersion', '0.9', /Unsupported passport format version "0.9"/],
    ['specVersion', '10.0', /Unsupported passport format version "10.0"/],
    ['specVersion', '2', /not a valid format version/],
    ['specVersion', 'latest', /not a valid format version/],
    ['specVersion', undefined, /not a valid format version/],
  ] as const) {
    it(`fails closed for ${field} ${String(value)}`, () => {
      const payload = { ...makePayload(), [field]: value } as unknown as PassportPayload;
      const result = verifyPassport(makePassport(payload), publicKey, opts);
      assert.equal(result.signatureValid, true);
      assert.equal(result.claimsValid, false);
      assert.equal(result.mayProceed, false);
      assert.equal(result.valid, false);
      assert.ok(result.errors.some((e) => message.test(e)), result.errors.join('; '));
    });
  }

  it('an unknown minor version of format 1 is a warning only', () => {
    const payload = { ...makePayload(), specVersion: '1.1' } as unknown as PassportPayload;
    const result = verifyPassport(makePassport(payload), publicKey, opts);
    assert.equal(result.mayProceed, true, result.errors.join('; '));
    assert.ok(result.warnings.some((w) => w.includes('"1.1"')));
  });

  it('expiry, revocation, issuer and signature each block mayProceed and set their field', () => {
    const expired = verifyPassport(makePassport(makePayload({ expiresAt: new Date(Date.now() - 1000).toISOString() })), publicKey, opts);
    assert.equal(expired.notExpired, false);
    assert.equal(expired.signatureValid, true);
    assert.equal(expired.mayProceed, false);

    const revoked = verifyPassport({ ...makePassport(makePayload()), status: 'REVOKED' }, publicKey, opts);
    assert.equal(revoked.claimsValid, false);
    assert.equal(revoked.mayProceed, false);

    const issuer = verifyPassport(makePassport(makePayload()), publicKey, { expectedIssuer: 'someone-else' });
    assert.equal(issuer.claimsValid, false);
    assert.equal(issuer.mayProceed, false);

    const tampered = makePassport(makePayload());
    (tampered.payload as PassportPayload).amount = 1;
    const sig = verifyPassport(tampered, publicKey, opts);
    assert.equal(sig.signatureValid, false);
    assert.equal(sig.claimsValid, true);
    assert.equal(sig.mayProceed, false);

    const nothing = verifyPassport(null as unknown as Passport, publicKey, opts);
    assert.equal(nothing.mayProceed, false);
    assert.equal(nothing.signatureValid, false);
    assert.equal(nothing.actionMatches, null);
  });

  it('action expectations: true when supplied and matching, false on mismatch, null when not supplied', () => {
    const actionPayload = { orderId: 'PO-1', amount: 5000 };
    const hash = createHash('sha256').update(stableStringify(actionPayload)).digest('hex');
    const passport = makePassport(makePayload({ actionHash: hash, actionType: 'PURCHASE_ORDER' }));

    const ok = verifyPassport(passport, publicKey, { ...opts, actionPayload, expectedActionType: 'PURCHASE_ORDER' });
    assert.equal(ok.actionMatches, true);
    assert.equal(ok.mayProceed, true, ok.errors.join('; '));

    const wrongPayload = verifyPassport(passport, publicKey, { ...opts, actionPayload: { orderId: 'PO-2' } });
    assert.equal(wrongPayload.actionMatches, false);
    assert.equal(wrongPayload.mayProceed, false);

    const wrongType = verifyPassport(passport, publicKey, { ...opts, actionPayload, expectedActionType: 'PAYMENT' });
    assert.equal(wrongType.actionMatches, false);
    assert.equal(wrongType.mayProceed, false);
    assert.ok(wrongType.errors.some((e) => e.includes('Action type mismatch')));

    const none = verifyPassport(passport, publicKey, opts);
    assert.equal(none.actionMatches, null);
    assert.equal(none.mayProceed, true);
  });

  it('audience and environment expectations fail closed with format 1.0 (no such claims)', () => {
    const passport = makePassport(makePayload());
    const aud = verifyPassport(passport, publicKey, { ...opts, expectedAudience: 'erp.example.com' });
    assert.equal(aud.audienceMatches, false);
    assert.equal(aud.environmentMatches, null);
    assert.equal(aud.mayProceed, false);
    assert.ok(aud.errors.some((e) => e.includes('no audience claim')));

    const env = verifyPassport(passport, publicKey, { ...opts, expectedEnvironment: 'production' });
    assert.equal(env.environmentMatches, false);
    assert.equal(env.mayProceed, false);

    // An unsigned field added to the payload cannot satisfy the expectation either.
    const sneaky = makePassport({ ...makePayload(), audience: 'erp.example.com' } as unknown as PassportPayload);
    assert.equal(verifyPassport(sneaky, publicKey, { ...opts, expectedAudience: 'erp.example.com' }).mayProceed, false);
  });

  it('the README integration gate refuses every negative semantic case', () => {
    // Mirrors the README example: execution is gated on result.mayProceed only.
    const gate = (passport: Passport) => {
      const result = verifyPassport(passport, publicKey, { expectedIssuer: 'agentsigna' });
      if (!result.mayProceed) throw new Error(result.errors.join('; '));
      return 'executed';
    };
    assert.equal(gate(makePassport(makePayload())), 'executed');
    for (const payload of [
      makePayload({ decision: 'DENY' }),
      makePayload({ decision: 'REQUIRE_APPROVAL' }),
      { ...makePayload(), spec: 'other' } as unknown as PassportPayload,
      { ...makePayload(), specVersion: '2.0' } as unknown as PassportPayload,
    ]) {
      assert.throws(() => gate(makePassport(payload)));
    }
  });
});
