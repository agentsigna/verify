/**
 * @agentsigna/verify — test suite
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
import {
  verifyPassport,
  verifyChain,
  JtiCache,
  Passport,
  PassportPayload,
  LedgerEvent,
} from './index.js';

// ── Test key pair ─────────────────────────────────────────────────────────────

const { privateKey, publicKey } = generateKeyPairSync('ed25519');

// ── Helpers ───────────────────────────────────────────────────────────────────

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
  // Ed25519 requires null digest — createSign('ed25519') is invalid in Node.js crypto
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
    issuer: 'https://api.agentsigna.com/orgs/acme',
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

// ── verifyPassport ────────────────────────────────────────────────────────────

describe('verifyPassport', () => {
  it('accepts a valid passport', () => {
    const payload = makePayload();
    const passport = makePassport(payload);
    const result = verifyPassport(passport, publicKey, {
      expectedIssuer: 'https://api.agentsigna.com/orgs/acme',
    });
    assert.equal(result.valid, true);
    assert.equal(result.errors.length, 0);
    assert.equal(result.passport?.decision, 'ALLOW');
    assert.equal(result.passport?.issuer, 'https://api.agentsigna.com/orgs/acme');
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
    const payload = makePayload({ issuer: 'https://api.agentsigna.com/orgs/acme' });
    const passport = makePassport(payload);
    const result = verifyPassport(passport, publicKey, {
      expectedIssuer: 'https://api.agentsigna.com/orgs/other-corp',
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
      expectedIssuer: 'https://api.agentsigna.com/orgs/acme',
    });
    assert.equal(result.valid, true);
  });

  it('accepts a PEM string as the public key', () => {
    const pem = publicKey.export({ type: 'spki', format: 'pem' }) as string;
    const payload = makePayload();
    const passport = makePassport(payload);
    const result = verifyPassport(passport, pem, {
      expectedIssuer: 'https://api.agentsigna.com/orgs/acme',
    });
    assert.equal(result.valid, true);
  });

  it('rejects a passport signed with a different key', () => {
    const { privateKey: otherPrivate } = generateKeyPairSync('ed25519');
    const payload = makePayload();
    const passport = makePassport(payload, otherPrivate);
    const result = verifyPassport(passport, publicKey, {
      expectedIssuer: 'https://api.agentsigna.com/orgs/acme',
    });
    assert.equal(result.valid, false);
    assert.ok(result.errors.some((e) => e.includes('Signature verification failed')));
  });

  it('fails gracefully with a wrong key type (RSA instead of Ed25519)', () => {
    const { publicKey: rsaPublic } = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const payload = makePayload();
    const passport = makePassport(payload);
    const result = verifyPassport(passport, rsaPublic as unknown as KeyObject, {
      expectedIssuer: 'https://api.agentsigna.com/orgs/acme',
    });
    assert.equal(result.valid, false);
    // Must not throw — must produce a clean error string
    assert.ok(result.errors.some((e) =>
      e.includes('Signature verification failed') || e.includes('Failed to load')
    ));
  });

  it('includes issuer in the passport summary even when invalid', () => {
    const payload = makePayload({ issuer: 'https://api.agentsigna.com/orgs/acme' });
    const passport = { ...makePassport(payload), status: 'REVOKED' as const };
    const result = verifyPassport(passport, publicKey);
    assert.equal(result.passport?.issuer, 'https://api.agentsigna.com/orgs/acme');
  });
});

// ── verifyChain ───────────────────────────────────────────────────────────────

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

  it('accepts a single-event chain', () => {
    const events = makeChain('case-001', 1);
    const result = verifyChain(events);
    assert.equal(result.valid, true);
    assert.equal(result.checkedEvents, 1);
    assert.equal(result.genesisDigest, result.tipDigest);
  });

  it('rejects a self-referential event without hanging (DoS prevention)', () => {
    const events = makeChain('case-001', 2);
    // Make event[1].previousDigest point to itself — breaks the chain linkage,
    // exits the traversal loop, surfaces as "broken" not an infinite loop
    events[1].previousDigest = events[1].eventDigest;
    const result = verifyChain(events);
    assert.equal(result.valid, false);
    assert.ok(result.errors.some((e) => e.includes('broken') || e.includes('Cycle')));
  });

  it('rejects a multi-event cycle without hanging (DoS prevention)', () => {
    // Build three events manually so event[2]'s digest equals event[0]'s digest,
    // creating a traversal loop: event[0] → event[1] → event[2] → event[0] again
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

// ── JtiCache ──────────────────────────────────────────────────────────────────

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
