/**
 * Outbound HTTPS for JWKS retrieval, ported from AgentSigna's hardened server-side client.
 *
 * - The hostname is resolved once. Every resolved address must be public; the request then
 *   connects to the first of them through a lookup function that returns only that pinned
 *   address, so a second DNS answer (DNS rebinding) can never change the target.
 * - IP literals are checked directly (the WHATWG URL parser has already normalized decimal,
 *   hexadecimal, octal and shortened IPv4 forms to dotted quads).
 * - Redirects are refused, the body is capped, and the whole exchange has a deadline.
 *
 * Internal module: not part of the package's public API.
 */

import * as dns from 'node:dns';
import * as http from 'node:http';
import * as https from 'node:https';
import { isIP } from 'node:net';

export type OutboundErrorCode =
  | 'INVALID_URL'
  | 'BLOCKED_ADDRESS'
  | 'DNS'
  | 'REDIRECT'
  | 'HTTP_STATUS'
  | 'TOO_LARGE'
  | 'TIMEOUT'
  | 'NETWORK';

export class OutboundRequestError extends Error {
  constructor(message: string, readonly code: OutboundErrorCode) {
    super(message);
    this.name = 'OutboundRequestError';
  }
}

// Address ranges

type Range = { bytes: number[]; bits: number };

function parseIpv4(address: string): number[] | null {
  if (isIP(address) !== 4) return null;
  return address.split('.').map((p) => Number(p));
}

/** 16 bytes of an IPv6 address (zone id removed), or null. */
function parseIpv6(address: string): number[] | null {
  const ip = address.split('%')[0];
  if (isIP(ip) !== 6) return null;
  let head = ip;
  let tailV4: number[] = [];
  const lastColon = ip.lastIndexOf(':');
  if (ip.slice(lastColon + 1).includes('.')) {
    const v4 = parseIpv4(ip.slice(lastColon + 1));
    if (!v4) return null;
    tailV4 = v4;
    head = ip.slice(0, lastColon + 1) + '0:0';
  }
  const [left, right] = head.includes('::') ? head.split('::') : [head, null];
  const l = left ? left.split(':') : [];
  const r = right ? right.split(':') : [];
  const missing = 8 - l.length - r.length;
  if (right === null ? l.length !== 8 : missing < 1) return null;
  const groups = [...l, ...Array(right === null ? 0 : missing).fill('0'), ...r].map((g) => parseInt(g, 16));
  const bytes: number[] = [];
  for (const g of groups) bytes.push((g >> 8) & 0xff, g & 0xff);
  if (tailV4.length) bytes.splice(12, 4, ...tailV4);
  return bytes;
}

function range(cidr: string): Range {
  const [net, bits] = cidr.split('/');
  const bytes = net.includes(':') ? parseIpv6(net) : parseIpv4(net);
  if (!bytes) throw new Error(`bad range ${cidr}`);
  return { bytes, bits: Number(bits) };
}

function inRange(bytes: number[], r: Range): boolean {
  if (bytes.length !== r.bytes.length) return false;
  let bits = r.bits;
  for (let i = 0; bits > 0; i++, bits -= 8) {
    const mask = bits >= 8 ? 0xff : (0xff << (8 - bits)) & 0xff;
    if ((bytes[i] & mask) !== (r.bytes[i] & mask)) return false;
  }
  return true;
}

/** IPv4 special-use ranges (RFC 6890 and successors) that a JWKS fetch never contacts. */
export const BLOCKED_IPV4 = [
  '0.0.0.0/8', // "this network", including 0.0.0.0
  '10.0.0.0/8', // private
  '100.64.0.0/10', // carrier-grade NAT
  '127.0.0.0/8', // loopback
  '169.254.0.0/16', // link-local, including cloud metadata 169.254.169.254
  '172.16.0.0/12', // private
  '192.0.0.0/24', // IETF protocol assignments
  '192.0.2.0/24', // documentation (TEST-NET-1)
  '192.31.196.0/24', // AS112
  '192.52.193.0/24', // AMT
  '192.88.99.0/24', // 6to4 relay anycast
  '192.168.0.0/16', // private
  '192.175.48.0/24', // AS112 direct delegation
  '198.18.0.0/15', // benchmarking
  '198.51.100.0/24', // documentation (TEST-NET-2)
  '203.0.113.0/24', // documentation (TEST-NET-3)
  '224.0.0.0/4', // multicast
  '240.0.0.0/4', // reserved, including broadcast 255.255.255.255
].map(range);

/**
 * IPv6 special-use ranges. Every form that embeds or translates an IPv4 address
 * (IPv4-mapped, IPv4-compatible, IPv4-translated, NAT64, 6to4, Teredo) is blocked outright:
 * a public JWKS host has no reason to publish such an address.
 */
export const BLOCKED_IPV6 = [
  '::/96', // unspecified ::, loopback ::1 and IPv4-compatible ::a.b.c.d
  '::ffff:0:0/96', // IPv4-mapped
  '::ffff:0:0:0/96', // IPv4-translated (RFC 2765)
  '64:ff9b::/96', // NAT64 well-known prefix
  '64:ff9b:1::/48', // NAT64 local-use
  '100::/64', // discard-only
  '2001::/23', // IETF protocol assignments, including Teredo 2001::/32, benchmarking, ORCHID
  '2001:db8::/32', // documentation
  '2002::/16', // 6to4
  '3fff::/20', // documentation (RFC 9637)
  '5f00::/16', // SRv6 SIDs
  'fc00::/7', // unique local
  'fe80::/10', // link-local (fe80:: to febf::)
  'fec0::/10', // site-local (deprecated)
  'ff00::/8', // multicast
].map(range);

const GLOBAL_UNICAST_V6 = range('2000::/3');

/** True when an address must never be contacted. Anything that is not a valid IP is blocked. */
export function isBlockedAddress(address: string): boolean {
  const ip = String(address).replace(/^\[|\]$/g, '').toLowerCase();
  const v4 = parseIpv4(ip);
  if (v4) return BLOCKED_IPV4.some((r) => inRange(v4, r));
  const v6 = parseIpv6(ip);
  // Only global unicast (2000::/3) is ever contacted, minus the special-use ranges inside it.
  if (v6) return !inRange(v6, GLOBAL_UNICAST_V6) || BLOCKED_IPV6.some((r) => inRange(v6, r));
  return true;
}

/** True for localhost names and blocked IP literals. Other names need resolution. */
export function isBlockedHostname(hostname: string): boolean {
  const host = hostname.replace(/^\[|\]$/g, '').toLowerCase().replace(/\.$/, '');
  if (host === 'localhost' || host.endsWith('.localhost')) return true;
  return isIP(host.split('%')[0]) ? isBlockedAddress(host) : false;
}

// Request

type LookupAll = (
  hostname: string,
  options: dns.LookupAllOptions,
  callback: (err: NodeJS.ErrnoException | null, addresses: dns.LookupAddress[]) => void,
) => void;

export interface SafeGetOptions {
  timeoutMs?: number;
  maxBytes?: number;
  headers?: Record<string, string>;
  /** Test hooks. */
  lookup?: LookupAll;
  isAllowedAddress?: (address: string) => boolean;
  allowHttp?: boolean;
}

export interface SafeResponse {
  status: number;
  body: Buffer;
  /** The address the socket actually connected to. */
  remoteAddress: string | undefined;
}

const defaultLookup: LookupAll = (hostname, options, callback) => dns.lookup(hostname, options, callback);

function resolveOnce(hostname: string, lookupAll: LookupAll): Promise<dns.LookupAddress[]> {
  return new Promise((resolve, reject) => {
    lookupAll(hostname, { all: true, verbatim: true }, (err, addresses) => {
      if (err) reject(new OutboundRequestError(`Hostname did not resolve: ${hostname}`, 'DNS'));
      else resolve(Array.isArray(addresses) ? addresses : []);
    });
  });
}

/**
 * GET over HTTPS to a public address only, with the address pinned at connection time.
 */
export async function safeGet(rawUrl: string, options: SafeGetOptions = {}): Promise<SafeResponse> {
  const timeoutMs = options.timeoutMs ?? 10_000;
  const maxBytes = options.maxBytes ?? 64 * 1024;
  const allowed = options.isAllowedAddress ?? ((a: string) => !isBlockedAddress(a));
  const deadline = Date.now() + timeoutMs;

  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    throw new OutboundRequestError(`Invalid JWKS URL: ${rawUrl}`, 'INVALID_URL');
  }
  if (url.protocol !== 'https:' && !(options.allowHttp && url.protocol === 'http:')) {
    throw new OutboundRequestError(`SSRF/MITM protection: JWKS URL must use HTTPS. Got: ${rawUrl}`, 'INVALID_URL');
  }
  if (url.username || url.password) {
    throw new OutboundRequestError('SSRF protection: JWKS URL must not contain credentials.', 'INVALID_URL');
  }

  const host = url.hostname.replace(/^\[|\]$/g, '');
  const lower = host.toLowerCase().replace(/\.$/, '');
  if (lower === 'localhost' || lower.endsWith('.localhost')) {
    throw new OutboundRequestError(`SSRF protection: JWKS hostname is private or loopback: ${url.hostname}`, 'BLOCKED_ADDRESS');
  }

  let pinned: { address: string; family: number };
  if (isIP(host)) {
    if (!allowed(host)) {
      throw new OutboundRequestError(`SSRF protection: JWKS hostname is private or loopback: ${url.hostname}`, 'BLOCKED_ADDRESS');
    }
    pinned = { address: host, family: isIP(host) };
  } else {
    // Resolve exactly once, with a deadline.
    const addresses = await Promise.race([
      resolveOnce(host, options.lookup ?? defaultLookup),
      new Promise<never>((_, reject) =>
        setTimeout(() => reject(new OutboundRequestError('JWKS request timed out.', 'TIMEOUT')), timeoutMs).unref(),
      ),
    ]);
    if (addresses.length === 0) throw new OutboundRequestError(`Hostname did not resolve: ${host}`, 'DNS');
    const bad = addresses.find((a) => !a || typeof a.address !== 'string' || !allowed(a.address));
    if (bad) {
      throw new OutboundRequestError(
        `SSRF protection: JWKS hostname resolved to private or loopback address: ${String(bad?.address)}`,
        'BLOCKED_ADDRESS',
      );
    }
    pinned = { address: addresses[0].address, family: isIP(addresses[0].address) };
  }

  // The socket may only use the pinned address, whatever DNS says now.
  const pinnedLookup = (_hostname: string, opts: { all?: boolean } | number | undefined, callback: (...args: unknown[]) => void) => {
    const cb = typeof opts === 'function' ? (opts as (...args: unknown[]) => void) : callback;
    if (opts && typeof opts === 'object' && opts.all) cb(null, [pinned]);
    else cb(null, pinned.address, pinned.family);
  };

  const transport = url.protocol === 'https:' ? https : http;
  const remaining = Math.max(1, deadline - Date.now());

  return new Promise<SafeResponse>((resolve, reject) => {
    let settled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const finish = (err: Error | null, value?: SafeResponse) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (err) reject(err);
      else resolve(value as SafeResponse);
    };

    const req = transport.request(
      url,
      {
        method: 'GET',
        headers: { accept: 'application/json', 'user-agent': '@agentsigna/verify', ...options.headers },
        lookup: pinnedLookup as never,
        agent: false,
        timeout: remaining,
      },
      (res) => {
        const status = res.statusCode ?? 0;
        const remoteAddress = res.socket?.remoteAddress;
        if (status >= 300 && status < 400) {
          res.resume();
          req.destroy();
          finish(new OutboundRequestError(`JWKS request was redirected (HTTP ${status}); redirects are not followed.`, 'REDIRECT'));
          return;
        }
        if (status < 200 || status >= 300) {
          res.resume();
          req.destroy();
          finish(new OutboundRequestError(`Failed to fetch JWKS from ${url.toString()}: HTTP ${status}`, 'HTTP_STATUS'));
          return;
        }
        const declared = Number(res.headers['content-length']);
        if (Number.isFinite(declared) && declared > maxBytes) {
          res.destroy();
          req.destroy();
          finish(new OutboundRequestError(`JWKS response is larger than ${maxBytes} bytes.`, 'TOO_LARGE'));
          return;
        }
        const chunks: Buffer[] = [];
        let size = 0;
        res.on('data', (chunk: Buffer) => {
          if (settled) return;
          size += chunk.length;
          if (size > maxBytes) {
            finish(new OutboundRequestError(`JWKS response is larger than ${maxBytes} bytes.`, 'TOO_LARGE'));
            res.destroy();
            req.destroy();
            return;
          }
          chunks.push(chunk);
        });
        res.on('end', () => finish(null, { status, body: Buffer.concat(chunks), remoteAddress }));
        res.on('error', (err) => finish(new OutboundRequestError(err.message, 'NETWORK')));
        res.on('aborted', () => finish(new OutboundRequestError('JWKS response was aborted.', 'NETWORK')));
      },
    );
    timer = setTimeout(() => {
      finish(new OutboundRequestError('JWKS request timed out.', 'TIMEOUT'));
      req.destroy();
    }, remaining);
    req.on('timeout', () => {
      finish(new OutboundRequestError('JWKS request timed out.', 'TIMEOUT'));
      req.destroy();
    });
    req.on('error', (err) =>
      finish(err instanceof OutboundRequestError ? err : new OutboundRequestError(err.message, 'NETWORK')),
    );
    req.end();
  });
}
