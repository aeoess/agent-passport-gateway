// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// URL Safety — SSRF Guard for Tenant-Supplied URLs
// ══════════════════════════════════════════════════════════════════
// Security triage 2026-04-11 fix 4.
//
// The policy evaluation path fetches agent.entity_verification_endpoint,
// which is a tenant-supplied URL. Before this module existed, the
// gateway would happily fetch any URL a tenant registered at agent
// creation time, including internal IPs, localhost, cloud metadata
// services (169.254.169.254), and loopback addresses. The 3-second
// timeout limited the dwell but did not prevent the request.
//
// This module provides a read-only validator that rejects the common
// SSRF vectors. It is used at TWO points:
//
//   1. At agent registration time (POST /api/v1/agents). If the
//      caller provides an entity_verification_endpoint that fails
//      validation, the registration is rejected with 400.
//
//   2. At policy evaluation time (defense in depth). If the stored
//      URL somehow got past registration or was written before this
//      guard existed, the fetch is skipped and the entity binding
//      check falls through.
//
// Known limitation: this validator blocks LITERAL private IPs and
// known-bad hostnames. It does NOT protect against DNS rebinding
// (a hostname that resolves to a public IP at validation time and
// to a private IP at fetch time). Full SSRF protection requires
// resolving DNS at validation time and passing the resolved IP to
// fetch, which changes the HTTP host header semantics. Flagged as
// a follow-up in the security triage report; the current guard
// closes the obvious holes.
//
// Reference: CODE-AUDIT-2026-04-11.md §2.10.
// ══════════════════════════════════════════════════════════════════

export interface UrlSafetyResult {
  safe: boolean
  reason?: string
}

/** Hostnames that are always rejected regardless of resolution. */
const BLOCKED_HOSTNAMES = new Set([
  'localhost',
  'localhost.localdomain',
  'ip6-localhost',
  'ip6-loopback',
  // Cloud instance metadata services
  'metadata.google.internal',
  'metadata.internal',
  'metadata',
  'instance-data',
  'instance-data.ec2.internal',
])

/** Literal IPv4 metadata service addresses. */
const BLOCKED_IPV4_LITERALS = new Set([
  '169.254.169.254', // AWS, GCP, Azure, DigitalOcean, Alibaba
  '100.100.100.200', // Alibaba Cloud
  '192.0.0.192',     // Oracle Cloud
])

/** Check whether an IPv4 literal falls in a private or loopback range. */
function isPrivateIPv4(host: string): boolean {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(host)
  if (!m) return false
  const [a, b] = [parseInt(m[1], 10), parseInt(m[2], 10)]
  // Any invalid octet → reject (defensive; the regex also catches most cases)
  if ([m[1], m[2], m[3], m[4]].some(o => parseInt(o, 10) > 255)) return true
  // 10.0.0.0/8
  if (a === 10) return true
  // 172.16.0.0/12
  if (a === 172 && b >= 16 && b <= 31) return true
  // 192.168.0.0/16
  if (a === 192 && b === 168) return true
  // 127.0.0.0/8 loopback
  if (a === 127) return true
  // 0.0.0.0/8 and 255.255.255.255 are also unsafe
  if (a === 0) return true
  if (host === '255.255.255.255') return true
  // Link-local 169.254.0.0/16 (includes metadata services; belt + braces)
  if (a === 169 && b === 254) return true
  return false
}

/** Check whether an IPv6 literal (bracketed or bare) falls in a private,
 *  loopback, link-local, or unique-local range. Conservative: any IPv6
 *  that looks loopback/link-local/ULA is rejected. */
function isPrivateIPv6(host: string): boolean {
  // Strip brackets for comparison
  const h = host.replace(/^\[|\]$/g, '').toLowerCase()
  if (h === '::1') return true
  if (h === '::') return true
  // fe80::/10 link-local
  if (h.startsWith('fe80:') || h.startsWith('fe8') || h.startsWith('fe9') ||
      h.startsWith('fea') || h.startsWith('feb')) return true
  // fc00::/7 unique-local (fc00:/ and fd00:/)
  if (h.startsWith('fc') || h.startsWith('fd')) return true
  // ::ffff:10.0.0.1 style IPv4-mapped (dotted-quad form)
  const mappedDotted = /^::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/.exec(h)
  if (mappedDotted) return isPrivateIPv4(mappedDotted[1])
  // ::ffff:HHHH:HHHH hex form (WHATWG URL normalizes the dotted-quad
  // IPv4-mapped form to this). Parse the last two hex groups as four
  // bytes and check against the private IPv4 ranges.
  const mappedHex = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(h)
  if (mappedHex) {
    const hi = parseInt(mappedHex[1], 16)
    const lo = parseInt(mappedHex[2], 16)
    if (!Number.isFinite(hi) || !Number.isFinite(lo)) return true // defensive: reject
    const a = (hi >> 8) & 0xff
    const b = hi & 0xff
    const c = (lo >> 8) & 0xff
    const d = lo & 0xff
    return isPrivateIPv4(`${a}.${b}.${c}.${d}`)
  }
  return false
}

/**
 * Validate a tenant-supplied URL for SSRF safety.
 *
 * Rules:
 *   - Must parse as a valid URL via the WHATWG URL constructor.
 *   - Must use the `https:` scheme. (http: is a hard-reject to keep the
 *     rule simple and to discourage plaintext auth headers.)
 *   - Hostname must not be on the explicit deny list (localhost and
 *     known metadata service hostnames).
 *   - IPv4 literal hostname must not be in a private/loopback/link-local
 *     range, and must not be a known metadata service address.
 *   - IPv6 literal hostname must not be loopback, link-local, ULA, or
 *     an IPv4-mapped form of a private address.
 *
 * NOT enforced: DNS rebinding protection (see module-level note).
 *
 * @param raw  The URL string as supplied by the tenant.
 * @returns    { safe: true } or { safe: false, reason }.
 */
export function validateExternalUrl(raw: unknown): UrlSafetyResult {
  if (typeof raw !== 'string' || raw.trim() === '') {
    return { safe: false, reason: 'URL is empty or not a string' }
  }
  let url: URL
  try {
    url = new URL(raw)
  } catch {
    return { safe: false, reason: 'URL is not parseable' }
  }
  if (url.protocol !== 'https:') {
    return { safe: false, reason: `Scheme "${url.protocol}" is not allowed; use https://` }
  }
  const hostname = url.hostname.toLowerCase()
  if (!hostname) {
    return { safe: false, reason: 'URL has no hostname' }
  }
  if (BLOCKED_HOSTNAMES.has(hostname)) {
    return { safe: false, reason: `Hostname "${hostname}" is blocked (localhost or metadata service)` }
  }
  if (BLOCKED_IPV4_LITERALS.has(hostname)) {
    return { safe: false, reason: `IPv4 literal "${hostname}" is a cloud metadata service address` }
  }
  if (isPrivateIPv4(hostname)) {
    return { safe: false, reason: `IPv4 literal "${hostname}" is in a private, loopback, or link-local range` }
  }
  if (hostname.includes(':') || hostname.startsWith('[')) {
    if (isPrivateIPv6(hostname)) {
      return { safe: false, reason: `IPv6 literal "${hostname}" is in a private, loopback, link-local, or unique-local range` }
    }
  }
  return { safe: true }
}
