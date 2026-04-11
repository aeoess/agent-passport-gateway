// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// Security triage 2026-04-11 fix 4: SSRF guard for tenant-supplied URLs.
// The policy evaluation path fetches agent.entity_verification_endpoint,
// which was accepted without validation. This test exercises the guard
// against every category the audit flagged: private IPs, localhost,
// cloud metadata services, IPv6 loopback/link-local/ULA, non-https
// schemes, and malformed inputs.
// Reference: CODE-AUDIT-2026-04-11.md §2.10.

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { validateExternalUrl } from '../src/gateway/url-safety.js'

describe('validateExternalUrl — safe URLs', () => {
  const safeCases = [
    'https://verification.acme.example/entities/abc',
    'https://verify.moltrust.ch/entity/did:moltrust:abc',
    'https://api.getagentid.dev/v1/entities/agent-001',
    'https://example.com:443/path?query=value#fragment',
    'https://8.8.8.8/health', // public IPv4 literal
  ]
  for (const url of safeCases) {
    it(`accepts ${url}`, () => {
      const result = validateExternalUrl(url)
      assert.equal(result.safe, true, `expected safe, got: ${result.reason}`)
    })
  }
})

describe('validateExternalUrl — scheme rejection', () => {
  it('rejects http://', () => {
    const r = validateExternalUrl('http://verification.acme.example/entity')
    assert.equal(r.safe, false)
    assert.match(r.reason!, /scheme/i)
  })

  it('rejects file://', () => {
    const r = validateExternalUrl('file:///etc/passwd')
    assert.equal(r.safe, false)
  })

  it('rejects ftp://', () => {
    const r = validateExternalUrl('ftp://example.com/path')
    assert.equal(r.safe, false)
  })

  it('rejects gopher://', () => {
    const r = validateExternalUrl('gopher://example.com/1')
    assert.equal(r.safe, false)
  })

  it('rejects javascript:', () => {
    const r = validateExternalUrl('javascript:alert(1)')
    assert.equal(r.safe, false)
  })
})

describe('validateExternalUrl — private IPv4 rejection', () => {
  const privateIPv4 = [
    '10.0.0.1', '10.255.255.255',
    '172.16.0.1', '172.20.5.5', '172.31.255.255',
    '192.168.0.1', '192.168.100.100',
    '127.0.0.1', '127.1.2.3',
    '0.0.0.0',
    '169.254.169.254', // AWS/GCP metadata (also in literal deny list)
    '169.254.1.1',     // general link-local
  ]
  for (const ip of privateIPv4) {
    it(`rejects https://${ip}/path`, () => {
      const r = validateExternalUrl(`https://${ip}/path`)
      assert.equal(r.safe, false, `expected rejection for ${ip}`)
    })
  }
})

describe('validateExternalUrl — localhost and metadata hostnames', () => {
  const blockedHostnames = [
    'localhost',
    'localhost.localdomain',
    'ip6-localhost',
    'metadata.google.internal',
    'metadata.internal',
    'metadata',
    'instance-data',
    'instance-data.ec2.internal',
  ]
  for (const host of blockedHostnames) {
    it(`rejects https://${host}/endpoint`, () => {
      const r = validateExternalUrl(`https://${host}/endpoint`)
      assert.equal(r.safe, false)
    })
  }
})

describe('validateExternalUrl — cloud metadata IP literals', () => {
  const metadataIPs = [
    '169.254.169.254', // AWS, GCP, Azure, DO, Alibaba (primary)
    '100.100.100.200', // Alibaba
    '192.0.0.192',     // Oracle Cloud
  ]
  for (const ip of metadataIPs) {
    it(`rejects https://${ip}/latest/meta-data/`, () => {
      const r = validateExternalUrl(`https://${ip}/latest/meta-data/`)
      assert.equal(r.safe, false)
    })
  }
})

describe('validateExternalUrl — IPv6 private ranges', () => {
  const privateIPv6 = [
    'https://[::1]/path',               // loopback
    'https://[fe80::1]/path',           // link-local
    'https://[fc00::1]/path',           // ULA
    'https://[fd00::1]/path',           // ULA
    'https://[::ffff:10.0.0.1]/path',   // IPv4-mapped private
    'https://[::ffff:127.0.0.1]/path',  // IPv4-mapped loopback
  ]
  for (const url of privateIPv6) {
    it(`rejects ${url}`, () => {
      const r = validateExternalUrl(url)
      assert.equal(r.safe, false, `expected rejection for ${url}`)
    })
  }
})

describe('validateExternalUrl — malformed inputs', () => {
  it('rejects empty string', () => {
    assert.equal(validateExternalUrl('').safe, false)
  })

  it('rejects whitespace-only string', () => {
    assert.equal(validateExternalUrl('   ').safe, false)
  })

  it('rejects non-string inputs', () => {
    assert.equal(validateExternalUrl(null).safe, false)
    assert.equal(validateExternalUrl(undefined).safe, false)
    assert.equal(validateExternalUrl(42 as any).safe, false)
    assert.equal(validateExternalUrl({} as any).safe, false)
  })

  it('rejects unparseable strings', () => {
    assert.equal(validateExternalUrl('not a url').safe, false)
    assert.equal(validateExternalUrl('https://').safe, false)
  })
})

describe('validateExternalUrl — regression guards', () => {
  it('(the audit case) rejects cloud metadata service 169.254.169.254', () => {
    const r = validateExternalUrl('https://169.254.169.254/latest/meta-data/iam/security-credentials/')
    assert.equal(r.safe, false)
    assert.match(r.reason!, /metadata/i)
  })

  it('(the audit case) rejects localhost', () => {
    const r = validateExternalUrl('https://localhost:9000/verify')
    assert.equal(r.safe, false)
  })

  it('(the audit case) rejects 127.0.0.1', () => {
    const r = validateExternalUrl('https://127.0.0.1/verify')
    assert.equal(r.safe, false)
  })

  it('(the audit case) rejects 10.x private range', () => {
    const r = validateExternalUrl('https://10.0.1.5/verify')
    assert.equal(r.safe, false)
  })
})
