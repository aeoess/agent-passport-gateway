// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// Wallet → agent reverse index — unit tests
//
// Promised to douglasborthwick-crypto on insumer-examples#1.
// Covers: add, lookup (case-insensitive), update, remove, rebuildFromDb,
// collision handling.

import { describe, it, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import Database from 'better-sqlite3'
import {
  recordBoundWallets,
  removeAgent,
  lookupByAddress,
  rebuildFromDb,
  reverseIndexSize,
  clearReverseIndex,
} from '../src/gateway/wallet-reverse-index.js'

const ETH_A = '0x1234567890abcdef1234567890abcdef12345678'
const ETH_B = '0xfedcba9876543210fedcba9876543210fedcba98'
const BASE_A = '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'

beforeEach(() => clearReverseIndex())

describe('wallet-reverse-index — record + lookup', () => {
  it('records a single binding and looks it up', () => {
    recordBoundWallets({
      tenant_id: 'tenant-1',
      agent_id: 'agent-alpha',
      bound_wallets: [
        { chain: 'ethereum', address: ETH_A, bound_at: '2026-04-10T00:00:00Z', binding_signature: 'sig0' },
      ],
    })
    const hit = lookupByAddress(ETH_A)
    assert.ok(hit)
    assert.equal(hit!.tenant_id, 'tenant-1')
    assert.equal(hit!.agent_id, 'agent-alpha')
    assert.equal(hit!.entry.chain, 'ethereum')
    assert.equal(hit!.entry.address, ETH_A)
    assert.equal(hit!.entry.binding_sig, 'sig0')
  })

  it('lookup is case-insensitive on the address', () => {
    recordBoundWallets({
      tenant_id: 'tenant-1',
      agent_id: 'agent-alpha',
      bound_wallets: [{ chain: 'ethereum', address: ETH_A, binding_signature: 'sig0' }],
    })
    const upper = lookupByAddress(ETH_A.toUpperCase())
    const checksum = lookupByAddress('0x1234567890ABCDEF1234567890abcdef12345678')
    assert.ok(upper)
    assert.ok(checksum)
    assert.equal(upper!.agent_id, 'agent-alpha')
    assert.equal(checksum!.agent_id, 'agent-alpha')
  })

  it('records multi-chain bindings for the same agent', () => {
    recordBoundWallets({
      tenant_id: 'tenant-1',
      agent_id: 'agent-bound-demo',
      bound_wallets: [
        { chain: 'ethereum', address: ETH_A, binding_signature: 'sig-eth' },
        { chain: 'base', address: BASE_A, binding_signature: 'sig-base' },
      ],
    })
    assert.equal(reverseIndexSize(), 2)
    const eth = lookupByAddress(ETH_A)
    const base = lookupByAddress(BASE_A)
    assert.equal(eth!.entry.chain, 'ethereum')
    assert.equal(base!.entry.chain, 'base')
    assert.equal(eth!.agent_id, 'agent-bound-demo')
    assert.equal(base!.agent_id, 'agent-bound-demo')
  })

  it('returns null for unknown addresses and uniform on empty/junk input', () => {
    assert.equal(lookupByAddress(ETH_A), null)
    assert.equal(lookupByAddress(''), null)
    assert.equal(lookupByAddress('   '), null)
    assert.equal(lookupByAddress(undefined as any), null)
  })

  it('skips entries missing required fields', () => {
    recordBoundWallets({
      tenant_id: 'tenant-1',
      agent_id: 'agent-x',
      bound_wallets: [
        null as any,
        {} as any,
        { chain: 'ethereum' } as any,
        { address: ETH_A } as any,
        { chain: 'ethereum', address: '' } as any,
        { chain: 'ethereum', address: ETH_A, binding_signature: 'sig' },
      ],
    })
    assert.equal(reverseIndexSize(), 1)
    assert.ok(lookupByAddress(ETH_A))
  })
})

describe('wallet-reverse-index — update', () => {
  it('replaces prior bindings for the same (tenant, agent) when re-recorded', () => {
    recordBoundWallets({
      tenant_id: 'tenant-1',
      agent_id: 'agent-alpha',
      bound_wallets: [{ chain: 'ethereum', address: ETH_A, binding_signature: 'old-sig' }],
    })
    // Re-record with a different address — old one should be gone
    recordBoundWallets({
      tenant_id: 'tenant-1',
      agent_id: 'agent-alpha',
      bound_wallets: [{ chain: 'ethereum', address: ETH_B, binding_signature: 'new-sig' }],
    })
    assert.equal(lookupByAddress(ETH_A), null)
    const newHit = lookupByAddress(ETH_B)
    assert.ok(newHit)
    assert.equal(newHit!.entry.binding_sig, 'new-sig')
  })

  it('preserves bindings of OTHER agents when one is updated', () => {
    recordBoundWallets({
      tenant_id: 'tenant-1', agent_id: 'agent-a',
      bound_wallets: [{ chain: 'ethereum', address: ETH_A, binding_signature: 'a' }],
    })
    recordBoundWallets({
      tenant_id: 'tenant-1', agent_id: 'agent-b',
      bound_wallets: [{ chain: 'ethereum', address: ETH_B, binding_signature: 'b' }],
    })
    // Update agent-a
    recordBoundWallets({
      tenant_id: 'tenant-1', agent_id: 'agent-a',
      bound_wallets: [{ chain: 'base', address: BASE_A, binding_signature: 'a-base' }],
    })
    assert.equal(lookupByAddress(ETH_A), null)        // a's old eth gone
    assert.equal(lookupByAddress(BASE_A)!.agent_id, 'agent-a')  // a's new base present
    assert.equal(lookupByAddress(ETH_B)!.agent_id, 'agent-b')   // b unchanged
  })
})

describe('wallet-reverse-index — remove', () => {
  it('removeAgent drops all bindings owned by that (tenant, agent)', () => {
    recordBoundWallets({
      tenant_id: 'tenant-1', agent_id: 'agent-alpha',
      bound_wallets: [
        { chain: 'ethereum', address: ETH_A, binding_signature: 's1' },
        { chain: 'base', address: BASE_A, binding_signature: 's2' },
      ],
    })
    assert.equal(reverseIndexSize(), 2)
    removeAgent('tenant-1', 'agent-alpha')
    assert.equal(reverseIndexSize(), 0)
    assert.equal(lookupByAddress(ETH_A), null)
    assert.equal(lookupByAddress(BASE_A), null)
  })

  it('removeAgent of an unknown pair is a no-op', () => {
    recordBoundWallets({
      tenant_id: 'tenant-1', agent_id: 'agent-alpha',
      bound_wallets: [{ chain: 'ethereum', address: ETH_A, binding_signature: 's' }],
    })
    removeAgent('tenant-1', 'does-not-exist')
    assert.equal(reverseIndexSize(), 1)
  })
})

describe('wallet-reverse-index — collision handling', () => {
  it('first-bound wins when two agents claim the same address', () => {
    recordBoundWallets({
      tenant_id: 'tenant-1', agent_id: 'first',
      bound_wallets: [{ chain: 'ethereum', address: ETH_A, binding_signature: 'first-sig' }],
    })
    recordBoundWallets({
      tenant_id: 'tenant-1', agent_id: 'second',
      bound_wallets: [{ chain: 'ethereum', address: ETH_A, binding_signature: 'second-sig' }],
    })
    const hit = lookupByAddress(ETH_A)
    assert.equal(hit!.agent_id, 'first', 'first-bound agent wins')
  })

  it('removing the first-bound agent promotes the collision-tracked alternative', () => {
    recordBoundWallets({
      tenant_id: 'tenant-1', agent_id: 'first',
      bound_wallets: [{ chain: 'ethereum', address: ETH_A, binding_signature: 'first-sig' }],
    })
    recordBoundWallets({
      tenant_id: 'tenant-1', agent_id: 'second',
      bound_wallets: [{ chain: 'ethereum', address: ETH_A, binding_signature: 'second-sig' }],
    })
    removeAgent('tenant-1', 'first')
    const promoted = lookupByAddress(ETH_A)
    assert.ok(promoted)
    assert.equal(promoted!.agent_id, 'second')
    assert.equal(promoted!.entry.binding_sig, 'second-sig')
  })
})

describe('wallet-reverse-index — rebuildFromDb', () => {
  function makeTestDb(): Database.Database {
    const db = new Database(':memory:')
    db.exec(`
      CREATE TABLE tenants (id TEXT PRIMARY KEY);
      CREATE TABLE agents (
        id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        agent_id TEXT NOT NULL,
        public_key TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'active',
        metadata TEXT,
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
      );
      INSERT INTO tenants (id) VALUES ('tenant-1');
    `)
    return db
  }

  it('rebuilds the index from agents.metadata.bound_wallets', () => {
    const db = makeTestDb()
    db.prepare(`INSERT INTO agents (id, tenant_id, agent_id, public_key, status, metadata) VALUES (?, ?, ?, ?, 'active', ?)`)
      .run('uuid-1', 'tenant-1', 'aeoess-bound-demo', 'pk-aeoess', JSON.stringify({
        bound_wallets: [
          { chain: 'ethereum', address: ETH_A, bound_at: '2026-04-10T00:00:00Z', binding_signature: 'sig-eth' },
          { chain: 'base', address: BASE_A, bound_at: '2026-04-10T00:00:00Z', binding_signature: 'sig-base' },
        ],
      }))
    db.prepare(`INSERT INTO agents (id, tenant_id, agent_id, public_key, status, metadata) VALUES (?, ?, ?, ?, 'active', ?)`)
      .run('uuid-2', 'tenant-1', 'plain-agent', 'pk-plain', null)

    const stats = rebuildFromDb(db)
    assert.equal(stats.agentsScanned, 1)
    assert.equal(stats.addressesIndexed, 2)

    const ethHit = lookupByAddress(ETH_A)
    const baseHit = lookupByAddress(BASE_A)
    assert.equal(ethHit!.agent_id, 'aeoess-bound-demo')
    assert.equal(baseHit!.agent_id, 'aeoess-bound-demo')
    assert.equal(ethHit!.entry.binding_sig, 'sig-eth')
    db.close()
  })

  it('skips inactive agents and survives malformed JSON', () => {
    const db = makeTestDb()
    db.prepare(`INSERT INTO agents (id, tenant_id, agent_id, public_key, status, metadata) VALUES (?, ?, ?, ?, 'inactive', ?)`)
      .run('uuid-1', 'tenant-1', 'inactive-agent', 'pk', JSON.stringify({
        bound_wallets: [{ chain: 'ethereum', address: ETH_A, binding_signature: 's' }],
      }))
    db.prepare(`INSERT INTO agents (id, tenant_id, agent_id, public_key, status, metadata) VALUES (?, ?, ?, ?, 'active', ?)`)
      .run('uuid-2', 'tenant-1', 'broken-meta', 'pk', '{not-json}')

    const stats = rebuildFromDb(db)
    assert.equal(stats.addressesIndexed, 0)
    assert.equal(lookupByAddress(ETH_A), null)
    db.close()
  })
})
