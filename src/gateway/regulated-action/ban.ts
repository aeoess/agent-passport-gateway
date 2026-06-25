// APS Regulated Action Profile v0: BAN client (private gateway).
//
// Spawns the level_1 signer child process and talks to it over newline-delimited JSON. The
// gateway holds this handle, NOT the key. The client interface intentionally exposes only
// getPublicKey() and signResourceConfirmation(); there is no method to read the private key,
// and the child has none either. resourceConfirmationType() returns boundary_attested_weak at
// level_1, the honest floor: a level_1 BAN cannot mint a strong (boundary_attested) confirmation.

import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process'
import { createInterface, type Interface } from 'node:readline'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import { canonicalizeJCS } from 'agent-passport-system'
import { RAPV0_TAG } from './disposition.js'

const HERE = dirname(fileURLToPath(import.meta.url))

export interface BanSigner {
  readonly level: string
  getPublicKey(): Promise<string>
  /** Sign a resource confirmation core object (minus its signature field). */
  signResourceConfirmation(core: Record<string, unknown>): Promise<string>
  /** The confirmation type this BAN can honestly produce. level_1 -> boundary_attested_weak. */
  resourceConfirmationType(): string
  close(): void
}

interface Pending { resolve: (v: string) => void; reject: (e: Error) => void }

export function spawnBan(): BanSigner {
  const child: ChildProcessWithoutNullStreams = spawn(process.execPath, [join(HERE, 'ban-process.mjs')], {
    stdio: ['pipe', 'pipe', 'inherit'],
  })
  const rl: Interface = createInterface({ input: child.stdout })
  const pending = new Map<number, Pending>()
  let nextId = 1
  let publicKey: string | null = null
  let level = 'level_1'
  let resourceType = 'boundary_attested_weak'

  rl.on('line', (line) => {
    let msg: Record<string, unknown>
    try { msg = JSON.parse(line) } catch { return }
    if (msg.ready) return
    const id = msg.id as number | undefined
    if (id === undefined) return
    const p = pending.get(id)
    if (!p) return
    pending.delete(id)
    if (msg.error) { p.reject(new Error(String(msg.error))); return }
    if (typeof msg.publicKey === 'string') {
      publicKey = msg.publicKey
      if (typeof msg.level === 'string') level = msg.level
      if (typeof msg.resource_type === 'string') resourceType = msg.resource_type
      p.resolve(msg.publicKey)
    } else if (typeof msg.sig === 'string') {
      p.resolve(msg.sig)
    }
  })

  function call(method: string, payload?: string): Promise<string> {
    const id = nextId++
    return new Promise<string>((resolve, reject) => {
      pending.set(id, { resolve, reject })
      child.stdin.write(JSON.stringify({ id, method, payload }) + '\n')
      setTimeout(() => {
        if (pending.has(id)) { pending.delete(id); reject(new Error('BAN signer timeout')) }
      }, 5000)
    })
  }

  return {
    get level() { return level },
    async getPublicKey() {
      if (publicKey) return publicKey
      return call('pubkey')
    },
    async signResourceConfirmation(core: Record<string, unknown>) {
      const payload = `${RAPV0_TAG.resource}.${canonicalizeJCS(core)}`
      return call('sign', payload)
    },
    resourceConfirmationType() { return resourceType },
    close() { try { child.kill() } catch { /* noop */ } },
  }
}
