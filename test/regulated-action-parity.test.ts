// APS Regulated Action Profile v0: STANDING PARITY LOCK for the vendored disposition copy.
//
// The gateway vendors the disposition truth-table (src/gateway/regulated-action/disposition.ts)
// because the Railway build is a single repo (node:22-slim, COPY src/ only) and the installed SDK
// version predates the published RegulatedActionV0 module, so a publish-free import is not
// deployable (DEVIATION D-6). This test locks the vendored copy to the frozen conformance vectors:
// it runs the vendored evaluateDisposition over every verifier-surface vector and FAILS on any
// divergence in disposition, incomplete_reason, authority_basis, or violations[]. It additionally
// cross-checks against the SDK module directly when a local SDK build is resolvable (dev only).
//
// When the SDK publishes a version exposing RegulatedActionV0, replace the vendored copy with a
// direct import and retire the fixture leg (see HANDOFF RECOMMENDATIONS).

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { dirname } from 'node:path'
import { evaluateDisposition, type RegulatedReceipt, type RegulatedContext } from '../src/gateway/regulated-action/index.js'

const HERE = dirname(fileURLToPath(import.meta.url))
const doc = JSON.parse(readFileSync(join(HERE, 'fixtures', 'rapv0-vectors.json'), 'utf8')) as {
  count: number
  verifier_vector_count: number
  vectors: Array<{
    id: string
    surface: string
    input_receipt: RegulatedReceipt
    verification_context: RegulatedContext
    expected: { disposition: string; incomplete_reason?: string; authority_basis?: string; violations: string[] }
  }>
}
const verifierVectors = doc.vectors.filter((v) => v.surface === 'verifier')

describe('RAPV0 vendored-copy parity lock (gateway disposition.ts vs frozen vectors)', () => {
  it('the fixture carries the full frozen set (31 verifier + 2 completeness)', () => {
    assert.equal(doc.count, 33)
    assert.equal(verifierVectors.length, 31)
  })

  for (const v of verifierVectors) {
    it(`${v.id}: vendored copy reproduces ${v.expected.disposition}`, () => {
      const r = evaluateDisposition(v.input_receipt, v.verification_context)
      assert.equal(r.disposition, v.expected.disposition, `${v.id} disposition`)
      if (v.expected.incomplete_reason) assert.equal(r.incomplete_reason, v.expected.incomplete_reason, `${v.id} reason`)
      if (v.expected.authority_basis) assert.equal(r.authority_basis, v.expected.authority_basis, `${v.id} basis`)
      assert.deepEqual(r.violations, v.expected.violations, `${v.id} violations`)
      assert.equal(r.judgment_correctness, 'not_claimed')
      assert.equal(r.authority_replay, 'not_evaluated')
    })
  }
})

// Dev-only cross-impl leg: if a local SDK build exposes RegulatedActionV0, assert ZERO divergence
// between the SDK verifier and the vendored copy across every verifier vector. Skipped (not failed)
// when the SDK module is not resolvable, e.g. inside the Railway container.
describe('RAPV0 cross-impl parity (SDK module vs vendored copy, dev only)', () => {
  it('SDK verifier and vendored copy agree on all verifier vectors (or skip if SDK absent)', async () => {
    let sdk: { verifyRegulatedAction: (r: RegulatedReceipt, c: RegulatedContext) => { disposition: string; incomplete_reason?: string; authority_basis?: string; violations: string[] } } | null = null
    const candidates = [
      `${process.env.HOME}/agent-passport-system/dist/src/index.js`,
      `${process.env.HOME}/agent-passport-system/src/index.ts`,
    ]
    for (const path of candidates) {
      try {
        const mod = await import(path)
        if (mod?.RegulatedActionV0?.verifyRegulatedAction) { sdk = mod.RegulatedActionV0; break }
      } catch { /* not resolvable here */ }
    }
    if (!sdk) {
      console.log('[parity] SDK module not resolvable in this environment; vendored-vs-frozen leg already covers parity. Skipping cross-impl leg.')
      return
    }
    let divergences = 0
    for (const v of verifierVectors) {
      const a = sdk.verifyRegulatedAction(v.input_receipt, v.verification_context)
      const b = evaluateDisposition(v.input_receipt, v.verification_context)
      if (a.disposition !== b.disposition || a.incomplete_reason !== b.incomplete_reason ||
          a.authority_basis !== b.authority_basis || JSON.stringify(a.violations) !== JSON.stringify(b.violations)) {
        divergences++
        console.error(`[parity] DIVERGENCE ${v.id}: sdk=${a.disposition}:${a.incomplete_reason ?? '-'} vendored=${b.disposition}:${b.incomplete_reason ?? '-'}`)
      }
    }
    assert.equal(divergences, 0, 'SDK module and vendored copy must agree on every verifier vector')
  })
})
