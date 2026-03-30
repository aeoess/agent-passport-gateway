// Nano Payment Rail — Smoke Test
// Run: npx tsx tests/nano-smoke.ts

import { xnoToRaw, rawToXno, createNanoRail } from '../src/payment-rails/nano.js'

console.log('═══════════════════════════════════════')
console.log('  Nano Payment Rail — Smoke Tests')
console.log('═══════════════════════════════════════\n')

let pass = 0
let fail = 0

function assert(name: string, actual: any, expected: any) {
  if (String(actual) === String(expected)) {
    console.log(`  ✅ ${name}`)
    pass++
  } else {
    console.log(`  ❌ ${name}: got "${actual}", expected "${expected}"`)
    fail++
  }
}

// ── Unit Conversion Tests ──
console.log('Unit Conversion:')

// 1 XNO = 10^30 raw
assert('1 XNO → raw', xnoToRaw('1'), '1000000000000000000000000000000')
assert('0 XNO → raw', xnoToRaw('0'), '0')
assert('0.001 XNO → raw', xnoToRaw('0.001'), '1000000000000000000000000000')
assert('0.000001 XNO → raw', xnoToRaw('0.000001'), '1000000000000000000000000')
assert('100 XNO → raw', xnoToRaw('100'), '100000000000000000000000000000000')

// Roundtrip
assert('raw→xno: 1 XNO', rawToXno('1000000000000000000000000000000'), '1')
assert('raw→xno: 0.001 XNO', rawToXno('1000000000000000000000000000'), '0.001')
assert('raw→xno: 0.000001 XNO', rawToXno('1000000000000000000000000'), '0.000001')
assert('raw→xno: 100 XNO', rawToXno('100000000000000000000000000000000'), '100')
assert('raw→xno: 0', rawToXno('0'), '0')

// Roundtrip fidelity
const testAmounts = ['0.001', '1', '0.000001', '42.5', '100']
for (const amt of testAmounts) {
  const raw = xnoToRaw(amt)
  const back = rawToXno(raw)
  assert(`roundtrip ${amt}`, back, amt)
}

// ── Rail Instantiation ──
console.log('\nRail Instantiation:')

const rail = createNanoRail({
  receivingAddress: 'nano_3pp4166test000000000000000000000000000000000000000000000test',
})
assert('rail.name', rail.name, 'nano')
assert('rail.currency', rail.currency, 'XNO')

// ── Invoice Creation (offline, no RPC needed) ──
console.log('\nInvoice Creation:')

const invoice = await rail.createInvoice({
  amount: 0.001,
  settlementId: 'settle-test-001',
  agentId: 'agent-smoke',
  memo: 'smoke test',
  expiresInSeconds: 60,
})
assert('invoice has id', !!invoice.invoiceId, true)
assert('invoice rail', invoice.rail, 'nano')
assert('invoice status', invoice.status, 'pending')
assert('invoice currency', invoice.currency, 'XNO')
assert('invoice has destination', invoice.destination.startsWith('nano_'), true)
assert('invoice has expiry', !!invoice.expiresAt, true)
assert('invoice metadata has raw', !!(invoice.metadata as any).amountRaw, true)

// ── Amount Uniqueness (two invoices for same amount should differ in raw) ──
console.log('\nAmount Uniqueness:')

const inv1 = await rail.createInvoice({ amount: 0.01 })
const inv2 = await rail.createInvoice({ amount: 0.01 })
const raw1 = (inv1.metadata as any).amountRaw
const raw2 = (inv2.metadata as any).amountRaw
assert('two invoices same amount → different raw', raw1 !== raw2, true)
// Both should be close to 0.01 XNO in raw
const base = BigInt(xnoToRaw('0.01'))
assert('inv1 raw > base', BigInt(raw1) > base, true)
assert('inv1 raw < base+10000', BigInt(raw1) < base + 10000n, true)
assert('inv2 raw > base', BigInt(raw2) > base, true)

// ── Summary ──
console.log(`\n═══════════════════════════════════════`)
console.log(`  Results: ${pass} passed, ${fail} failed`)
console.log(`═══════════════════════════════════════`)
process.exit(fail > 0 ? 1 : 0)
