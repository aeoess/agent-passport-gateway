// Nano Payment Rail — Live RPC Test
// Run: npx tsx tests/nano-live.ts
// Tests actual Nano network queries (read-only, no wallet needed)

import { createNanoRail, rawToXno } from '../src/payment-rails/nano.js'

const KNOWN_ACCOUNT = 'nano_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuohr3'

console.log('═══════════════════════════════════════')
console.log('  Nano Live RPC Tests (read-only)')
console.log('═══════════════════════════════════════\n')

const rail = createNanoRail({
  rpcUrl: 'https://rpc.nano.to',
  receivingAddress: KNOWN_ACCOUNT,
})

let pass = 0
let fail = 0

function ok(name: string, condition: boolean, detail?: string) {
  if (condition) {
    console.log(`  ✅ ${name}${detail ? ` — ${detail}` : ''}`)
    pass++
  } else {
    console.log(`  ❌ ${name}${detail ? ` — ${detail}` : ''}`)
    fail++
  }
}

try {
  // Test 1: getBalance
  console.log('Balance:')
  const balance = await rail.getBalance()
  ok('getBalance returns balance_raw', balance.balance.length > 0, `${balance.balanceXno} XNO`)
  ok('getBalance returns receivable', balance.receivable.length > 0)

  // Test 2: getHistory
  console.log('\nHistory:')
  const history = await rail.getHistory(5)
  ok('getHistory returns array', Array.isArray(history), `${history.length} transactions`)
  if (history.length > 0) {
    const first = history[0]
    ok('history entry has hash', !!first.hash)
    ok('history entry has amountXno', !!first.amountXno, first.amountXno + ' XNO')
    ok('history entry has type', !!first.type, first.type)
  }

  // Test 3: verifyTransaction (use a known block hash from history)
  if (history.length > 0) {
    console.log('\nVerify Transaction:')
    const txHash = history[0].hash
    const verification = await rail.verifyTransaction(txHash)
    ok('verifyTransaction returns result', verification.amount >= 0, `verified=${verification.verified}`)
    ok('verification has sender', !!verification.sender, verification.sender?.slice(0, 20) + '...')
  }

  // Test 4: createInvoice (offline, but confirm it formats for this address)
  console.log('\nInvoice (offline):')
  const invoice = await rail.createInvoice({
    amount: 0.001,
    settlementId: 'live-test-001',
    agentId: 'test-agent',
    memo: 'live smoke test',
  })
  ok('invoice destination matches config', invoice.destination === KNOWN_ACCOUNT)
  ok('invoice amount includes XNO', invoice.amountHuman.includes('XNO'))
  ok('invoice status is pending', invoice.status === 'pending')

  // Test 5: checkStatus on the invoice (should stay pending — nobody paid)
  console.log('\nCheck Status (no payment):')
  const status = await rail.checkStatus(invoice.invoiceId)
  ok('unpaid invoice stays pending', status.status === 'pending')

} catch (e: any) {
  console.error('\n  💥 Fatal error:', e.message)
  fail++
}

console.log(`\n═══════════════════════════════════════`)
console.log(`  Results: ${pass} passed, ${fail} failed`)
console.log(`═══════════════════════════════════════`)
process.exit(fail > 0 ? 1 : 0)
