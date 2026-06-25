// APS Regulated Action Profile v0: Boundary Attestation Node (BAN) signer process.
//
// HONEST CLASSIFICATION: this is a level_1 signer (separate PROCESS, SAME user). The gateway
// parent can ptrace its own child and read /proc/<pid>/mem at the same uid, so this does NOT
// defeat a malicious operator. It is boundary_attested_weak. A level_2 signer (separate OS
// principal the gateway uid cannot ptrace: separate OS user with a 0600 key, or a separate
// container / remote signer) is an enterprise deployment decision, not a reference-build artifact.
//
// The private key lives ONLY in this process memory. The protocol exposes pubkey and sign over
// newline-delimited JSON on stdin/stdout. There is deliberately NO method that returns the
// private key. At level_1 the resource confirmation type is reported as boundary_attested_weak,
// which can never satisfy resource_present_valid, so the honest end-to-end path returns
// intent_precommitted, never reconciled.

import { createInterface } from 'node:readline'
import { generateKeyPair, sign } from 'agent-passport-system'

const LEVEL = 'level_1'
const RESOURCE_TYPE = 'boundary_attested_weak'
const kp = generateKeyPair() // private key never leaves this process

const rl = createInterface({ input: process.stdin })
rl.on('line', (line) => {
  let msg
  try { msg = JSON.parse(line) } catch { return }
  if (msg.method === 'pubkey') {
    process.stdout.write(JSON.stringify({ id: msg.id, publicKey: kp.publicKey, level: LEVEL, resource_type: RESOURCE_TYPE }) + '\n')
  } else if (msg.method === 'sign') {
    // Signs exactly the caller-supplied domain-separated payload string. Never echoes the key.
    const sig = sign(String(msg.payload), kp.privateKey)
    process.stdout.write(JSON.stringify({ id: msg.id, sig }) + '\n')
  } else {
    process.stdout.write(JSON.stringify({ id: msg.id, error: 'unknown_method' }) + '\n')
  }
})
process.stdout.write(JSON.stringify({ ready: true, level: LEVEL }) + '\n')
