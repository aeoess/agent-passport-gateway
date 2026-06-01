// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// G-D1 - Honest disclaimer for policy simulation (constraint C4)
// ══════════════════════════════════════════════════════════════════
// This module is customer-facing, so the claims discipline is mandatory.
// A simulation replays a candidate policy against receipts that already
// happened. It tells you what WOULD have changed in the past. It cannot tell
// you the policy is safe to enforce going forward, because future traffic is
// not in the sample. Every simulation result carries this disclaimer verbatim.
//
// Claims rules applied here:
//   - "estimates" / "would have", never "proves" / "guarantees".
//   - describes the past, never promises future safety.
//   - "supports evidence for", never "makes you compliant".
//   - assurance is verifier-derived, never issuer-asserted.
// ══════════════════════════════════════════════════════════════════

/**
 * The canonical, machine-stable disclaimer key. Tests assert on this exact
 * string being present in every simulation output. Changing the wording is a
 * Tima-gated decision (customer-facing claim).
 */
export const SIMULATION_DISCLAIMER =
  'This simulation estimates what this candidate policy would have done against ' +
  'past receipts only. It describes the past and does not guarantee future safety. ' +
  'A clean simulation supports evidence for a policy change but does not prove the ' +
  'policy is correct and does not make you compliant. Historical traffic is not a ' +
  'forecast of future traffic; review before enforcing.'

/** A short caption form for compact surfaces (still honest, same constraints). */
export const SIMULATION_DISCLAIMER_SHORT =
  'Estimates the past from historical receipts. Does not guarantee future safety.'
