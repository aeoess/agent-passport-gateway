// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Public conformance surface: the single source of truth.
//
// Both the JSON endpoint (GET /api/v1/public/conformance) and the shields
// badge endpoint (GET /api/v1/public/conformance/badge) derive from the one
// CONFORMANCE_SUMMARY object below; there is no second hardcoded copy. Bump
// these numbers to mirror the aps-conformance-suite runner tally on each
// conformance-suite commit. Kept in its own side-effect-free module so the
// derivation is unit-testable without booting the server.
// ══════════════════════════════════════════════════════════════════

// Mirror of the aps-conformance-suite runner tally (verify.ts). Categories and
// totals reflect the runner output, not the fixture manifest: expected-value
// vector classes that the runner reports as skipped are verified upstream and
// by cross-language parity, and are counted in `skipped_vectors`.
export const CONFORMANCE_SUMMARY = {
  repo:        'https://github.com/aeoess/aps-conformance-suite',
  categories: [
    { name: 'bilateral-delegation',  total: 10, passing: 10 },
    { name: 'inference-session',     total: 7,  passing: 7  },
    { name: 'instruction-provenance',total: 10, passing: 10 },
    { name: 'aivss-scenarios',       total: 10, passing: 10 },
    { name: 'canonical-bytes',       total: 9,  passing: 8, skipped: 1 },
    { name: 'accountability-record', total: 12, passing: 12 },
    { name: 'read-fidelity-receipt', total: 9,  passing: 9  },
    { name: 'actionref-canonical',   total: 4,  passing: 0, skipped: 4 },
    { name: 'bilateral-pair',        total: 6,  passing: 0, skipped: 6 },
    { name: 'bilateral-golden',      total: 2,  passing: 2 },
  ],
  total_vectors:   79,
  passing_vectors: 68,
  failing_vectors: 0,
  skipped_vectors: 11,
  last_verified:  '2026-07-10',  // Bumped on each conformance-suite commit
  rfc_8785_jcs:   true,
  ed25519_signed: true,
  notes: 'Canonicalization-contract vectors are byte-identical, JCS canonicalized, and Ed25519 signature-verified by the suite runner; expected-value vector classes (reported skipped by the runner) are verified upstream and by cross-language parity. Zero failures. Reproducible from fixed seeds.',
}

// Shields.io endpoint schema (https://shields.io/endpoint), derived from the
// same CONFORMANCE_SUMMARY. Red when any vector fails, else brightgreen.
export function conformanceBadge() {
  return {
    schemaVersion: 1,
    label: 'APS conformance',
    message: `${CONFORMANCE_SUMMARY.passing_vectors}/${CONFORMANCE_SUMMARY.total_vectors} verified`,
    color: CONFORMANCE_SUMMARY.failing_vectors > 0 ? 'red' : 'brightgreen',
  }
}
