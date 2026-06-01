// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Data class vocabulary (local, behind a Wave 2 SDK seam)
// ══════════════════════════════════════════════════════════════════
// The SDK has no first-class data-CLASS primitive in the installed
// alpha (^2.6.0-alpha.3). There is no classifyDataClass and no DataClass
// enum. So the class vocabulary lives here, LOCALLY, behind a typed
// seam, and we stub the SDK call. When the SDK ships its class primitive,
// the local enum is replaced and grade derivation routes through the SDK.
//
// TODO(W2-classification): SDK DataClass vocabulary +
//   classifyDataClass(source, evidence) -> { class, confidence:
//   'declared'|'detected'|'inferred', grade } will replace DATA_CLASSES
//   and the local grade derivation in source-class.ts. Until then we
//   define the vocabulary here and derive the grade via the SDK
//   classifyEvidenceQuality / evidenceQualityToGrade pattern.
//
// The vocabulary is intentionally a small, regulator-legible set. It is
// NOT exhaustive; a connector may report a class outside this set, in
// which case the class is recorded verbatim and treated as the lowest
// known sensitivity for destination matching (handled by the caller).
// ══════════════════════════════════════════════════════════════════

/** Known data classes. A connector-reported class outside this set is
 *  still recorded; this list seeds destination policy and ordering. */
export const DATA_CLASSES = [
  'public',
  'internal',
  'confidential',
  'pii',
  'phi',
  'pci',
  'secret',
] as const

export type DataClass = (typeof DATA_CLASSES)[number]

/** Relative sensitivity rank, ascending. Used only to give the
 *  destination-control check a deterministic ordering when a policy
 *  lists allowed classes; it is not a security boundary on its own. An
 *  unknown class ranks at the most sensitive tier so it never
 *  accidentally clears a permissive destination. */
const SENSITIVITY_RANK: Record<string, number> = {
  public: 0,
  internal: 1,
  confidential: 2,
  pii: 3,
  pci: 4,
  phi: 5,
  secret: 6,
}

export function isKnownDataClass(value: string): value is DataClass {
  return (DATA_CLASSES as readonly string[]).includes(value)
}

/** Sensitivity rank for a class string. Unknown classes rank above the
 *  most sensitive known class so destination matching stays fail-closed. */
export function sensitivityRank(dataClass: string): number {
  const rank = SENSITIVITY_RANK[dataClass]
  return rank === undefined ? SENSITIVITY_RANK.secret + 1 : rank
}
