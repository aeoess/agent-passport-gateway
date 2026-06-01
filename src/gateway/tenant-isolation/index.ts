// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// G-D4 - tenant-isolation public surface
// ══════════════════════════════════════════════════════════════════
// Onboarding + deployment hardening, the D2 isolation switch, customer
// bring-your-own trust root (W2-B1 seam), hash-and-pointer (W2-B6 seam),
// the cross-tenant cohort k-floor-over-time-series gate (C3), and the
// air-gapped offline export bundle. THIN-GATEWAY: this module coordinates,
// pre-checks, and emits; authority and verification live at the edges.
// ══════════════════════════════════════════════════════════════════

export {
  type IsolationMode,
  type TenantIsolationState,
  type CrossTenantDecision,
  getTenantIsolationState,
  normalizeIsolationRow,
  canParticipateCrossTenant,
  canTenantParticipateCrossTenant,
  setIsolationMode,
  setCohortOptIn,
} from './isolation-switch.js'

export {
  TimeSeriesFloorStrategy,
  DEFAULT_COHORT_GATE_CONFIG,
  type CohortGateConfig,
  type CohortContribution,
  type CohortEmissionResult,
  type AggregateOnlySignal,
  gateCohortEmission,
  membershipDigest,
  membershipChurn,
} from './cohort-gate.js'

export {
  type TrustRootSource,
  type CustomerTrustAnchor,
  type TrustRootBinding,
  type TrustRootValidation,
  anchorFingerprint,
  validateCustomerTrustAnchor,
  bindTrustRoot,
} from './trust-root-seam.js'

export {
  type HashPointerEnvelope,
  toHashPointer,
  assertNoRawPayload,
  isHashOnly,
} from './hash-pointer-seam.js'

export {
  type AirGapBundle,
  buildAirGapBundle,
  verifyAirGapBundleOffline,
  bundleRecordsToJsonLines,
  bundleRecordsToCsv,
} from './airgap-bundle.js'

export {
  type DeploymentIsolationConfig,
  readDeploymentConfig,
  applyDeploymentIsolationDefault,
} from './boot.js'

export { tenantIsolationRouter } from './router.js'
