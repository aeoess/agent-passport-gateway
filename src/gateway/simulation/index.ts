// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// G-D1 - Modes + policy simulation. Public module surface.
// ══════════════════════════════════════════════════════════════════
// Shadow / warn / approval / enforce / emergency enforcement modes plus a
// policy-simulation-over-historical-receipts engine and the migration metric.
// Product intelligence (how well governance works), kept in the private
// gateway. The protocol primitives it leans on (scope authorization) come from
// agent-passport-system via a lazy-import seam; nothing here reimplements them.
// ══════════════════════════════════════════════════════════════════

export {
  type EnforcementMode,
  type RiskLevel,
  type RawVerdict,
  type ModeEffect,
  type ModeDecision,
  type ModeDecisionInput,
  ENFORCEMENT_MODES,
  isEnforcementMode,
  applyMode,
  classifyRequestRisk,
} from './modes.js'

export {
  DEFAULT_MODE,
  initModeConfigTable,
  resolveMode,
  setMode,
  listModes,
} from './mode-config.js'

export {
  type CandidatePolicy,
  type HistoricalDecision,
  type SimulationInput,
  type SimulationResult,
  evaluateCandidate,
  simulatePolicy,
} from './engine.js'

export {
  type MigrationMetric,
  initModeObservationsTable,
  recordModeObservation,
  computeMigrationMetric,
} from './migration-metric.js'

export {
  SIMULATION_DISCLAIMER,
  SIMULATION_DISCLAIMER_SHORT,
} from './disclaimer.js'

export {
  type SpineFactType,
  registerEventSpineSink,
  emitToEventSpine,
} from './event-spine.js'

export { simulationRouter } from './router.js'
