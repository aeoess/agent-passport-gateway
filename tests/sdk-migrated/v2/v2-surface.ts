// Test-support barrel: the SDK's v2/index no longer exists as a single
// surface. During the 2026-04-17 gateway extraction (commit e1ae666) part
// of the v2 constitutional modules moved to src/sdk-migrated/v2/ while the
// rest remained in the agent-passport-system SDK. This barrel re-exports
// exactly the symbols the migrated v2 test files consume, from wherever
// each symbol now lives. Test-only — not part of the gateway's public API.

export { clearAffectedPartyStores, fileAppeal, fileComplaint, getComplaints, registerAffectedParty, resolveAppeal, resolveComplaint } from '../../../src/sdk-migrated/v2/affected-party.js'
export { checkSupermajority, clearAmendmentStores, proposeAmendment, ratifyAmendment, requiresHumanRatification, voteOnAmendment } from '../../../src/sdk-migrated/v2/amendment.js'
export { checkComplexityMasking, checkImpossibleLatency, checkRubberStamping, checkVelocitySpike, clearApprovalFatigueStores, computeFatigueMetrics, getApprovalHistory, getFatigueFlags, recordApproval } from '../../../src/sdk-migrated/v2/approval-fatigue.js'
export { clearBlindEvaluationStores, createBlindEvaluation, evaluateBlind, getBlindSubmission, revealIdentities, submitBlind } from '../../../src/sdk-migrated/v2/blind-evaluation.js'
export { clearCascadeCorrelationStores, computeCorrelationMetrics, detectFeedbackLoops, recordOutputDependency } from '../../../src/sdk-migrated/v2/cascade-correlation.js'
export { clearCircuitBreakerStores, defineBreaker, evaluateBreaker, getBlockedCategories, isActionBlocked, resetBreaker, tripBreaker } from '../../../src/sdk-migrated/v2/circuit-breakers.js'
export { auditCompositeCapabilities, clearCompositeAuditStores, getCompositeFlags, isAgentInLaunderingPipeline, recordPipelineAction } from '../../../src/sdk-migrated/v2/composite-audit.js'
export { auditCrossChainFlows, clearCrossChainAuditStores, recordCrossChainFlow } from '../../../src/sdk-migrated/v2/cross-chain-audit.js'
export { clearEffectStores, declareEffects, getAgentDivergenceAvg, getEffectPatterns, getVerificationsForAgent, isAgentBlockedByEffects, verifyEffects } from '../../../src/sdk-migrated/v2/effect-enforcement.js'
export { clearEffectSamplingStores, completeAudit, createSamplingPolicy, getSamplingStats, recordSample, setSamplingRng, shouldSample } from '../../../src/sdk-migrated/v2/effect-sampling.js'
export { clearEmergenceStores, computeSystemMetrics, detectEmergence, getEmergenceFlags, recordAgentActivity, reviewEmergenceFlag } from '../../../src/sdk-migrated/v2/emergence.js'
export { clearExternalityStores, computeExternalityBudget, getResourceUtilization, isOverBudget, recordExternality, registerSharedResource } from '../../../src/sdk-migrated/v2/externality.js'
export { analyzeCumulativeDrift, clearGovernanceDriftStores, getGovernanceDriftFlags, recordGovernanceChange, reviewGovernanceDriftFlag } from '../../../src/sdk-migrated/v2/governance-drift.js'
export type { ChangeDirection } from '../../../src/sdk-migrated/v2/governance-drift.js'
export { analyzeInactionPattern, clearInactionAuditStores, recordAvailableAction, recordConsequence, recordInaction } from '../../../src/sdk-migrated/v2/inaction-audit.js'
export { analyzeOutputProportionality, clearOutputProportionalityStores, getFlaggedOutputs } from '../../../src/sdk-migrated/v2/output-proportionality.js'
export { abortTransition, approveTransition, clearRootTransitionStores, createTransitionPlan, executeTransition, getApprovalStatus, getCurrentPhase, getPhaseHistory } from '../../../src/sdk-migrated/v2/root-transition.js'
export { checkSemanticCompliance, clearSemanticScopingStores, defineSemanticScope, getScopeViolations } from '../../../src/sdk-migrated/v2/scope-violations.js'
export { analyzeSemanticDrift, clearSemanticDriftStores, getAgentDriftAverage, getDriftResults, isAgentSemanticRisk, recordSemanticIntent } from '../../../src/sdk-migrated/v2/semantic-drift-tracker.js'
export { assignBranch, checkSeparation, clearSeparationOfPowersStores, getAgentBranches, getBranchMembers, preventBranchConflict } from '../../../src/sdk-migrated/v2/separation-of-powers.js'
export { clearValuesOverrideStores, getAgentPenaltyCount, getOverrideHistory, getPendingOverrideReviews, invokeValuesOverride, reviewOverride } from '../../../src/sdk-migrated/v2/values-override.js'
export { attachProfile, checkProfileCompliance, clearEpistemicIsolationStores, clearIntentBindingStores, clearPolicyProfileStores, createBarrier, createIntentChain, createProfile, detachProfile, extendChain, extractKeywords, getBarrierStatus, getProfilesForTarget, isBarrierComplete, revealResults, submitToBarrier, validateChainIntegrity } from 'agent-passport-system'
export type { PolicyContext } from 'agent-passport-system'
