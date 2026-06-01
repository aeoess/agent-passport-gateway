// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// Delegation Contracts module - human-to-machine authority bridge (GEM).
// The human summary is derived from the SDK-signed machine scope and cannot
// drift from what is enforced. See contract.ts for the invariants.

export {
  DelegationContract,
  REQUIRED_OWNER_ROLES,
} from './contract.js'
export type {
  OwnerRole,
  ContractOwner,
  OwnerSignature,
  BoundReceiptRef,
  DelegationContractArtifact,
} from './contract.js'
export {
  getRenderScopeDimension,
  setRenderScopeDimension,
  passthroughRenderScopeDimension,
} from './scope-registry.js'
export type {
  ScopeDimension,
  RenderScopeDimension,
} from './scope-registry.js'
