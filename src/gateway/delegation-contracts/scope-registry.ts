// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════════
// Scope dimension rendering - single seam over the SDK Wave 2 scope registry
// ══════════════════════════════════════════════════════════════════════
// The human-readable summary of a delegation contract is DERIVED from the
// machine scope. This file is the one place that maps a raw scope token to a
// human-readable dimension descriptor. Isolating it behind a single module
// level seam means swapping in the SDK Wave 2 scope registry is a one-line
// dependency change, and no scope-label string-building leaks into the
// contract itself.
//
// The descriptor is a faithful projection of the scope token. It carries no
// independent meaning the scope does not already carry, so the rendered
// summary cannot describe authority the machine scope does not grant.

/** A faithful, human-readable projection of one scope token. */
export interface ScopeDimension {
  /** The exact scope token this dimension was derived from. */
  scope: string
  /** Human-readable label for the scope token. */
  label: string
  /** The dimension family (first segment of the token). */
  dimension: string
  /** Human-readable description of what the token authorizes. */
  description: string
}

/** Signature of a scope-dimension lookup. The SDK Wave 2 registry conforms. */
export type RenderScopeDimension = (scope: string) => ScopeDimension

// TODO(W2-C1): replace this passthrough with the SDK Wave 2 scope registry
// (faithful scope-dimension rendering). Until that primitive ships, the
// descriptor is an identity projection of the token: label and description
// echo the scope verbatim and the dimension is the leading segment. This
// guarantees the rendered summary never claims more than the scope holds.
const passthroughRenderScopeDimension: RenderScopeDimension = (scope) => {
  const trimmed = (scope ?? '').trim()
  const dimension = trimmed.split(':')[0] || trimmed
  return {
    scope: trimmed,
    label: trimmed,
    dimension,
    description: trimmed,
  }
}

// The single injectable seam. Tests and the Wave 2 wiring swap this; the
// contract code reads it through getRenderScopeDimension() only.
let _renderScopeDimension: RenderScopeDimension = passthroughRenderScopeDimension

/** The active scope-dimension renderer. The contract derives its summary from this. */
export function getRenderScopeDimension(): RenderScopeDimension {
  return _renderScopeDimension
}

/**
 * Inject a scope-dimension renderer (the SDK Wave 2 registry, or a test
 * double). Returns a restore function so callers can revert the seam.
 */
export function setRenderScopeDimension(fn: RenderScopeDimension): () => void {
  const previous = _renderScopeDimension
  _renderScopeDimension = fn
  return () => { _renderScopeDimension = previous }
}

/** The default identity renderer, exported for tests asserting passthrough fidelity. */
export { passthroughRenderScopeDimension }
