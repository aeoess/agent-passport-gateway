// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Sink-side APS verifier - public surface
// ══════════════════════════════════════════════════════════════════
// Two-sided enforcement: the gateway pre-check is one gate; the SINK
// (the receiving API) verifies the APS receipt before it accepts the
// action, so the pre-check is not the only gate.
//
// Trust is pushed to the edge. Every export here runs OFFLINE: the
// receiving API verifies against keys it already holds, with no callback
// to the gateway. The verifier composes installed SDK primitives; the
// Wave 2 relying-party verifier is stubbed at a single seam in
// verifier.ts (// TODO(W2-C2)).
//
//   verifySinkOffline           - the core drop-in verifier
//   expressSinkVerifier         - Express reference middleware
//   installBypassGuard          - Express defense-in-depth bypass guard
//   fastifySinkVerifier         - Fastify reference preHandler
//   createInternalSinkVerifier  - internal-HTTP-sink verifier
//   MemoryBypassSink            - default bounded bypass-trail log
// ══════════════════════════════════════════════════════════════════

export {
  verifySinkOffline,
  type SinkTrustSet,
  type SinkAction,
  type SinkVerdict,
} from './verifier.js'

export {
  MemoryBypassSink,
  bypassEventFromVerdict,
  type BypassSink,
  type BypassEvent,
  type BypassReason,
} from './bypass-log.js'

export {
  expressSinkVerifier,
  installBypassGuard,
  SINK_VERIFIED_MARKER,
  type ExpressSinkOptions,
} from './middleware-express.js'

export {
  fastifySinkVerifier,
  FASTIFY_SINK_VERIFIED_KEY,
  type FastifySinkOptions,
  type FastifyLikeRequest,
  type FastifyLikeReply,
} from './middleware-fastify.js'

export {
  createInternalSinkVerifier,
  type InternalSinkOptions,
  type InternalSinkVerifier,
  type InternalKeyStore,
  type InlineKeyStore,
  type FetchedKeyStore,
} from './internal-http-sink.js'
