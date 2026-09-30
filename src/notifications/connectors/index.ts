// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// G-C1 Connectors - public surface (barrel)
// ══════════════════════════════════════════════════════════════════
// Extends src/notifications/ with connector + signed-webhook primitives,
// customer-run by default. The gateway EMITS through these sinks; customers run
// their own reaction logic. This is not a connector zoo of inbound automation:
// the single inbound path is the bounded Okta/Entra offboard -> revoke bridge.
// ══════════════════════════════════════════════════════════════════

// Versioned event schema
export {
  CONNECTOR_SCHEMA_VERSION,
  buildConnectorEvent,
  validateConnectorEvent,
} from './event-schema.js'
export type {
  ConnectorEvent,
  ConnectorEventType,
  ConnectorBatchRef,
  ConnectorSummaryMatrix,
} from './event-schema.js'

// The ONE adapter interface + canonicalizer
export { canonicalJson, ConnectorDeliveryError } from './connector.js'
export type { Connector, ConnectorKind, ConnectorSink } from './connector.js'

// Dispatcher (retry + dead-letter; thin seam over G-A1's EgressDispatcher)
export {
  ConnectorDispatcher,
  DEFAULT_RETRY_POLICY,
  backoffDelay,
  deadLetterCount,
  listDeadLetters,
} from './dispatcher.js'
export type { RetryPolicy, DeliveryResult } from './dispatcher.js'

// Endpoint registry + replay protection
export {
  registerEndpoint,
  listEndpoints,
  getEndpoint,
  deleteEndpoint,
  recordDeliveryOutcome,
  checkAndRecordNonce,
  DEFAULT_REPLAY_WINDOW_MS,
} from './subscription-store.js'
export type { WebhookEndpoint, RegisterEndpointInput, ReplayCheckResult } from './subscription-store.js'

// Signed webhook sink + reference verifier
export {
  buildSignedWebhook,
  verifyWebhookSignature,
  signWebhookHmac,
  webhookSigningString,
  makeWebhookSink,
  HDR_SIGNATURE,
  HDR_JWS,
  HDR_TIMESTAMP,
  HDR_NONCE,
  HDR_KEY_ID,
  HDR_SCHEMA,
} from './webhook-sink.js'
export type { SignedWebhookRequest, VerifyResult } from './webhook-sink.js'

// OCSF formatting
export { toOcsf, validateOcsf } from './ocsf.js'
export type { OcsfRecord } from './ocsf.js'

// Adapters
export { makeOtelOcsfSink, toOtlpLogs } from './adapters/otel-ocsf.js'
export { makeSlackSink, toSlackMessage } from './adapters/slack.js'
export { makeTeamsSink, toTeamsMessage } from './adapters/teams.js'
export { makeJiraSink, toJiraIssue } from './adapters/jira.js'
export { makeServiceNowSink, toServiceNowIncident } from './adapters/servicenow.js'
export { makePagerDutySink, toPagerDutyEvent } from './adapters/pagerduty.js'
export { makeInternalHttpSink } from './adapters/internal-http.js'
export { makeEmailSink, toEmail } from './adapters/email-sink.js'

// Inbound identity bridge
export {
  verifyInboundOffboard,
  applyOffboard,
  resolveTargetFromOffboard,
  getSdkRevokeByAgent,
} from './identity-bridge.js'
export type { IdentityProvider, NormalizedOffboard, OffboardOutcome } from './identity-bridge.js'

// G-A1 batch egress -> connector fan-out seam
export { batchToConnectorEvent, makeBatchEgressSink } from './batch-egress.js'

// Router + table bootstrap
export { connectorsRouter, mountInboundIdentityBridge } from './router.js'
export { initConnectorTables } from './init.js'
