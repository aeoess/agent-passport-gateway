// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * Connector-routing seam for G-C1.
 *
 * G-C1 (connectors) is a separate branch (gw-c1-connectors) but it is STILL at
 * base 5ccdac7: there is NO src/gateway/connectors/ surface to read yet. So per
 * the build directive we define a MINIMAL local interface and fall back to the
 * existing notification paths (sendEmail / coordination task lifecycle) until C1
 * lands. We never assume the C1 module exists.
 *
 * TODO(G-C1 / gw-c1-connectors): route alert/ticket via the connector registry.
 *   Replace `defaultConnectorRouter` with the real registry-backed router that
 *   resolves a target (Slack, PagerDuty, Jira, ...) to a connector and delivers.
 *   The `ConnectorRouter` interface below is the seam; the swap is mechanical.
 */

/** Minimal connector-router interface. C1 will provide a registry-backed impl. */
export interface ConnectorRouter {
  route(target: string, payload: Record<string, unknown>): Promise<{ delivered: boolean; via: string }>
}

/**
 * Default router used until C1 lands. It does NOT itself deliver to external
 * connectors (none exist yet); it reports the fallback channel the caller should
 * use (email for alerts, coordination task for tickets). The automation layer
 * uses this verdict to choose its existing-surface fallback. No external call,
 * never throws.
 */
export const defaultConnectorRouter: ConnectorRouter = {
  async route(target, _payload) {
    // No connector registry yet. Signal "not delivered via connector" so the
    // caller falls back to sendEmail / coordinationRouter. via records intent.
    return { delivered: false, via: `fallback:${target}` }
  },
}

let _router: ConnectorRouter = defaultConnectorRouter

/** Swap the router (used by tests, and by C1 wiring once it lands). */
export function setConnectorRouter(router: ConnectorRouter): void {
  _router = router
}

export function getConnectorRouter(): ConnectorRouter {
  return _router
}
