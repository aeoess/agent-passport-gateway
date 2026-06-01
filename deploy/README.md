# In-tenant deployment (G-D4)

These artifacts deploy the AEOESS gateway INSIDE the customer's own
infrastructure, distinct from the hosted single-tenant Railway path defined
by the repository-root `Dockerfile` + `railway.json` (leave those untouched).

Three deployment shapes, one image:

| Path | Where it runs | Trust root | Cross-tenant signal |
| --- | --- | --- | --- |
| `docker/` | Customer VM / single node | Customer HSM or KMS, or gateway-generated | Opt-in, standard mode only |
| `helm/` | Customer Kubernetes cluster | Customer HSM or KMS via CSI/secret ref | Opt-in, standard mode only |
| `terraform/` | Customer cloud account (provisions the cluster + KMS key) | Customer KMS key (Terraform-managed) | Opt-in, standard mode only |
| `airgap/` | Disconnected appliance, no outbound network | Customer HSM, offline | Structurally impossible (no egress) |

## What the customer owns

The gateway is a THIN coordinator. Authority and verification live at the
edges:

- The customer brings their own trust root and signing key in their HSM or
  KMS. The gateway stores a reference and a fingerprint, never the private
  key. See `src/gateway/tenant-isolation/trust-root-seam.ts` (W2-B1 seam).
- The gateway stores only hashes and pointers, never PHI or raw sensitive
  payloads. See `src/gateway/tenant-isolation/hash-pointer-seam.ts` (W2-B6 seam).
- A regulated tenant runs in hard isolation: `ISOLATION_MODE=hard` and no
  cross-tenant code path is reachable.

## Isolation switch

Set `ISOLATION_MODE` at deploy time and the gateway seeds the tenant row
accordingly. `hard` is the default-safe value (D2 isolation-by-default). A
tenant can later move to `standard` and opt in to de-identified, aggregated,
above-k-floor cross-tenant signal, but only by an explicit, separately
audited transition.

## First pilot path

The recommended first deployment is a lower-risk INTERNAL workflow, for
example a developer agent that opens pull requests with no secrets and no
production deploy access. This is deliberately NOT live PHI on day one. The
hard-isolation and air-gapped shapes are validated against that pilot before
any regulated-data workload is onboarded.

## Claims

These artifacts support evidence for the customer's own audit. They do not
make the customer compliant. Assurance is verifier-derived from the receipts
and the customer-pinned trust root, never set by the gateway. The EU AI Act
and sector regulators increasingly require this kind of evidence; the
gateway helps the customer produce it.
