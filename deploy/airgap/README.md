# Air-gapped deployment (G-D4)

For a tenant whose appliance has NO outbound network path. Cross-tenant
emission is structurally impossible because there is nowhere to emit to. This
is the strictest shape: a regulated tenant running fully disconnected.

## Pre-stage the image

Build on a connected host, then carry the image in:

```sh
# On a connected build host (context = repo root):
docker build -f deploy/docker/Dockerfile -t agent-passport-gateway:in-tenant .
docker save agent-passport-gateway:in-tenant -o agent-passport-gateway-in-tenant.tar

# Move agent-passport-gateway-in-tenant.tar onto the air-gapped appliance, then:
docker load -i agent-passport-gateway-in-tenant.tar
```

## Run disconnected

```sh
docker run -d \
  --name agent-passport-gateway \
  --network none \
  -v /srv/aeoess/data:/data \
  -e ISOLATION_MODE=hard \
  -e TRUST_ROOT_SOURCE=hsm \
  -e TRUST_ROOT_KEY_REF="pkcs11:slot=0;object=tenant-signer" \
  -e DB_PATH=/data/gateway.db \
  agent-passport-gateway:in-tenant
```

`--network none` removes the container's network entirely. The gateway still
serves locally on the appliance for in-cluster callers reached over a host
bridge if you instead use `--network host`; the point is no route to the
public internet exists.

## Getting audit evidence out

There is no Rekor anchor and no hosted export. Instead the gateway produces a
self-verifying air-gapped bundle via
`GET /api/v1/tenant-isolation/airgap-bundle?from=...&to=...`. The bundle
carries receipt HASHES only (never PHI or raw payloads) plus the gateway
JWKS, so an auditor's offline verifier can recompute every hash and check the
gateway signature WITHOUT contacting AEOESS. See
`src/gateway/tenant-isolation/airgap-bundle.ts`.

For a customer bring-your-own-root tenant, the verifier pins the customer
trust root rather than the bundled JWKS. Assurance is verifier-derived, never
set by the gateway.

## First pilot

Validate the air-gapped path on a lower-risk internal workflow first (e.g. a
developer agent opening pull requests, no secrets, no production deploy)
before any live PHI workload.
