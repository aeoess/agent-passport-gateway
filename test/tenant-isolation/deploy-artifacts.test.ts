// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// G-D4 - in-tenant deployment artifacts. Confirms the Helm / Terraform /
// Docker / air-gapped artifacts exist under deploy/, that the in-tenant
// image is hard-isolated by default and points at a customer-owned volume,
// and that the root Railway single-tenant path is left untouched (no
// semantic collision with the hosted Dockerfile).

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, existsSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'

const here = dirname(fileURLToPath(import.meta.url))
const repoRoot = join(here, '..', '..')

function read(rel: string): string {
  return readFileSync(join(repoRoot, rel), 'utf8')
}

describe('in-tenant deploy artifacts exist', () => {
  const required = [
    'deploy/README.md',
    'deploy/docker/Dockerfile',
    'deploy/docker/docker-compose.yml',
    'deploy/helm/agent-passport-gateway/Chart.yaml',
    'deploy/helm/agent-passport-gateway/values.yaml',
    'deploy/helm/agent-passport-gateway/templates/deployment.yaml',
    'deploy/helm/agent-passport-gateway/templates/service.yaml',
    'deploy/helm/agent-passport-gateway/templates/pvc.yaml',
    'deploy/helm/agent-passport-gateway/templates/networkpolicy.yaml',
    'deploy/terraform/main.tf',
    'deploy/airgap/README.md',
    'deploy/.env.example',
  ]
  for (const rel of required) {
    it(`has ${rel}`, () => {
      assert.ok(existsSync(join(repoRoot, rel)), `${rel} must exist`)
    })
  }
})

describe('in-tenant Docker image is isolation-by-default + customer-owned volume', () => {
  it('Dockerfile defaults ISOLATION_MODE=hard', () => {
    const df = read('deploy/docker/Dockerfile')
    assert.match(df, /ENV ISOLATION_MODE=hard/)
  })
  it('Dockerfile mounts a customer-owned data volume, not a hosted path', () => {
    const df = read('deploy/docker/Dockerfile')
    assert.match(df, /ENV DB_PATH=\/data\/gateway\.db/)
  })
  it('Dockerfile derives from node:22-slim like the root image (consistent build)', () => {
    assert.match(read('deploy/docker/Dockerfile'), /FROM node:22-slim/)
  })
})

describe('Helm chart carries the isolation + trust-root knobs', () => {
  it('values.yaml defaults isolation.mode to hard', () => {
    assert.match(read('deploy/helm/agent-passport-gateway/values.yaml'), /mode:\s*hard/)
  })
  it('deployment templates ISOLATION_MODE from values', () => {
    assert.match(read('deploy/helm/agent-passport-gateway/templates/deployment.yaml'), /ISOLATION_MODE/)
  })
  it('trust-root key reference comes from a Secret (not inline key material)', () => {
    assert.match(read('deploy/helm/agent-passport-gateway/templates/deployment.yaml'), /secretKeyRef/)
  })
})

describe('Terraform provisions a customer-owned KMS key as the trust root', () => {
  it('declares aws_kms_key with rotation and an isolation_mode variable', () => {
    const tf = read('deploy/terraform/main.tf')
    assert.match(tf, /resource "aws_kms_key" "tenant_trust_root"/)
    assert.match(tf, /enable_key_rotation\s*=\s*true/)
    assert.match(tf, /variable "isolation_mode"/)
  })
})

describe('root Railway single-tenant path is untouched (no collision)', () => {
  it('root Dockerfile still targets the hosted PORT/DB_PATH path', () => {
    const df = read('Dockerfile')
    assert.match(df, /FROM node:22-slim/)
    // Root image must NOT carry the in-tenant ISOLATION_MODE default; that
    // lives only under deploy/. This keeps the hosted path semantically
    // distinct from the in-tenant path.
    assert.ok(!/ENV ISOLATION_MODE/.test(df), 'root Dockerfile must not set ISOLATION_MODE')
  })
  it('railway.json still points at the root Dockerfile', () => {
    const rj = JSON.parse(read('railway.json'))
    assert.equal(rj.build.dockerfilePath, 'Dockerfile')
  })
})
