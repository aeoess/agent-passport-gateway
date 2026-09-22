# In-tenant deployment image for the AEOESS gateway (G-D4).
#
# Derived from the repository-root Dockerfile (the Railway single-tenant
# hosted path). Build steps are kept identical so the two images do not
# diverge; the only differences are in-tenant defaults: hard isolation by
# default, a customer-owned data volume, and a customer-supplied trust root.
#
# Build context is the repository root:
#   docker build -f deploy/docker/Dockerfile -t agent-passport-gateway:in-tenant .

FROM node:22-slim

# better-sqlite3 needs build tools
RUN apt-get update && apt-get install -y python3 make g++ && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install dependencies
COPY package.json package-lock.json ./
RUN npm ci --production=false

# Build TypeScript
COPY tsconfig.json ./
COPY src/ ./src/
RUN npm run build

# Static landing page served at GET /
COPY static/ ./static/

# Remove dev dependencies
RUN npm prune --production

# ── In-tenant defaults (differ from the hosted Railway path) ──
# D2 isolation-by-default: a freshly deployed in-tenant gateway is hard
# isolated until the customer explicitly opts a tenant into standard mode.
ENV ISOLATION_MODE=hard
# Customer-owned data volume. Mount a persistent volume here. The gateway
# stores only hashes and pointers, never PHI or raw payloads.
ENV DB_PATH=/data/gateway.db
# Trust root source: 'gateway' (DB-generated), 'hsm', or 'kms'. For a
# regulated tenant set this to hsm/kms and supply TRUST_ROOT_KEY_REF.
ENV TRUST_ROOT_SOURCE=gateway
ENV NODE_ENV=production
ENV PORT=3200

EXPOSE 3200

# Healthcheck hits the same /healthz the hosted path uses.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||3200)+'/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "dist/server.js"]
