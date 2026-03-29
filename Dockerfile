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
RUN npm run build && echo "Build completed at $(date)"

# Remove dev dependencies
RUN npm prune --production

# Railway sets PORT automatically
ENV PORT=3200
ENV DB_PATH=/data/gateway.db
ENV NODE_ENV=production

EXPOSE 3200

CMD ["node", "dist/server.js"]
