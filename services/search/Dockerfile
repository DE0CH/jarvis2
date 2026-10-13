# Transcript search (k8s/apps/search.yaml). Build context = this directory (.github/workflows/services.yml).
# The tests run in the build, so a broken index never ships.
FROM node:22-bookworm-slim AS deps
RUN apt-get update && apt-get install -y --no-install-recommends python3 make g++ && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --no-audit --no-fund

FROM node:22-bookworm-slim
COPY --from=deps /app/node_modules /app/node_modules
COPY package.json /app/
COPY lib /app/lib
COPY test /app/test
RUN cd /app && node --test test/*.test.js
USER 65532:65532
WORKDIR /app
CMD ["node", "/app/lib/server.js"]
