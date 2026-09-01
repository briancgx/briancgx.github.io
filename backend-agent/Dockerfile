# Minimal runtime image for the agent proxy. Runs TypeScript directly via tsx.
FROM node:22-alpine

WORKDIR /app

# Install only runtime deps (express, cors, tsx). Dev types are not needed.
COPY package.json package-lock.json* ./
RUN npm install --omit=dev --no-audit --no-fund

COPY tsconfig.json ./
COPY src ./src

ENV NODE_ENV=production
ENV PORT=8080
EXPOSE 8080

# Basic container healthcheck against the /health endpoint.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://127.0.0.1:8080/health >/dev/null 2>&1 || exit 1

# Drop root.
USER node

CMD ["npm", "start"]
