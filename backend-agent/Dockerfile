# backend-agent/Dockerfile
# TODO: Agent 2 (Claude) / Agent 3 (Grok) - Configure production container runtime for AI Challenge Proxy
FROM node:22-alpine

WORKDIR /app

COPY package*.json ./
# RUN npm ci --omit=dev

COPY . .

EXPOSE 3000
CMD ["node", "server.js"]
