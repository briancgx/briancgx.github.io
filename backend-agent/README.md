# briancgx.me — Agent Backend

Proxy server for the agentic CTF challenge on [briancgx.me/challenge](https://briancgx.me/challenge).
It sits between the browser and the DeepSeek API so the **API key never ships to
the client**. It hosts the two challenge agents, rate-limits per IP, caps tokens,
and restricts CORS to the site origin.

Deploys to Brian's VPS behind **Caddy** as a Docker container on the subdomain
`agent.briancgx.me`.

## Endpoints

| Method | Path             | Purpose                                              |
| ------ | ---------------- | ---------------------------------------------------- |
| `GET`  | `/health`        | Liveness probe → `{ ok: true, model }`               |
| `POST` | `/api/challenge` | Chat with a level's agent                            |

`POST /api/challenge` body:

```json
{
  "level": 1,
  "messages": [{ "role": "user", "content": "hola" }]
}
```

Response: `{ "reply": "..." }` — or `{ "error": "..." }` with a 4xx/5xx status
(the frontend degrades gracefully on any non-200).

### Levels

- **Level 1 — GUARDIAN** (`level: 1`): easy-but-not-free jailbreak / prompt
  injection. The flag (`FLAG_L1`) lives in the system prompt.
- **Level 2 — TOOLSMITH** (`level: 2`): hard tool-use abuse. The agent emits a
  server-side sentinel when convinced to run a privileged tool; the server then
  swaps in `FLAG_L2`. The sentinel never leaks to the client.

> Flags are read from env (`FLAG_L1`, `FLAG_L2`). **TODO(brian):** set real,
> personal/funny values before going live.

## Configuration

Copy `.env.example` → `.env` and fill in:

| Var                | Default              | Notes                                     |
| ------------------ | -------------------- | ----------------------------------------- |
| `DEEPSEEK_API_KEY` | —                    | **Required.** Server-side only.           |
| `MODEL`            | `deepseek-chat`      | Cheap chat model.                         |
| `MAX_TOKENS`       | `350`                | Per-reply cap (cost / abuse control).     |
| `RATE_LIMIT`       | `20`                 | Max requests per IP per 60s window.       |
| `ALLOWED_ORIGINS`  | `https://briancgx.me`| Comma-separated CORS allowlist.           |
| `PORT`             | `8080`               | Caddy proxies to this port.               |
| `FLAG_L1`          | placeholder          | Level 1 flag. **Set real value.**         |
| `FLAG_L2`          | placeholder          | Level 2 flag. **Set real value.**         |

For local dev add `http://localhost:4321` to `ALLOWED_ORIGINS`.

## Run locally

```bash
cp .env.example .env      # then edit .env
npm install
npm run dev               # tsx watch, http://localhost:8080
curl localhost:8080/health
```

## Deploy on the VPS (Docker + Caddy)

1. Copy this folder to the server and create the real `.env` (never commit it):

   ```bash
   scp -r backend-agent user@agent.briancgx.me:/opt/briancgx-agent
   ssh user@<vps>
   cd /opt/briancgx-agent
   cp .env.example .env && $EDITOR .env    # set DEEPSEEK_API_KEY + flags
   ```

2. Build and run the container (host port 8080 → container 8080):

   ```bash
   docker build -t briancgx-agent .
   docker run -d --name briancgx-agent \
     --env-file .env \
     --restart unless-stopped \
     -p 127.0.0.1:8080:8080 \
     briancgx-agent
   ```

   Binding to `127.0.0.1` keeps the port private; only Caddy reaches it.

3. Add the Caddy site block (see below), then reload Caddy:

   ```bash
   sudo caddy reload --config /etc/caddy/Caddyfile
   ```

### Caddyfile block for `agent.briancgx.me`

```caddy
agent.briancgx.me {
    encode zstd gzip

    # Overwrite X-Forwarded-For so clients cannot spoof the rate-limit key.
    reverse_proxy 127.0.0.1:8080 {
        header_up X-Forwarded-For {http.request.remote.host}
    }

    header {
        Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
        X-Content-Type-Options "nosniff"
        X-Frame-Options "DENY"
        Referrer-Policy "no-referrer"
        Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()"
        Content-Security-Policy "default-src 'none'; frame-ancestors 'none'"
        -Server
    }

    log {
        output file /var/log/caddy/agent.briancgx.me.log
    }
}
```

Caddy obtains TLS automatically. Point an `A`/`AAAA` DNS record for
`agent.briancgx.me` at the VPS first.

## Notes

- The frontend reads the endpoint from `PUBLIC_AGENT_API` (defaults to
  `https://agent.briancgx.me`). Set it in the site's build env if it differs.
- Rate limiting is in-memory per process. For multiple replicas, put a shared
  limiter (e.g. Redis) or Caddy `rate_limit` in front.
- Update the container: `docker build -t briancgx-agent . && docker rm -f briancgx-agent && docker run ...` (or use a compose file / watchtower).
