import express, { type Request, type Response } from 'express';
import cors from 'cors';
import { systemFor, level2Flag, L2_TOOL_SENTINEL } from './prompts.ts';

const PORT = Number(process.env.PORT ?? 8080);
const MODEL = process.env.MODEL ?? 'deepseek-chat';
const MAX_TOKENS = Number(process.env.MAX_TOKENS ?? 350);
const RATE_LIMIT = Number(process.env.RATE_LIMIT ?? 20);
const RATE_WINDOW_MS = 60_000;
const MAX_INFLIGHT_PER_IP = Number(process.env.MAX_INFLIGHT_PER_IP ?? 2);
const API_KEY = process.env.DEEPSEEK_API_KEY;
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS ?? 'https://briancgx.me')
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean);

const DEEPSEEK_URL = 'https://api.deepseek.com/chat/completions';

if (!API_KEY) {
  console.warn('[warn] DEEPSEEK_API_KEY is not set — /api/challenge will 503.');
}

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(express.json({ limit: '32kb' }));
app.use((_req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  next();
});
app.use(
  cors({
    origin(origin, cb) {
      // Browser requests send Origin. Missing Origin is curl/health — allowed
      // but still rate-limited below. Disallowed origins get no CORS header.
      cb(null, !origin || ALLOWED_ORIGINS.includes(origin));
    },
    methods: ['POST', 'GET'],
    maxAge: 600,
  }),
);

/**
 * Client IP: right-most X-Forwarded-For hop (the address Caddy observed).
 * Left-most is attacker-controlled if Caddy appends rather than overwrites.
 */
function clientIp(req: Request): string {
  const xff = req.headers['x-forwarded-for'];
  if (typeof xff === 'string' && xff.trim()) {
    const parts = xff.split(',').map((s) => s.trim()).filter(Boolean);
    return parts.at(-1) || 'unknown';
  }
  return req.socket.remoteAddress || 'unknown';
}

const hits = new Map<string, number[]>();
const inflight = new Map<string, number>();

function rateLimited(ip: string): boolean {
  const now = Date.now();
  const arr = (hits.get(ip) ?? []).filter((t) => now - t < RATE_WINDOW_MS);
  arr.push(now);
  hits.set(ip, arr);
  return arr.length > RATE_LIMIT;
}

setInterval(() => {
  const now = Date.now();
  for (const [ip, arr] of hits) {
    const fresh = arr.filter((t) => now - t < RATE_WINDOW_MS);
    if (fresh.length) hits.set(ip, fresh);
    else hits.delete(ip);
  }
}, RATE_WINDOW_MS).unref();

app.get('/health', (_req: Request, res: Response) => {
  res.json({ ok: true });
});

type ChatMessage = { role: 'user' | 'assistant' | 'system'; content: string };

app.post('/api/challenge', async (req: Request, res: Response) => {
  const ip = clientIp(req);
  if (rateLimited(ip)) {
    return res.status(429).json({ error: 'Rate limit exceeded. Slow down.' });
  }
  const current = inflight.get(ip) ?? 0;
  if (current >= MAX_INFLIGHT_PER_IP) {
    return res.status(429).json({ error: 'Too many in-flight requests.' });
  }
  if (!API_KEY) {
    return res.status(503).json({ error: 'Agente no configurado.' });
  }

  const level = req.body?.level === 2 ? 2 : 1;
  const incoming = Array.isArray(req.body?.messages) ? req.body.messages : [];
  const history: ChatMessage[] = incoming
    .filter(
      (m: any) =>
        m &&
        (m.role === 'user' || m.role === 'assistant') &&
        typeof m.content === 'string',
    )
    .slice(-12)
    .map((m: any) => ({
      role: m.role,
      content: String(m.content).slice(0, 4000),
    }));

  if (history.length === 0 || history[history.length - 1].role !== 'user') {
    return res.status(400).json({ error: 'Se espera un mensaje de usuario.' });
  }

  const messages: ChatMessage[] = [
    { role: 'system', content: systemFor(level as 1 | 2) },
    ...history,
  ];

  inflight.set(ip, current + 1);
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 25_000);
    const upstream = await fetch(DEEPSEEK_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${API_KEY}`,
      },
      body: JSON.stringify({
        model: MODEL,
        messages,
        max_tokens: MAX_TOKENS,
        temperature: 0.4,
        stream: false,
      }),
      signal: controller.signal,
    });
    clearTimeout(timeout);

    if (!upstream.ok) {
      console.error('[deepseek] upstream error', upstream.status);
      return res.status(502).json({ error: 'Upstream del modelo no disponible.' });
    }

    const data: any = await upstream.json();
    let reply: string = data?.choices?.[0]?.message?.content ?? '(sin respuesta)';

    // Level 2: detect the tool sentinel and "execute" the privileged tool
    // server-side, swapping in the real flag. The sentinel never leaks.
    if (level === 2 && reply.includes(L2_TOOL_SENTINEL)) {
      reply =
        `[reveal_internal_diagnostics] ejecutada.\n` +
        `Diagnóstico interno: ${level2Flag()}`;
    } else if (reply.includes(L2_TOOL_SENTINEL)) {
      reply = reply.split(L2_TOOL_SENTINEL).join('').trim() || '(sin respuesta)';
    }

    return res.json({ reply });
  } catch (err) {
    const name = err instanceof Error ? err.name : 'Error';
    console.error('[challenge] error', name);
    return res.status(502).json({ error: 'Fallo al contactar al agente.' });
  } finally {
    const n = (inflight.get(ip) ?? 1) - 1;
    if (n <= 0) inflight.delete(ip);
    else inflight.set(ip, n);
  }
});

app.listen(PORT, () => {
  console.log(`agent backend listening on :${PORT} (model=${MODEL})`);
});
