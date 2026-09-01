# AUDIT.md — Agente 3 (Grok / xAI)

Auditoría de diseño, rendimiento, seguridad y accesibilidad sobre el rewrite
Astro en `astro-rewrite`. **No se hizo merge a `main`.** No se cambió la
arquitectura ni el naming de componentes que dejó Claude
(`AgenticConsole`, `CommandPalette`, `WriteupCatalog`, `ChallengeBox`, etc.).

`HANDOFF.md` no existía al arrancar (carrera Antigravity/Claude). Apareció
después, con instrucciones de identidad obsoletas; se corrigió esa línea.

---

## Resumen

El sitio ya expresa la identidad **briancgx · AI Security Researcher @ Straiker ·
Red Team Operator · MX**. El sistema de tokens (fondo `#0a0e14`, ops `#ff3b3b`,
IA `#22d3ee`, JetBrains Mono + Inter) está cableado. El chat del reto pinta
respuestas como texto React (sin `innerHTML`). La key de DeepSeek no viaja al
cliente.

Quedan decisiones de Brian (flags, HTB, CV, certs, WebP de writeups, React en
todas las páginas) y cabeceras HTTP reales (GitHub Pages no las sirve).

### Lighthouse (lab, Chromium headless, `astro preview`)

| Superficie | Perf | A11y | BP | SEO | Notas |
|---|---:|---:|---:|---:|---|
| Home desktop **antes** (1ª pasada Grok) | 100 | 95 | 100 | 100 | contraste Easy `text-ops/80`; `aria-label` ≠ texto visible |
| Home desktop **después** | **100** | **100** | **100** | **100** | FCP 0.4s · LCP 0.5s · CLS 0 · TBT 10ms |
| Home mobile **después** | **83** | **100** | — | — | TBT 650ms por hidratar React (`client.BlZe1zq3.js` 58 KiB gzip) en idle |
| Writeup Grandma desktop | **92** | **100** | **100** | **100** | LCP 1.4s, CLS 0.091, screenshots PNG sin `width`/`height` |

No hay métricas Lighthouse del Jekyll legacy ni del stub de Antigravity (no
era un sitio medible). El “antes” de bundle sí se midió sobre el `dist` de
Claude, justo antes de las correcciones de este agente.

### Bundle (home)

| | Antes (Claude, `dist` ~11 MB) | Después (Grok) |
|---|---|---|
| `dist/` | 11 MB | **9.3 MB** |
| Fuentes | Inter+JetBrains en latin/ext/cyrillic/greek/vietnamese | **solo latin** (48 KB + 40 KB) |
| React runtime en **todas** las páginas | 186.6 KB / 58.5 KB gzip | igual (CommandPalette `client:idle`) |
| ChallengeBox / WriteupCatalog | solo en sus rutas | igual |
| `/assets/certs`, CV placeholder | publicados | **fuera de `public/`** (`_pending/`) |

---

## Correcciones ya aplicadas (bajo riesgo)

### Identidad
- About ya no ofrece el PDF placeholder (“briancgx - CV Placeholder”). `SHOW_CV=false`.
- Certificaciones siguen ocultas (`SHOW_CERTS=false`). El catálogo público
  `public/assets/certs/` (incl. nombres oficiales con “Pentester” y
  `certs.json`) se movió a `_pending/certs/` para que no se sirva.
- `HANDOFF.md` ya no pide badges de un equipo antiguo ni certs inventadas.

### Diseño / micro-interacciones
- Dificultades y estados de éxito/error usan **solo** ops/IA. Se eliminó
  emerald/yellow de badges, flags, offline y semáforos macOS.
- Chrome C2 reducido a `c2://session` + `ACTIVE` (sin semáforo de plantilla).
- `Ctrl+K` en nav y SearchBar (Kali/Linux; Cmd sigue funcionando).
- Consola del hero: DOM (`textContent` / `replaceChildren`), sin `innerHTML`.
- `prefers-reduced-motion` en hero, barra de lectura y scroll del chat.

### Rendimiento
- Subset latin + `font-display: swap` (self-hosted, sin Google Fonts).
- `width`/`height` en thumbs de cards; `loading=lazy` + `decoding=async` en
  imágenes Markdown (rehype local, sin dep nueva).
- WriteupCatalog pasa de `client:load` a `client:idle`.
- Pagefind sigue diferido (solo se `import()` al abrir Ctrl+K).

### Seguridad
- Chat del reto: `{m.content}` como hijo de texto (escape de React). Límite
  2000 chars en el input.
- Enlaces externos: `rel="noopener noreferrer"` (footer, Markdown, HTB).
- CSP por **meta** (fallback GitHub Pages) + `public/_headers` (Cloudflare
  Pages / Netlify; GH Pages **ignora** este archivo) + snippet Caddy abajo.
- Referrer-Policy por meta.
- Backend: IP de rate-limit = **último** hop de `X-Forwarded-For`; cap de
  in-flight por IP (2); `/health` ya no filtra el modelo; errores no logean
  cuerpos ni el system prompt; Caddy debe **sobrescribir** `X-Forwarded-For`.
- Stub `backend-agent/server.js` (OpenAI) eliminado.

### Accesibilidad
- Contraste Easy: `text-ops` sólido (WCAG AA). Tokens medidos sobre `#0a0e14`:
  ops `#ff3b3b` **5.47:1** AA, cian `#22d3ee` **10.70:1** AAA, texto `#cdd7e5`
  **13.31:1**, muted `#7688a0` **5.34:1**.
- `aria-label` de cards y botón Buscar alineados con el texto visible.
- Command palette: `combobox`/`listbox`, `aria-activedescendant`, lock de
  scroll, Escape global.
- Skip link, `focus-visible`, TOC por teclado, filtros con `<fieldset>` +
  checkbox nativos.

---

## Hallazgos que siguen abiertos

### Crítico
Ninguno en el código actual. El reto **no está live** hasta desplegar
`backend-agent` con `DEEPSEEK_API_KEY` y flags reales.

### Alto

**H1 — React (186 KB / 58 KB gzip) en todas las páginas**  
CommandPalette es isla `client:idle` en `Base.astro` → hidrata React hasta
en home/about/writeup. Mobile TBT 650 ms; Lighthouse estima 34 KiB unused JS.
*Decisión:* reescribir la palette en vanilla (sin React) **o** cargar el
chunk solo al primer Ctrl+K. No lo hice: cambia el contrato de islas que
dejó Claude.

**H2 — Screenshots de writeups (≈8 MB PNG, muchos JPEG disfrazados de `.png`)**  
Grandma: 50 imágenes, LCP 1.4 s, CLS 0.091, `unsized-images`. Sin `srcset`/
WebP/AVIF ni dimensiones en Markdown. *Decisión:* pipeline de conversión
(WebP + widths) y plugin `rehype-img-size`. No toqué los binarios.

**H3 — Cabeceras HTTP reales**  
GitHub Pages no emite CSP / `X-Frame-Options` / `frame-ancestors`. El meta
CSP **no aplica** `frame-ancestors`. Hace falta Cloudflare (dominio proxied)
o Caddy si algún día se sirve desde la VPS. Snippets abajo.

**H4 — Rate-limit del reto es in-memory y bypasseable con proxies**  
20 req/IP/min + 2 in-flight. Un pool de IPs (VPN/Tor/rotating) multiplica
coste. Caddy **debe** picar `header_up X-Forwarded-For {http.request.remote.host}`
(si solo *appendea*, el leftmost era spoofable; ahora leemos el rightmost).
Varias réplicas no comparten el mapa. *Decisión:* `rate_limit` de Caddy y/o
Redis, y un techo global diario de tokens.

### Medio

**M1 — `npm audit` (sitio): 6 vulns (4 low, 2 high)**  
Astro 5.18.2 arrastra GHSA de XSS (`define:vars`, spread attrs, view
transitions, server islands) y `sharp`/libvips (build-time, OG canvas).
`npm audit fix --force` sube a **Astro 7** (breaking). En este código no se
usan `define:vars` con input de usuario, view transitions ni server islands.
esbuild GHSA es Windows-dev-only. *No forcé el upgrade.* Backend: 0 vulns.

**M2 — CI `deploy.yml` solo dispara en `main`**  
Correcto para no publicar `astro-rewrite`. Falta un job `pull_request` de
`build` sin deploy. El paso extra `npx pagefind --site dist` es redundante
(`astro-pagefind` ya indexa).

**M3 — CORS permite requests sin `Origin`**  
Necesario para curl/health. Un POST JSON “simple” no pasa el preflight, así
que un browser cross-origin no dispara el LLM. OK. No abrir `*` nunca.

**M4 — Flags placeholder en env**  
`FLAG{L1_TODO_...}` / `FLAG{L2_TODO_...}` si se despliega sin `.env` real.
El L2 sentinel vive solo en servidor.

**M5 — `astro-og-canvas` descarga Noto Sans de `api.fontsource.org` en el build**  
CI necesita red. No afecta al cliente.

**M6 — Favicon default de Astro** (cohete). Sustituir por un mark propio.

### Bajo

**L1 — `content/config.ts` usa la API legacy `type: 'content'`** (Astro 5 aún
la acepta). Migrar a `src/content.config.ts` + loader `glob` es cosmética.

**L2 — TOC no es un landmark en mobile** (hidden `lg:block`). Aceptable.

**L3 — Command palette sin focus trap Tab circular.** Escape + click-outside sí.

**L4 — `#0d121b` en consolas** no está en el mapa Tailwind; es un paso entre
`bg` y `surface`. Consistente visualmente.

**L5 — CSS del writeup (`_slug_.*.css` ~23 KB) se comparte en home.**

---

## Decisiones para Brian

1. **Certs** — En `_pending/certs/certs.json` hay CPTS, BSCP, eWPTX, C-AgAIPen,
   C-AI/MLPen, CRTeamer (hay notas locales de estudio). **CRTO no está en esa
   lista.** Confirma la lista real, luego `SHOW_CERTS=true` y mueve badges a
   `public/assets/certs/`. Los nombres de producto de SecOps Group contienen
   la palabra que no debe usarse como *rol* del sitio; si se publican, que
   sea como nombre oficial del badge, no como bio.
2. **CV** — PDF real → `public/cv/briancgx-cv.pdf` + `SHOW_CV=true`.
3. **HTB** — URL en `SOCIAL.htb` (ahora `HTB_PROFILE_URL`).
4. **Flags** del reto y tono.
5. **Email** — `contact@briancgx.me` (alternativa `hello@` no usada).
6. **Palette vanilla** vs vivir con React 58 KB gzip en mobile (H1).
7. **WebP/AVIF** de writeups (H2).
8. **Astro 7** en un PR aparte (M1), no en este branch.
9. **Cloudflare** delante de `briancgx.me`: ¿orange-cloud? Si sí, Transform
   Rules con el bloque de cabeceras. Si no, las metas son el único CSP.

---

## Cabeceras (tres sitios)

GitHub Pages **no** aplica `public/_headers`. El meta CSP en `Base.astro` cubre
script/style/img/font/connect; **no** cubre `frame-ancestors`.

### A) Meta (ya en el HTML, fallback GH Pages)

```
default-src 'self';
script-src 'self' 'unsafe-inline';   /* islas Astro + hero inline */
style-src 'self' 'unsafe-inline';    /* Tailwind + Expressive Code */
img-src 'self' data:;
font-src 'self';
connect-src 'self' https://agent.briancgx.me;
base-uri 'self'; form-action 'self'; object-src 'none'
```

`unsafe-inline` en script/style es el precio de islas Astro 5 sin nonces.
Pagefind se carga same-origin.

### B) Cloudflare Transform Rule (si el DNS está proxied) o `public/_headers`

Ver `public/_headers`. Añadir `frame-ancestors 'none'` aquí (sí funciona en
header HTTP). También: `X-Content-Type-Options: nosniff`,
`X-Frame-Options: DENY`, `Referrer-Policy: strict-origin-when-cross-origin`,
`Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=()`,
`Cross-Origin-Opener-Policy: same-origin`.

### C) Caddy — sitio estático (si algún día no es GH Pages)

```caddy
briancgx.me {
    encode zstd gzip
    root * /var/www/briancgx-me/site
    file_server
    header {
        Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
        X-Content-Type-Options "nosniff"
        X-Frame-Options "DENY"
        Referrer-Policy "strict-origin-when-cross-origin"
        Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
        Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self' https://agent.briancgx.me; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; object-src 'none'"
        -Server
    }
}
```

### D) Caddy — `agent.briancgx.me` (ya en `backend-agent/README.md`)

Importante: **overwrite** de `X-Forwarded-For`, no append. CSP
`default-src 'none'; frame-ancestors 'none'` en la API.

---

## Revisión ofensiva del reto

| Control | Estado |
|---|---|
| Key DeepSeek en el bundle | No. Solo `PUBLIC_AGENT_API` (URL). |
| Key en git | `.env` gitignored. `.env.example` tiene placeholder `sk-your-deepseek-key-here`. |
| XSS chat | Respuesta como text node. Pagefind excerpts se `stripHtml` y se pintan como texto. |
| CORS | Allowlist `https://briancgx.me`. Sin Origin = curl. |
| Rate-limit | Sliding window 20/min/IP (rightmost XFF) + 2 in-flight. Bypasses: IPs rotadas, IPv6 privacy, réplicas sin estado compartido. |
| max_tokens | 350. Historia ≤12 turnos × 4000 chars. Timeout 25s. Body JSON 32 KB. |
| System prompt en errores | No. Logs: status/nombre de error. |
| Health | `{ ok: true }` (ya no filtra el modelo). |
| L2 sentinel | Se sustituye server-side; no se envía al cliente. |

No ejecuté el contenedor contra DeepSeek (no hay key en este entorno).

---

## Verificación

- `npm run build` OK (14 páginas, Pagefind 14, OG, RSS, sitemap).
- Preview `http://127.0.0.1:4321`: `/` `/writeups/` `/about/` `/challenge/`
  `/writeups/dockerlabs-writeup-*` `/tags/linux/` `/rss.xml` `/robots.txt` → 200.
- Identidad correcta en HTML; 0 ocurrencias de los títulos prohibidos en
  `src/` y `dist/`.
- Lighthouse desktop home 100/100/100/100 **después** de contraste + labels.
- No hay herramientas de browser MCP aquí: la UI se verificó vía Lighthouse
  (contraste, names, CLS) + HTML de preview, no click-through humano.

Rama: `astro-rewrite`. Merge a `main` solo con tu OK.
