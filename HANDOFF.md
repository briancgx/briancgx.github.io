# HANDOFF.md — Reescritura del Sitio Personal de briancgx (Astro + Tailwind)

## 📌 Resumen de Ejecución (Agente 1 — Antigravity)
El Agente 1 (Antigravity) ha preparado el terreno base, scaffold del proyecto Astro, limpieza del legacy Jekyll, migración de contenidos y activos, configuración de CI/CD para GitHub Pages y verificación completa de compilación (`npm run build`).

---

## 🛠️ Stack y Entorno Configurado
- **Framework:** Astro v5 (modo `static`) + TypeScript en modo `strict`.
- **Estilos:** Tailwind CSS v3 con directivas `@tailwind` en `src/styles/global.css`.
- **Syntax Highlighting:** `astro-expressive-code` con marcos de terminal y botones de copiado.
- **Buscador:** `pagefind` integrado en el pipeline de build estático.
- **Integraciones Astro:** `@astrojs/tailwind`, `@astrojs/react`, `@astrojs/sitemap`, `@astrojs/rss`, `astro-expressive-code`.
- **Dominio:** `briancgx.me` preservado en `CNAME` y `public/CNAME`.
- **Rama Git de trabajo:** `astro-rewrite` (NO mergeada a `main`).

---

## 📂 Estructura de Archivos y Stubs Creados

### 1. Configuración y Tooling
- `astro.config.mjs`: Integraciones de Tailwind, React, Sitemap, Expressive Code y configuración de `site: "https://briancgx.me"`.
- `tailwind.config.mjs`: Configuración base de Tailwind con soporte para modo oscuro (`class`).
- `ec.config.mjs`: Configuración de Expressive Code con tema oscuro tipo terminal/hacker.
- `tsconfig.json`: Modo estricto con alias de ruta `@/*` -> `src/*`.
- `.github/workflows/deploy.yml`: Pipeline de CI/CD para GitHub Pages (checkout -> setup-node -> npm ci -> build -> pagefind -> preservación de CNAME -> deploy).

### 2. Contenido Migrado (`src/content/`)
- `src/content/config.ts`: Colección `writeups` tipada con Zod (`title`, `slug`, `date`, `platform`, `difficulty`, `lang`, `tags`, `machine_image`, `excerpt`, `draft`).
- `src/content/writeups/2024-06-22-dockerlabs-writeup-grandma.md`: Writeup de máquina *Grandma* (Dockerlabs, dificultad *hard*, idioma *es*, tags de pivoting/tunneling/LFI, imágenes enlazadas a `/assets/...`).
- `src/content/writeups/2024-06-22-dockerlabs-writeup-trust.md`: Writeup de máquina *Trust* (Dockerlabs, dificultad *easy*, idioma *en*, imágenes enlazadas a `/assets/...`).

### 3. Layouts (`src/layouts/`)
- `src/layouts/Base.astro`: Layout base minimalista con etiquetas Open Graph / SEO, meta tags canónicos, dark mode y estructura semántica (Header/Nav, Main, Footer).
- `src/layouts/Writeup.astro`: Layout para artículos técnicos con metadata badges (plataforma, dificultad, fecha, tags) y ranura para contenido de Markdown.

### 4. Páginas y Rutas (`src/pages/`)
- `src/pages/index.astro`: Página de inicio (Stub listo para Hero y Writeups recientes).
- `src/pages/writeups/index.astro`: Catálogo de writeups con buscador y filtros facetados.
- `src/pages/writeups/[slug].astro`: Renderizado dinámico de posts mediante Content Collections de Astro.
- `src/pages/about.astro`: Página de perfil y botón de descarga de CV.
- `src/pages/challenge.astro`: Página del reto interactivo de Prompt Injection.
- `src/pages/tags/[tag].astro`: Listado de writeups filtrados dinámicamente por etiqueta.
- `src/pages/rss.xml.ts`: Endpoint de feed RSS con metadatos de los writeups.

### 5. Componentes Stubs (`src/components/`)
- `src/components/hero/Hero.astro`: Stub de sección Hero.
- `src/components/catalog/CatalogFilter.astro`: Stub de filtros facetados (Plataforma, Dificultad, Tags).
- `src/components/search/SearchBar.astro`: Stub de buscador / Pagefind / Command Palette.
- `src/components/writeup/WriteupCard.astro`: Stub de tarjeta de previsualización de writeup.
- `src/components/challenge/ChallengeBox.astro`: Stub de caja interactiva para reto de IA.

### 6. Activos Públicos (`public/`)
- `public/assets/images/`: Imágenes migradas de máquinas Dockerlabs, HTB, logos y avatar (`ig.jpg`).
- `public/cv/briancgx-cv.pdf`: Archivo PDF placeholder para el CV.
- `public/CNAME`: Archivo CNAME con `briancgx.me`.

### 7. Backend Proxy del Reto (`backend-agent/`)
- `backend-agent/Dockerfile`: Imagen base de Node 22 para ejecución en contenedor.
- `backend-agent/server.js`: Servidor HTTP base (stub) para proxy de LLM.
- `backend-agent/.env.example`: Plantilla de variables de entorno para API keys y flags del reto.

---

## 🚦 Verificación de Compilación
El comando `npm run build` se ejecutó exitosamente:
```text
13 page(s) built in 21.05s
Pagefind indexed 13 pages and wrote index to dist/pagefind
Build complete! All routes, static assets, RSS feed and sitemaps generated without errors.
```

---

## 📋 Lista de Tareas para el Agente 2 (Claude)
1. **Diseño Visual & UX:**
   - Implementar el diseño visual en modo oscuro con la estética ciberseguridad / hacker (JetBrains Mono / Inter, acentos neón controlados / verde esmeralda / cian, borders sutiles).
   - Desarrollar la sección Hero (`src/components/hero/Hero.astro`) con animación de consola o terminal interactiva.
2. **Interactividad & Componentes React / Astro:**
   - Implementar el filtrado facetado interactivo en el catálogo (`src/components/catalog/CatalogFilter.astro`).
   - Implementar la Command Palette / buscador instantáneo (`Ctrl+K` / `Cmd+K`) usando Pagefind.
   - Enriquecer `src/layouts/Writeup.astro` con Tabla de Contenidos (TOC) interactiva, tiempo estimado de lectura y breadcrumbs.
   - Implementar el componente del reto de IA en `src/components/challenge/ChallengeBox.astro` (interfaz de chat/terminal para probar Prompt Injection).
3. **Página About & Perfil:**
   - Maquetar la página `src/pages/about.astro` con biografía, badges de certificaciones (HTB CyberGh0st, eCPPT, etc.) y enlace al CV.
4. **Backend del Reto (Opcional):**
   - Completar la lógica de llamada al modelo LLM con protección de system prompt en `backend-agent/server.js`.

---

## 🔒 Nota para el Agente 3 (Grok)
- Realizar la auditoría de seguridad final (cabeceras de seguridad, Content Security Policy, sanitización de inputs en el reto de IA, revisión de enlaces e imágenes).
- Optimizar rendimiento y pulir micro-interacciones.
