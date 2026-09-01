import { defineConfig } from 'astro/config';
import tailwind from '@astrojs/tailwind';
import react from '@astrojs/react';
import sitemap from '@astrojs/sitemap';
import pagefind from 'astro-pagefind';
import expressiveCode from 'astro-expressive-code';
import { ecConfig } from './ec.config.mjs';

// https://astro.build/config
export default defineConfig({
  site: 'https://briancgx.me',
  trailingSlash: 'ignore',
  build: {
    format: 'directory',
  },
  integrations: [
    // Expressive Code must run before the Markdown integration so it can
    // transform fenced code blocks into terminal-framed, copyable snippets.
    expressiveCode(ecConfig),
    tailwind({ applyBaseStyles: false }),
    react(),
    sitemap(),
    pagefind(),
  ],
  markdown: {
    // Expressive Code owns syntax highlighting; disable Astro's Shiki pass.
    syntaxHighlight: false,
  },
});
