import { defineConfig } from 'astro/config';
import tailwind from '@astrojs/tailwind';
import react from '@astrojs/react';
import sitemap from '@astrojs/sitemap';
import pagefind from 'astro-pagefind';
import expressiveCode from 'astro-expressive-code';
import { ecConfig } from './ec.config.mjs';

/** Lazy-load markdown images and mark outbound links. No extra deps. */
function rehypeWriteupMedia() {
  return (tree) => {
    const walk = (node) => {
      if (!node || typeof node !== 'object') return;
      if (node.type === 'element') {
        const props = (node.properties ??= {});
        if (node.tagName === 'img') {
          props.loading ??= 'lazy';
          props.decoding ??= 'async';
        }
        if (node.tagName === 'a' && typeof props.href === 'string') {
          if (/^https?:/i.test(props.href)) {
            props.rel = 'noopener noreferrer';
            props.target = '_blank';
          }
        }
      }
      if (Array.isArray(node.children)) node.children.forEach(walk);
    };
    walk(tree);
  };
}

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
    rehypePlugins: [rehypeWriteupMedia],
  },
});
