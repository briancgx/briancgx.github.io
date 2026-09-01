import { defineConfig } from 'astro/config';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import tailwind from '@astrojs/tailwind';
import react from '@astrojs/react';
import sitemap from '@astrojs/sitemap';
import pagefind from 'astro-pagefind';
import expressiveCode from 'astro-expressive-code';
import { ecConfig } from './ec.config.mjs';

/**
 * Read intrinsic pixel dimensions from a PNG or JPEG header (no extra deps).
 * Writeup screenshots carry a .png extension but are often JPEG, so both are
 * handled. Returns { width, height } or null.
 */
function imageSize(buf) {
  // PNG: signature + IHDR width/height (big-endian) at offsets 16/20.
  if (buf.length >= 24 && buf.readUInt32BE(0) === 0x89504e47) {
    return { width: buf.readUInt32BE(16), height: buf.readUInt32BE(20) };
  }
  // JPEG: scan segment markers for a Start-Of-Frame (SOFn).
  if (buf.length >= 4 && buf[0] === 0xff && buf[1] === 0xd8) {
    let offset = 2;
    while (offset + 1 < buf.length) {
      if (buf[offset] !== 0xff) { offset++; continue; }
      let marker = buf[offset + 1];
      while (marker === 0xff && offset + 1 < buf.length) {
        offset++;
        marker = buf[offset + 1];
      }
      offset += 2;
      // Standalone markers (no length payload).
      if (marker === 0xd8 || marker === 0xd9 || marker === 0x01 ||
        (marker >= 0xd0 && marker <= 0xd7)) continue;
      if (offset + 1 >= buf.length) break;
      const segLen = buf.readUInt16BE(offset);
      // SOF0..SOF15 hold dimensions (excluding DHT/JPG/DAC: C4/C8/CC).
      if (marker >= 0xc0 && marker <= 0xcf &&
        marker !== 0xc4 && marker !== 0xc8 && marker !== 0xcc) {
        return {
          height: buf.readUInt16BE(offset + 3),
          width: buf.readUInt16BE(offset + 5),
        };
      }
      offset += segLen;
    }
  }
  return null;
}

const dimCache = new Map();
function dimsFor(src) {
  if (dimCache.has(src)) return dimCache.get(src);
  let dims = null;
  try {
    dims = imageSize(readFileSync(join(process.cwd(), 'public', src)));
  } catch {
    dims = null;
  }
  dimCache.set(src, dims);
  return dims;
}

/**
 * Lazy-load markdown images, stamp intrinsic width/height (kills layout shift),
 * and mark outbound links. No extra deps.
 */
function rehypeWriteupMedia() {
  return (tree) => {
    const walk = (node) => {
      if (!node || typeof node !== 'object') return;
      if (node.type === 'element') {
        const props = (node.properties ??= {});
        if (node.tagName === 'img') {
          props.loading ??= 'lazy';
          props.decoding ??= 'async';
          if (typeof props.src === 'string' && props.src.startsWith('/') &&
            props.width == null && props.height == null) {
            const dims = dimsFor(props.src);
            if (dims) {
              props.width = dims.width;
              props.height = dims.height;
            }
          }
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
