import { OGImageRoute } from 'astro-og-canvas';
import { getWriteups, writeupSlug } from '@/lib/writeups';
import { SITE, PLATFORM_LABELS, DIFFICULTY_LABELS } from '@/consts';

const writeups = await getWriteups();

// Keyed by the route param (with `.png` so URLs end in .png).
const pages: Record<string, { title: string; description: string }> = {
  'default.png': {
    title: `${SITE.title} — Writeups & AI Security`,
    description: SITE.description,
  },
};

for (const w of writeups) {
  pages[`writeups/${writeupSlug(w)}.png`] = {
    title: w.data.title,
    description: `${PLATFORM_LABELS[w.data.platform] ?? w.data.platform} · ${
      DIFFICULTY_LABELS[w.data.difficulty] ?? w.data.difficulty
    } · ${w.data.lang.toUpperCase()}`,
  };
}

export const { getStaticPaths, GET } = OGImageRoute({
  param: 'route',
  pages,
  getImageOptions: (_path, page) => ({
    title: page.title,
    description: page.description,
    bgGradient: [
      [10, 14, 20],
      [16, 21, 31],
    ],
    border: { color: [34, 211, 238], width: 12, side: 'inline-start' },
    padding: 60,
    font: {
      title: {
        color: [205, 215, 229],
        size: 64,
        weight: 'Bold',
        lineHeight: 1.15,
      },
      description: {
        color: [118, 136, 160],
        size: 30,
        lineHeight: 1.4,
      },
    },
  }),
});
