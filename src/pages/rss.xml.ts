import rss from '@astrojs/rss';
import type { APIContext } from 'astro';
import { getWriteups, writeupHref } from '@/lib/writeups';
import { SITE } from '@/consts';

export async function GET(context: APIContext) {
  const writeups = await getWriteups();
  return rss({
    title: `${SITE.title} — Writeups`,
    description: SITE.description,
    site: context.site ?? SITE.url,
    trailingSlash: false,
    items: writeups.map((w) => ({
      title: w.data.title,
      pubDate: w.data.date,
      description: w.data.excerpt,
      link: writeupHref(w),
      categories: [w.data.platform, w.data.difficulty, ...w.data.tags],
    })),
    customData: `<language>${SITE.lang}</language>`,
  });
}
