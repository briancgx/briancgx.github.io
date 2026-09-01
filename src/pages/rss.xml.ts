// src/pages/rss.xml.ts
// TODO: Agent 2 (Claude) - Customize RSS feed items, categories, and full description metadata
import rss from '@astrojs/rss';
import { getCollection } from 'astro:content';
import type { APIContext } from 'astro';

export async function GET(context: APIContext) {
  const writeups = await getCollection('writeups', ({ data }) => !data.draft);
  return rss({
    title: 'briancgx - Cybersecurity Writeups',
    description: 'Personal cybersecurity portfolio & CTF writeups by briancgx',
    site: context.site ?? 'https://briancgx.me',
    items: writeups.map((post) => ({
      title: post.data.title,
      pubDate: post.data.date,
      description: post.data.excerpt,
      link: `/writeups/${post.slug || post.id.replace(/\.md$/, '')}/`,
    })),
  });
}
