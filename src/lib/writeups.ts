import { getCollection, type CollectionEntry } from 'astro:content';
import { PLATFORM_LOGOS } from '@/consts';

export type Writeup = CollectionEntry<'writeups'>;

/** Card image: the writeup's own machine_image, else its platform logo. */
export function writeupImage(entry: Writeup): string | undefined {
  return entry.data.machine_image ?? PLATFORM_LOGOS[entry.data.platform];
}

/** URL slug for a writeup: frontmatter `slug` wins, else filename w/o ext. */
export function writeupSlug(entry: Writeup): string {
  // @ts-expect-error legacy content collections expose `.slug`
  const legacy = entry.slug as string | undefined;
  return legacy ?? entry.id.replace(/\.(md|mdx)$/i, '');
}

export function writeupHref(entry: Writeup): string {
  return `/writeups/${writeupSlug(entry)}`;
}

const published = ({ data }: Writeup) => !data.draft || import.meta.env.DEV;

/** All non-draft writeups, newest first. */
export async function getWriteups(): Promise<Writeup[]> {
  const all = await getCollection('writeups', published);
  return all.sort((a, b) => b.data.date.getTime() - a.data.date.getTime());
}

/** Unique, sorted tag list across published writeups. */
export async function getAllTags(): Promise<string[]> {
  const writeups = await getWriteups();
  const tags = new Set<string>();
  for (const w of writeups) w.data.tags.forEach((t) => tags.add(t));
  return [...tags].sort((a, b) => a.localeCompare(b));
}
