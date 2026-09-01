/**
 * Rough reading-time estimate from raw markdown body.
 * Strips code fences and image/link syntax so counts reflect prose.
 */
export function readingTime(markdown: string): number {
  const text = markdown
    .replace(/```[\s\S]*?```/g, ' ') // fenced code
    .replace(/`[^`]*`/g, ' ') // inline code
    .replace(/!\[[^\]]*\]\([^)]*\)/g, ' ') // images
    .replace(/\[[^\]]*\]\([^)]*\)/g, ' '); // links
  const words = text.split(/\s+/).filter(Boolean).length;
  return Math.max(1, Math.round(words / 200));
}
