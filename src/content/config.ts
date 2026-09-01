import { defineCollection, z } from 'astro:content';

const writeups = defineCollection({
  type: 'content',
  schema: z.object({
    title: z.string(),
    slug: z.string().optional(),
    date: z.coerce.date(),
    platform: z.enum(['htb', 'dockerlabs', 'tryhackme']),
    difficulty: z.enum(['easy', 'medium', 'hard', 'insane']),
    lang: z.enum(['es', 'en']),
    tags: z.array(z.string()).default([]),
    machine_image: z.string().optional(),
    excerpt: z.string(),
    draft: z.boolean().default(false),
  }),
});

export const collections = {
  writeups,
};
