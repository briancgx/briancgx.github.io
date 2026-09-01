import { useMemo, useState } from 'react';
import { PLATFORM_LABELS, DIFFICULTY_LABELS, DIFFICULTY_CLASS, LANG_LABELS } from '@/consts';

export type CatalogItem = {
  title: string;
  href: string;
  excerpt: string;
  platform: string;
  difficulty: string;
  lang: string;
  tags: string[];
  date: string; // ISO yyyy-mm-dd
  machine_image?: string;
};

const DIFFICULTY_ORDER = ['easy', 'medium', 'hard', 'insane'];

function toggle<T>(set: Set<T>, value: T): Set<T> {
  const next = new Set(set);
  next.has(value) ? next.delete(value) : next.add(value);
  return next;
}

function Chevron({ className = '' }: { className?: string }) {
  return (
    <svg
      viewBox="0 0 12 12"
      width="12"
      height="12"
      aria-hidden="true"
      className={className}
    >
      <path
        d="M2.5 4.5 6 8l3.5-3.5"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

export default function WriteupCatalog({ items }: { items: CatalogItem[] }) {
  const [platforms, setPlatforms] = useState<Set<string>>(new Set());
  const [difficulties, setDifficulties] = useState<Set<string>>(new Set());
  const [langs, setLangs] = useState<Set<string>>(new Set());
  const [tags, setTags] = useState<Set<string>>(new Set());
  // Mobile: the whole filter panel is collapsed by default so results show first.
  const [open, setOpen] = useState(false);

  // Facet option lists derived from the data (with counts).
  const facets = useMemo(() => {
    const count = (key: (i: CatalogItem) => string | string[]) => {
      const m = new Map<string, number>();
      for (const i of items) {
        const v = key(i);
        for (const val of Array.isArray(v) ? v : [v])
          m.set(val, (m.get(val) ?? 0) + 1);
      }
      return m;
    };
    return {
      platforms: count((i) => i.platform),
      difficulties: count((i) => i.difficulty),
      langs: count((i) => i.lang),
      tags: count((i) => i.tags),
    };
  }, [items]);

  const filtered = useMemo(() => {
    return items.filter((i) => {
      if (platforms.size && !platforms.has(i.platform)) return false;
      if (difficulties.size && !difficulties.has(i.difficulty)) return false;
      if (langs.size && !langs.has(i.lang)) return false;
      if (tags.size && !i.tags.some((t) => tags.has(t))) return false;
      return true;
    });
  }, [items, platforms, difficulties, langs, tags]);

  const activeCount =
    platforms.size + difficulties.size + langs.size + tags.size;

  const clearAll = () => {
    setPlatforms(new Set());
    setDifficulties(new Set());
    setLangs(new Set());
    setTags(new Set());
  };

  const sortedTags = [...facets.tags.entries()].sort((a, b) =>
    a[0].localeCompare(b[0]),
  );
  const sortedDiff = [...facets.difficulties.entries()].sort(
    (a, b) => DIFFICULTY_ORDER.indexOf(a[0]) - DIFFICULTY_ORDER.indexOf(b[0]),
  );

  return (
    <div className="grid gap-6 md:grid-cols-[15rem_1fr] md:gap-8">
      <div className="md:sticky md:top-4 md:self-start">
        {/* Mobile toggle — hidden on desktop where the panel is always shown. */}
        <button
          type="button"
          onClick={() => setOpen((o) => !o)}
          aria-expanded={open}
          className="flex w-full items-center justify-between rounded-lg border border-border bg-surface px-4 py-2.5 font-mono text-xs uppercase tracking-widest text-text md:hidden"
        >
          <span>
            <span className="text-ai">$</span> filtros
            {activeCount > 0 && <span className="text-ops"> ({activeCount})</span>}
          </span>
          <Chevron className={`transition-transform ${open ? 'rotate-180' : ''}`} />
        </button>

        <div
          className={`${open ? 'mt-3 block' : 'hidden'} space-y-2 md:mt-0 md:block`}
          aria-label="Filtros"
        >
          <div className="flex items-center justify-between px-1">
            <p className="hidden font-mono text-xs uppercase tracking-widest text-muted md:block">
              <span className="text-ai">$</span> filter
            </p>
            {activeCount > 0 && (
              <button
                type="button"
                onClick={clearAll}
                className="ml-auto font-mono text-xs text-ops hover:underline"
              >
                reset ({activeCount})
              </button>
            )}
          </div>

          <FacetGroup
            legend="Plataforma"
            options={[...facets.platforms.entries()]}
            selected={platforms}
            label={(k) => PLATFORM_LABELS[k] ?? k}
            onToggle={(k) => setPlatforms((s) => toggle(s, k))}
          />
          <FacetGroup
            legend="Dificultad"
            options={sortedDiff}
            selected={difficulties}
            label={(k) => DIFFICULTY_LABELS[k] ?? k}
            onToggle={(k) => setDifficulties((s) => toggle(s, k))}
          />
          <FacetGroup
            legend="Idioma"
            options={[...facets.langs.entries()]}
            selected={langs}
            label={(k) => LANG_LABELS[k] ?? k}
            onToggle={(k) => setLangs((s) => toggle(s, k))}
          />
          <FacetGroup
            legend="Tags"
            options={sortedTags}
            selected={tags}
            label={(k) => `#${k}`}
            onToggle={(k) => setTags((s) => toggle(s, k))}
            startOpen={false}
          />
        </div>
      </div>

      <section aria-live="polite">
        <p className="mb-4 font-mono text-xs text-muted">
          {filtered.length} de {items.length} writeups
        </p>
        {filtered.length === 0 ? (
          <p className="rounded-lg border border-border bg-surface p-8 text-center font-mono text-sm text-muted">
            Sin resultados con esos filtros.
          </p>
        ) : (
          <div className="grid gap-4 sm:grid-cols-2">
            {filtered.map((i) => (
              <article key={i.href} className="card group flex flex-col overflow-hidden">
                <a href={i.href} className="flex h-full flex-col">
                  <div className="flex items-center gap-3 border-b border-border bg-surface2/50 p-4">
                    {i.machine_image && (
                      <img
                        src={i.machine_image}
                        alt=""
                        width={40}
                        height={40}
                        loading="lazy"
                        decoding="async"
                        className="h-10 w-10 shrink-0 rounded object-contain"
                      />
                    )}
                    <div className="min-w-0">
                      <h3 className="truncate font-semibold text-text group-hover:text-ai">
                        {i.title}
                      </h3>
                      <time className="font-mono text-xs text-muted">[{i.date}]</time>
                    </div>
                  </div>
                  <div className="flex flex-1 flex-col gap-3 p-4">
                    <div className="flex flex-wrap items-center gap-2 font-mono text-xs">
                      <span className="badge border-ai/30 text-ai">
                        {PLATFORM_LABELS[i.platform] ?? i.platform}
                      </span>
                      <span
                        className={`badge ${DIFFICULTY_CLASS[i.difficulty] ?? 'text-text'}`}
                      >
                        {DIFFICULTY_LABELS[i.difficulty] ?? i.difficulty}
                      </span>
                      <span className="badge">{LANG_LABELS[i.lang] ?? i.lang}</span>
                    </div>
                    <p className="line-clamp-3 text-sm text-text/75">{i.excerpt}</p>
                    <div className="mt-auto flex flex-wrap gap-1.5 pt-1 font-mono text-xs text-muted">
                      {i.tags.slice(0, 4).map((t) => (
                        <span key={t}>#{t}</span>
                      ))}
                    </div>
                  </div>
                </a>
              </article>
            ))}
          </div>
        )}
      </section>
    </div>
  );
}

function FacetGroup({
  legend,
  options,
  selected,
  label,
  onToggle,
  startOpen = true,
}: {
  legend: string;
  options: [string, number][];
  selected: Set<string>;
  label: (key: string) => string;
  onToggle: (key: string) => void;
  startOpen?: boolean;
}) {
  if (options.length === 0) return null;
  const activeInGroup = options.filter(([k]) => selected.has(k)).length;
  return (
    <details
      open={startOpen}
      className="group rounded-lg border border-border bg-surface"
    >
      <summary className="flex cursor-pointer list-none items-center justify-between px-3 py-2 font-mono text-xs font-semibold text-text [&::-webkit-details-marker]:hidden">
        <span>
          {legend}
          {activeInGroup > 0 && (
            <span className="ml-1.5 text-ai">({activeInGroup})</span>
          )}
        </span>
        <Chevron className="text-muted transition-transform group-open:rotate-180" />
      </summary>
      <div className="space-y-0.5 border-t border-border p-1.5">
        {options.map(([key, n]) => {
          const on = selected.has(key);
          return (
            <label
              key={key}
              className={`flex cursor-pointer items-center justify-between gap-2 rounded px-2 py-1 font-mono text-xs transition-colors ${
                on ? 'bg-ai/10 text-ai' : 'text-muted hover:text-text'
              }`}
            >
              <span className="flex items-center gap-2">
                <input
                  type="checkbox"
                  checked={on}
                  onChange={() => onToggle(key)}
                  className="accent-ai"
                />
                {label(key)}
              </span>
              <span className="tabular-nums opacity-70">{n}</span>
            </label>
          );
        })}
      </div>
    </details>
  );
}
