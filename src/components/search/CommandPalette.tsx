import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { NAV, PLATFORM_LABELS, DIFFICULTY_LABELS } from '@/consts';

type WriteupItem = {
  title: string;
  href: string;
  platform: string;
  difficulty: string;
};

type Result = {
  id: string;
  title: string;
  href: string;
  hint?: string;
  kind: 'nav' | 'writeup' | 'search';
};

// Pagefind is generated at build time under /pagefind. Types are minimal.
type PagefindResult = {
  data: () => Promise<{
    url: string;
    meta: { title?: string };
    excerpt: string;
  }>;
};
type Pagefind = {
  search: (q: string) => Promise<{ results: PagefindResult[] }>;
  init?: () => Promise<void>;
};

let pagefindPromise: Promise<Pagefind | null> | null = null;
function loadPagefind(): Promise<Pagefind | null> {
  if (pagefindPromise) return pagefindPromise;
  pagefindPromise = (async () => {
    try {
      // Vite must not try to resolve this at build time.
      const mod = (await import(
        /* @vite-ignore */ `${import.meta.env.BASE_URL}pagefind/pagefind.js`
      )) as Pagefind;
      await mod.init?.();
      return mod;
    } catch {
      return null; // dev, or index not built yet → graceful fallback.
    }
  })();
  return pagefindPromise;
}

export default function CommandPalette({ items }: { items: WriteupItem[] }) {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState('');
  const [active, setActive] = useState(0);
  const [searchHits, setSearchHits] = useState<Result[]>([]);
  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLUListElement>(null);

  const staticResults = useMemo<Result[]>(() => {
    const nav: Result[] = NAV.map((n) => ({
      id: `nav:${n.href}`,
      title: n.label,
      href: n.href,
      hint: 'Navegación',
      kind: 'nav',
    }));
    const writeups: Result[] = items.map((w) => ({
      id: `wu:${w.href}`,
      title: w.title,
      href: w.href,
      hint: `${PLATFORM_LABELS[w.platform] ?? w.platform} · ${
        DIFFICULTY_LABELS[w.difficulty] ?? w.difficulty
      }`,
      kind: 'writeup',
    }));
    return [...nav, ...writeups];
  }, [items]);

  // Local fuzzy-ish filter over static entries.
  const filteredStatic = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return staticResults;
    return staticResults.filter(
      (r) =>
        r.title.toLowerCase().includes(q) ||
        (r.hint ?? '').toLowerCase().includes(q),
    );
  }, [query, staticResults]);

  const results = useMemo(() => {
    // De-dupe: a Pagefind body hit for a page already listed statically
    // is dropped in favor of the richer static entry.
    const seen = new Set(filteredStatic.map((r) => r.href));
    return [...filteredStatic, ...searchHits.filter((r) => !seen.has(r.href))];
  }, [filteredStatic, searchHits]);

  const close = useCallback(() => {
    setOpen(false);
    setQuery('');
    setSearchHits([]);
    setActive(0);
  }, []);

  // Global open triggers: Ctrl/Cmd+K and any [data-command-palette-open].
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        setOpen((v) => !v);
      } else if (e.key === 'Escape') {
        setOpen(false);
      }
    };
    const onClick = (e: MouseEvent) => {
      const t = (e.target as HTMLElement)?.closest?.(
        '[data-command-palette-open]',
      );
      if (t) {
        e.preventDefault();
        setOpen(true);
      }
    };
    window.addEventListener('keydown', onKey);
    window.addEventListener('click', onClick);
    return () => {
      window.removeEventListener('keydown', onKey);
      window.removeEventListener('click', onClick);
    };
  }, []);

  useEffect(() => {
    if (open) {
      loadPagefind();
      const prev = document.body.style.overflow;
      document.body.style.overflow = 'hidden';
      requestAnimationFrame(() => inputRef.current?.focus());
      return () => {
        document.body.style.overflow = prev;
      };
    }
  }, [open]);

  // Debounced Pagefind body search.
  useEffect(() => {
    const q = query.trim();
    if (!open || q.length < 2) {
      setSearchHits([]);
      return;
    }
    let cancelled = false;
    const t = setTimeout(async () => {
      const pf = await loadPagefind();
      if (!pf || cancelled) return;
      const { results: raw } = await pf.search(q);
      const top = await Promise.all(raw.slice(0, 6).map((r) => r.data()));
      if (cancelled) return;
      setSearchHits(
        top.map((d, i) => ({
          id: `pf:${d.url}:${i}`,
          title: d.meta.title ?? d.url,
          href: d.url,
          hint: stripHtml(d.excerpt),
          kind: 'search',
        })),
      );
    }, 160);
    return () => {
      cancelled = true;
      clearTimeout(t);
    };
  }, [query, open]);

  useEffect(() => {
    setActive(0);
  }, [query]);

  // Keep the active row scrolled into view.
  useEffect(() => {
    const el = listRef.current?.querySelector<HTMLElement>(
      `[data-idx="${active}"]`,
    );
    el?.scrollIntoView({ block: 'nearest' });
  }, [active]);

  const go = (r: Result | undefined) => {
    if (!r) return;
    window.location.href = r.href;
  };

  const onKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Escape') {
      e.preventDefault();
      close();
    } else if (e.key === 'ArrowDown') {
      e.preventDefault();
      setActive((a) => Math.min(a + 1, results.length - 1));
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      setActive((a) => Math.max(a - 1, 0));
    } else if (e.key === 'Enter') {
      e.preventDefault();
      go(results[active]);
    }
  };

  if (!open) return null;

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center p-4 pt-[12vh]"
      role="dialog"
      aria-modal="true"
      aria-label="Buscar y navegar"
    >
      <div
        className="absolute inset-0 bg-black/60 backdrop-blur-sm"
        onClick={close}
        aria-hidden="true"
      />
      <div
        className="relative w-full max-w-xl overflow-hidden rounded-lg border border-border bg-surface shadow-2xl shadow-black/50 animate-fade-in"
        onKeyDown={onKeyDown}
      >
        <div className="flex items-center gap-2 border-b border-border px-3">
          <span className="font-mono text-ai" aria-hidden="true">
            $
          </span>
          <input
            ref={inputRef}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Buscar writeups o navegar…"
            className="w-full bg-transparent py-3 font-mono text-sm text-text outline-none placeholder:text-muted"
            aria-label="Buscar"
            aria-controls="command-palette-list"
            aria-activedescendant={
              results[active] ? `command-palette-opt-${active}` : undefined
            }
            role="combobox"
            aria-expanded={true}
            aria-autocomplete="list"
            autoComplete="off"
            spellCheck={false}
          />
          <kbd className="rounded bg-surface2 px-1.5 py-0.5 font-mono text-[10px] text-muted">
            ESC
          </kbd>
        </div>

        <ul
          ref={listRef}
          id="command-palette-list"
          role="listbox"
          className="max-h-[50vh] overflow-y-auto py-1"
        >
          {results.length === 0 && (
            <li className="px-4 py-6 text-center font-mono text-sm text-muted">
              Sin resultados para “{query}”.
            </li>
          )}
          {results.map((r, i) => (
            <li
              key={r.id}
              id={`command-palette-opt-${i}`}
              data-idx={i}
              role="option"
              aria-selected={i === active}
            >
              <a
                href={r.href}
                onMouseEnter={() => setActive(i)}
                className={`flex items-center justify-between gap-3 px-4 py-2.5 text-sm ${
                  i === active ? 'bg-surface2' : ''
                }`}
              >
                <span className="flex min-w-0 items-center gap-2">
                  <span
                    className={`font-mono text-xs ${
                      r.kind === 'search' ? 'text-muted' : 'text-ai'
                    }`}
                    aria-hidden="true"
                  >
                    {r.kind === 'nav' ? '→' : r.kind === 'search' ? '⌕' : '#'}
                  </span>
                  <span className="min-w-0">
                    <span className="block truncate text-text">{r.title}</span>
                    {r.hint && (
                      <span className="block truncate font-mono text-xs text-muted">
                        {r.hint}
                      </span>
                    )}
                  </span>
                </span>
              </a>
            </li>
          ))}
        </ul>

        <div className="flex items-center justify-between border-t border-border px-4 py-2 font-mono text-[10px] text-muted">
          <span>↑↓ navegar · ↵ abrir · esc cerrar</span>
          <span className="text-ai">briancgx</span>
        </div>
      </div>
    </div>
  );
}

function stripHtml(html: string): string {
  return html.replace(/<[^>]+>/g, '').slice(0, 120);
}
