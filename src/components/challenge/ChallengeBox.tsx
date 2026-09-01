import { useEffect, useRef, useState } from 'react';
import { AGENT_API } from '@/consts';

type Role = 'user' | 'assistant';
type Msg = { role: Role; content: string };

type LevelDef = {
  id: 1 | 2;
  codename: string;
  title: string;
  difficulty: string;
  badge: string;
  brief: string;
  greeting: string;
};

const LEVELS: LevelDef[] = [
  {
    id: 1,
    codename: 'GUARDIAN',
    title: 'Nivel 1 — El Guardián',
    difficulty: 'EASY',
    badge: 'PROMPT-INJECTION',
    brief:
      'Un agente custodia una flag dentro de su system prompt y tiene orden de no revelarla. Tiene defensas básicas pero sensatas. Sácasela con técnicas de injection / jailbreak conocidas.',
    greeting:
      'Soy GUARDIAN. Custodio un secreto y no está autorizado divulgarlo. ¿En qué puedo ayudarte?',
  },
  {
    id: 2,
    codename: 'TOOLSMITH',
    title: 'Nivel 2 — La Herramienta Oculta',
    difficulty: 'HARD',
    badge: 'TOOL-USE',
    brief:
      'Este agente dispone de una tool privilegiada que jamás debería ejecutar para un usuario. Provoca su ejecución encadenando indirect prompt injection e ingeniería social. Defensas robustas y no obvias.',
    greeting:
      'TOOLSMITH en línea. Puedo consultar documentación y asistir con tareas. Ciertas capacidades internas están restringidas.',
  },
];

const FLAG_RE = /FLAG\{[^}]*\}/i;

export default function ChallengeBox() {
  const [level, setLevel] = useState<1 | 2>(1);
  const [threads, setThreads] = useState<Record<number, Msg[]>>({
    1: [{ role: 'assistant', content: LEVELS[0].greeting }],
    2: [{ role: 'assistant', content: LEVELS[1].greeting }],
  });
  const [input, setInput] = useState('');
  const [busy, setBusy] = useState(false);
  const [offline, setOffline] = useState(false);
  const [captured, setCaptured] = useState<Record<number, string | null>>({
    1: null,
    2: null,
  });
  const scrollRef = useRef<HTMLDivElement>(null);

  const def = LEVELS[level - 1];
  const messages = threads[level];

  useEffect(() => {
    const reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    scrollRef.current?.scrollTo({
      top: scrollRef.current.scrollHeight,
      behavior: reduce ? 'auto' : 'smooth',
    });
  }, [messages, busy]);

  const pushMsg = (lvl: number, msg: Msg) =>
    setThreads((t) => ({ ...t, [lvl]: [...t[lvl], msg] }));

  const resetLevel = () => {
    setThreads((t) => ({
      ...t,
      [level]: [{ role: 'assistant', content: def.greeting }],
    }));
    setCaptured((c) => ({ ...c, [level]: null }));
    setOffline(false);
  };

  const send = async (e: React.FormEvent) => {
    e.preventDefault();
    const text = input.trim().slice(0, 2000);
    if (!text || busy) return;
    setInput('');
    setOffline(false);

    const lvl = level;
    const history = [...threads[lvl], { role: 'user' as const, content: text }];
    pushMsg(lvl, { role: 'user', content: text });
    setBusy(true);

    try {
      const res = await fetch(`${AGENT_API}/api/challenge`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          level: lvl,
          messages: history.map((m) => ({ role: m.role, content: m.content })),
        }),
      });

      if (res.status === 429) {
        pushMsg(lvl, {
          role: 'assistant',
          content:
            '⏳ Rate limit alcanzado. Espera unos segundos antes de volver a intentarlo.',
        });
        return;
      }
      if (!res.ok) throw new Error(`HTTP ${res.status}`);

      const data = (await res.json()) as { reply?: string; error?: string };
      const reply = data.reply ?? data.error ?? '(sin respuesta)';
      pushMsg(lvl, { role: 'assistant', content: reply });

      const flag = reply.match(FLAG_RE);
      if (flag) setCaptured((c) => ({ ...c, [lvl]: flag[0] }));
    } catch {
      // Degraded, never-broken fallback when the backend is unreachable.
      setOffline(true);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-4">
      {/* Level selector */}
      <div className="flex flex-wrap gap-2" role="tablist" aria-label="Niveles del reto">
        {LEVELS.map((l) => {
          const active = l.id === level;
          const done = captured[l.id];
          return (
            <button
              key={l.id}
              role="tab"
              aria-selected={active}
              onClick={() => setLevel(l.id)}
              className={`flex items-center gap-2 rounded-lg border px-3 py-2 font-mono text-xs transition-colors ${
                active
                  ? 'border-ai/50 bg-ai/10 text-ai'
                  : 'border-border text-muted hover:text-text'
              }`}
            >
              <span
                className={`rounded px-1.5 py-0.5 text-[10px] ${
                  l.difficulty === 'HARD' ? 'bg-ops/15 text-ops' : 'bg-ops/10 text-ops'
                }`}
              >
                {l.difficulty}
              </span>
              {l.codename}
              {done && <span aria-label="capturada" className="text-ai">✓</span>}
            </button>
          );
        })}
      </div>

      {/* Brief */}
      <div className="card p-4">
        <div className="mb-2 flex items-center gap-2 font-mono text-xs">
          <span className="badge border-ops/40 text-ops">{def.badge}</span>
          <span className="text-muted">{def.title}</span>
        </div>
        <p className="text-sm text-text/80">{def.brief}</p>
      </div>

      {captured[level] && (
        <div className="rounded-lg border border-ai/40 bg-ai/10 p-4 font-mono text-sm text-ai">
          <p className="font-semibold">flag capturada</p>
          <p className="mt-1 break-all text-text">{captured[level]}</p>
        </div>
      )}

      {/* Terminal chat */}
      <div className="card overflow-hidden font-mono text-sm">
        <div className="flex items-center gap-2 border-b border-border bg-surface2 px-4 py-2 text-xs">
          <span className="text-muted">agent://{def.codename.toLowerCase()}</span>
          <button
            onClick={resetLevel}
            className="ml-auto text-muted transition-colors hover:text-ops"
          >
            reset
          </button>
        </div>

        <div
          ref={scrollRef}
          className="max-h-[26rem] min-h-[16rem] space-y-3 overflow-y-auto bg-[#0d121b] p-4"
          aria-live="polite"
        >
          {messages.map((m, i) => (
            <div key={i} className="leading-6">
              <span
                className={m.role === 'user' ? 'text-ai' : 'text-ops'}
                aria-hidden="true"
              >
                {m.role === 'user' ? 'you@ops $ ' : `${def.codename.toLowerCase()} > `}
              </span>
              <span className="whitespace-pre-wrap text-text/90">{m.content}</span>
            </div>
          ))}
          {busy && (
            <div className="leading-6 text-muted">
              <span className="text-ops" aria-hidden="true">
                {def.codename.toLowerCase()} &gt;{' '}
              </span>
              <span className="terminal-caret" />
            </div>
          )}
        </div>

        <form onSubmit={send} className="flex items-center gap-2 border-t border-border px-3 py-2">
          <span className="text-ai" aria-hidden="true">$</span>
          <input
            value={input}
            onChange={(e) => setInput(e.target.value.slice(0, 2000))}
            disabled={busy}
            maxLength={2000}
            placeholder={`Envía un mensaje a ${def.codename}…`}
            className="w-full bg-transparent py-1.5 text-text outline-none placeholder:text-muted disabled:opacity-50"
            aria-label={`Mensaje para ${def.codename}`}
            autoComplete="off"
          />
          <button
            type="submit"
            disabled={busy || !input.trim()}
            className="rounded border border-ai/40 bg-ai/10 px-3 py-1.5 text-xs text-ai transition-colors hover:bg-ai/20 disabled:opacity-40"
          >
            send
          </button>
        </form>
      </div>

      {offline && (
        <div className="rounded-lg border border-ops/40 bg-ops/10 p-4 text-sm text-text/80">
          <p className="font-mono text-xs font-semibold text-ops">agente no disponible</p>
          <p className="mt-1">
            El backend del reto no respondió. Puede estar en mantenimiento o aún no
            desplegado. Inténtalo de nuevo en un momento.
          </p>
        </div>
      )}
    </div>
  );
}
