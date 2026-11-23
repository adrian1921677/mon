import { FormEvent, useCallback, useEffect, useMemo, useState } from "react";
import {
  createClient,
  type HealthResponse,
  type ProjectRead,
} from "./api/client";
import {
  getBackendInfo,
  isTauriRuntime,
  startBackend,
  type BackendInfo,
} from "./api/backend";

type ConnectionState = "checking" | "online" | "offline";

export default function App() {
  const [backend, setBackend] = useState<BackendInfo | null>(null);
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [connection, setConnection] = useState<ConnectionState>("checking");
  const [projects, setProjects] = useState<ProjectRead[]>([]);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const client = useMemo(
    () => createClient(backend?.baseUrl ?? undefined),
    [backend?.baseUrl],
  );

  const refresh = useCallback(async () => {
    setError(null);
    try {
      if (isTauriRuntime()) {
        const info = await getBackendInfo();
        setBackend(info);
        if (!info.running) {
          await startBackend();
          setBackend(await getBackendInfo());
        }
      } else {
        setBackend({
          running: true,
          host: "127.0.0.1",
          port: 8765,
          baseUrl: "http://127.0.0.1:8765",
          pid: null,
        });
      }

      const h = await client.health();
      setHealth(h);
      setConnection(h.status === "ok" ? "online" : "offline");
      const list = await client.listProjects();
      setProjects(list);
    } catch (err) {
      setConnection("offline");
      setHealth(null);
      setError(err instanceof Error ? err.message : String(err));
    }
  }, [client]);

  useEffect(() => {
    void refresh();
    const id = window.setInterval(() => void refresh(), 5000);
    return () => window.clearInterval(id);
  }, [refresh]);

  async function onCreate(e: FormEvent) {
    e.preventDefault();
    if (!name.trim()) return;
    setBusy(true);
    setError(null);
    try {
      await client.createProject({
        name: name.trim(),
        description: description.trim() || null,
      });
      setName("");
      setDescription("");
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  async function onDelete(id: string) {
    setBusy(true);
    setError(null);
    try {
      await client.deleteProject(id);
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  const statusLabel =
    connection === "online"
      ? "Backend online"
      : connection === "checking"
        ? "Prüfe Verbindung…"
        : "Backend offline";

  const statusColor =
    connection === "online"
      ? "var(--ok)"
      : connection === "checking"
        ? "var(--warn)"
        : "var(--danger)";

  return (
    <div className="min-h-screen px-6 py-5 md:px-10">
      <header className="mb-8 flex flex-wrap items-end justify-between gap-4 border-b border-[var(--line)] pb-5">
        <div>
          <p className="text-xs font-semibold tracking-[0.18em] text-[var(--muted)] uppercase">
            Local Security Platform
          </p>
          <h1 className="mt-1 text-3xl font-semibold tracking-tight text-[var(--ink)]">
            Hck
          </h1>
          <p className="mt-1 max-w-xl text-sm text-[var(--muted)]">
            Phase-1-Shell: lokales Backend auf 127.0.0.1, Projekte und Health-Check.
          </p>
        </div>
        <div className="rounded-md border border-[var(--line)] bg-[var(--panel)] px-4 py-3 shadow-sm">
          <div className="flex items-center gap-2 text-sm font-medium">
            <span
              className="inline-block h-2.5 w-2.5 rounded-full"
              style={{ background: statusColor }}
              aria-hidden
            />
            {statusLabel}
          </div>
          <dl className="mt-2 grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-xs text-[var(--muted)]">
            <dt>URL</dt>
            <dd className="font-mono text-[var(--ink)]">
              {backend?.baseUrl ?? "http://127.0.0.1:8765"}
            </dd>
            <dt>Version</dt>
            <dd>{health?.version ?? "—"}</dd>
            <dt>DB</dt>
            <dd>{health?.database ?? "—"}</dd>
            <dt>PID</dt>
            <dd>{backend?.pid ?? "extern / Dev"}</dd>
          </dl>
          <button
            type="button"
            onClick={() => void refresh()}
            className="mt-3 w-full rounded border border-[var(--line)] bg-white px-3 py-1.5 text-xs font-medium hover:bg-gray-50"
          >
            Erneut prüfen
          </button>
        </div>
      </header>

      {error ? (
        <div
          role="alert"
          className="mb-5 rounded border border-red-200 bg-red-50 px-4 py-3 text-sm text-[var(--danger)]"
        >
          {error}
          {!isTauriRuntime() && connection === "offline" ? (
            <span className="mt-1 block text-[var(--muted)]">
              Im Browser-Dev-Modus Backend separat starten:{" "}
              <code className="font-mono">cd backend && python -m app.main</code>
            </span>
          ) : null}
        </div>
      ) : null}

      <div className="grid gap-6 lg:grid-cols-[340px_1fr]">
        <section className="rounded-md border border-[var(--line)] bg-[var(--panel)] p-5 shadow-sm">
          <h2 className="text-sm font-semibold tracking-wide text-[var(--ink)] uppercase">
            Neues Projekt
          </h2>
          <form className="mt-4 space-y-3" onSubmit={onCreate}>
            <label className="block text-sm">
              <span className="mb-1 block text-[var(--muted)]">Name</span>
              <input
                value={name}
                onChange={(e) => setName(e.target.value)}
                required
                maxLength={255}
                className="w-full rounded border border-[var(--line)] px-3 py-2 outline-none focus:border-[var(--accent)]"
                placeholder="z. B. Lab-Netzwerk A"
              />
            </label>
            <label className="block text-sm">
              <span className="mb-1 block text-[var(--muted)]">Beschreibung</span>
              <textarea
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                rows={3}
                className="w-full resize-y rounded border border-[var(--line)] px-3 py-2 outline-none focus:border-[var(--accent)]"
                placeholder="Optional"
              />
            </label>
            <button
              type="submit"
              disabled={busy || connection !== "online"}
              className="rounded bg-[var(--accent)] px-4 py-2 text-sm font-medium text-[var(--accent-ink)] disabled:cursor-not-allowed disabled:opacity-50"
            >
              Anlegen
            </button>
          </form>
        </section>

        <section className="rounded-md border border-[var(--line)] bg-[var(--panel)] p-5 shadow-sm">
          <div className="mb-4 flex items-baseline justify-between gap-3">
            <h2 className="text-sm font-semibold tracking-wide text-[var(--ink)] uppercase">
              Projekte
            </h2>
            <span className="text-xs text-[var(--muted)]">{projects.length} gesamt</span>
          </div>
          {projects.length === 0 ? (
            <p className="text-sm text-[var(--muted)]">
              Noch keine Projekte. Lege links das erste Projekt an.
            </p>
          ) : (
            <ul className="divide-y divide-[var(--line)]">
              {projects.map((p) => (
                <li
                  key={p.id}
                  className="flex flex-wrap items-start justify-between gap-3 py-3 first:pt-0 last:pb-0"
                >
                  <div>
                    <div className="font-medium text-[var(--ink)]">{p.name}</div>
                    {p.description ? (
                      <p className="mt-0.5 text-sm text-[var(--muted)]">{p.description}</p>
                    ) : null}
                    <p className="mt-1 font-mono text-[11px] text-[var(--muted)]">{p.id}</p>
                  </div>
                  <button
                    type="button"
                    disabled={busy}
                    onClick={() => void onDelete(p.id)}
                    className="rounded border border-[var(--line)] px-3 py-1.5 text-xs text-[var(--danger)] hover:bg-red-50 disabled:opacity-50"
                  >
                    Löschen
                  </button>
                </li>
              ))}
            </ul>
          )}
        </section>
      </div>
    </div>
  );
}
