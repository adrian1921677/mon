import { FormEvent, useCallback, useEffect, useMemo, useState } from "react";
import {
  ApiError,
  createClient,
  SETTING_ACTIVE_TESTS,
  type HealthResponse,
  type ProjectRead,
  type ScanRead,
  type ScopeEntryRead,
  type ScopeEntryType,
  type ScopeValidateResponse,
  type ToolLiveRead,
} from "./api/client";
import {
  getBackendInfo,
  isTauriRuntime,
  startBackend,
  type BackendInfo,
} from "./api/backend";

type ConnectionState = "checking" | "online" | "offline";
type ViewTab = "projects" | "tools";

const SCOPE_TYPES: ScopeEntryType[] = [
  "ip",
  "cidr",
  "domain",
  "url",
  "api_spec",
  "path",
];

function statusTone(status: string): string {
  if (status === "installed") return "var(--ok)";
  if (status === "not_installed") return "var(--warn)";
  return "var(--muted)";
}

export default function App() {
  const [backend, setBackend] = useState<BackendInfo | null>(null);
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [connection, setConnection] = useState<ConnectionState>("checking");
  const [view, setView] = useState<ViewTab>("projects");
  const [projects, setProjects] = useState<ProjectRead[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [scopeEntries, setScopeEntries] = useState<ScopeEntryRead[]>([]);
  const [tools, setTools] = useState<ToolLiveRead[]>([]);
  const [scans, setScans] = useState<ScanRead[]>([]);
  const [selectedScanner, setSelectedScanner] = useState("nmap");
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [scopeType, setScopeType] = useState<ScopeEntryType>("ip");
  const [scopeValue, setScopeValue] = useState("");
  const [validateResult, setValidateResult] = useState<ScopeValidateResponse | null>(null);
  const [activeTests, setActiveTests] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const client = useMemo(
    () => createClient(backend?.baseUrl ?? undefined),
    [backend?.baseUrl],
  );

  const refreshScope = useCallback(
    async (projectId: string) => {
      const entries = await client.listScope(projectId);
      setScopeEntries(entries);
    },
    [client],
  );

  const refreshTools = useCallback(async () => {
    const list = await client.listTools(false);
    setTools(list);
    const installed = list.filter((t) => t.status === "installed");
    const pool = installed.length ? installed : list;
    if (pool.length && !pool.some((t) => t.scanner_id === selectedScanner)) {
      setSelectedScanner(pool[0].scanner_id);
    }
  }, [client, selectedScanner]);

  const refreshScans = useCallback(
    async (projectId: string) => {
      const list = await client.listScans(projectId);
      setScans(list);
    },
    [client],
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
      if (selectedId && !list.some((p) => p.id === selectedId)) {
        setSelectedId(null);
        setScopeEntries([]);
        setScans([]);
      } else if (selectedId) {
        await refreshScope(selectedId);
        await refreshScans(selectedId);
      }
      try {
        const settings = await client.listSettings();
        const flag = settings.find((s) => s.key === SETTING_ACTIVE_TESTS);
        setActiveTests(Boolean(flag?.value_json === true || flag?.value_json === "true"));
      } catch {
        /* settings optional */
      }
      try {
        await refreshTools();
      } catch {
        /* tools optional until backend Phase 3 */
      }
    } catch (err) {
      setConnection("offline");
      setHealth(null);
      setError(err instanceof Error ? err.message : String(err));
    }
  }, [client, refreshScope, refreshScans, refreshTools, selectedId]);

  useEffect(() => {
    void refresh();
    const id = window.setInterval(() => void refresh(), 8000);
    return () => window.clearInterval(id);
  }, [refresh]);

  async function onCreate(e: FormEvent) {
    e.preventDefault();
    if (!name.trim()) return;
    setBusy(true);
    setError(null);
    try {
      const created = await client.createProject({
        name: name.trim(),
        description: description.trim() || null,
      });
      setName("");
      setDescription("");
      setSelectedId(created.id);
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
      if (selectedId === id) {
        setSelectedId(null);
        setScopeEntries([]);
        setScans([]);
      }
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  async function onSelectProject(id: string) {
    setSelectedId(id);
    setValidateResult(null);
    setError(null);
    try {
      await refreshScope(id);
      await refreshScans(id);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }

  async function onAddScope(e: FormEvent) {
    e.preventDefault();
    if (!selectedId || !scopeValue.trim()) return;
    setBusy(true);
    setError(null);
    setValidateResult(null);
    try {
      await client.createScope(selectedId, {
        type: scopeType,
        value: scopeValue.trim(),
        meta_json: {},
      });
      setScopeValue("");
      await refreshScope(selectedId);
    } catch (err) {
      if (err instanceof ApiError && err.body && typeof err.body === "object") {
        const detail = (err.body as { detail?: ScopeValidateResponse }).detail;
        if (detail && typeof detail === "object" && "allowed" in detail) {
          setValidateResult(detail);
          setError(detail.message || "Scope abgelehnt");
        } else {
          setError(err.message);
        }
      } else {
        setError(err instanceof Error ? err.message : String(err));
      }
    } finally {
      setBusy(false);
    }
  }

  async function onValidateScope() {
    if (!selectedId || !scopeValue.trim()) return;
    setBusy(true);
    setError(null);
    try {
      const result = await client.validateScope(selectedId, {
        mode: "entry",
        type: scopeType,
        value: scopeValue.trim(),
        resolve_dns: scopeType === "domain" || scopeType === "url",
      });
      setValidateResult(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  async function onDeleteScope(entryId: string) {
    if (!selectedId) return;
    setBusy(true);
    setError(null);
    try {
      await client.deleteScope(selectedId, entryId);
      await refreshScope(selectedId);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  async function onToggleActiveTests() {
    setBusy(true);
    setError(null);
    try {
      const next = !activeTests;
      await client.upsertSetting(SETTING_ACTIVE_TESTS, next);
      setActiveTests(next);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  async function onRefreshToolsPersist() {
    setBusy(true);
    setError(null);
    try {
      await client.refreshTools();
      await refreshTools();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  async function onStartScan() {
    if (!selectedId || !selectedScanner) return;
    setBusy(true);
    setError(null);
    try {
      const scan = await client.createScan(selectedId, {
        scanner_ids: [selectedScanner],
        depth: "standard",
      });
      await refreshScans(selectedId);
      const task = scan.tasks[0];
      if (task?.status === "failed" && task.log_path) {
        setError(`Scan: ${task.scanner_id} — ${task.log_path}`);
      }
    } catch (err) {
      if (err instanceof ApiError && err.body && typeof err.body === "object") {
        const detail = (err.body as { detail?: { message?: string } | string }).detail;
        if (typeof detail === "string") setError(detail);
        else if (detail && typeof detail === "object")
          setError(detail.message || JSON.stringify(detail));
        else setError(err.message);
      } else {
        setError(err instanceof Error ? err.message : String(err));
      }
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

  const selected = projects.find((p) => p.id === selectedId) ?? null;
  const installedCount = tools.filter((t) => t.status === "installed").length;

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
            Phase 6: Schemathesis (+ Phase 4–5) — echte CLI-Scans, Findings in DB.
          </p>
          <div className="mt-3 flex gap-2">
            <button
              type="button"
              onClick={() => setView("projects")}
              className={`rounded px-3 py-1.5 text-xs font-medium ${
                view === "projects"
                  ? "bg-[var(--accent)] text-[var(--accent-ink)]"
                  : "border border-[var(--line)] hover:bg-gray-50"
              }`}
            >
              Projekte & Scope
            </button>
            <button
              type="button"
              onClick={() => setView("tools")}
              className={`rounded px-3 py-1.5 text-xs font-medium ${
                view === "tools"
                  ? "bg-[var(--accent)] text-[var(--accent-ink)]"
                  : "border border-[var(--line)] hover:bg-gray-50"
              }`}
            >
              Tool Manager
            </button>
          </div>
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
            <dt>Tools</dt>
            <dd>
              {installedCount}/{tools.length || "—"} installiert
            </dd>
            <dt>Aktive Tests</dt>
            <dd>{activeTests ? "freigegeben" : "gesperrt"}</dd>
          </dl>
          <div className="mt-3 flex gap-2">
            <button
              type="button"
              onClick={() => void refresh()}
              className="flex-1 rounded border border-[var(--line)] bg-white px-3 py-1.5 text-xs font-medium hover:bg-gray-50"
            >
              Erneut prüfen
            </button>
            <button
              type="button"
              disabled={busy || connection !== "online"}
              onClick={() => void onToggleActiveTests()}
              className="flex-1 rounded border border-[var(--line)] px-3 py-1.5 text-xs font-medium hover:bg-gray-50 disabled:opacity-50"
            >
              {activeTests ? "Aktive sperren" : "Aktive freigeben"}
            </button>
          </div>
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

      {view === "tools" ? (
        <section className="rounded-md border border-[var(--line)] bg-[var(--panel)] p-5 shadow-sm">
          <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
            <div>
              <h2 className="text-sm font-semibold tracking-wide text-[var(--ink)] uppercase">
                Tool Manager
              </h2>
              <p className="mt-1 text-sm text-[var(--muted)]">
                Verfügbarkeit der Scanner-Adapter. Echo (Test) erscheint hier nicht. Phase-4/5-Tools
                (Nmap/Semgrep/Trivy/Gitleaks/ZAP/Nuclei) laufen lokal, wenn installiert.
              </p>
            </div>
            <button
              type="button"
              disabled={busy || connection !== "online"}
              onClick={() => void onRefreshToolsPersist()}
              className="rounded bg-[var(--accent)] px-4 py-2 text-sm font-medium text-[var(--accent-ink)] disabled:opacity-50"
            >
              Neu prüfen & speichern
            </button>
          </div>
          {tools.length === 0 ? (
            <p className="text-sm text-[var(--muted)]">Keine Tools geladen.</p>
          ) : (
            <ul className="divide-y divide-[var(--line)]">
              {tools.map((t) => (
                <li
                  key={t.scanner_id}
                  className="flex flex-wrap items-start justify-between gap-3 py-3 first:pt-0 last:pb-0"
                >
                  <div>
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="font-medium text-[var(--ink)]">{t.display_name}</span>
                      <span className="font-mono text-[11px] text-[var(--muted)]">
                        {t.scanner_id}
                      </span>
                      <span
                        className="rounded px-1.5 py-0.5 text-[11px] font-medium"
                        style={{ color: statusTone(t.status) }}
                      >
                        {t.status}
                      </span>
                      {t.is_active ? (
                        <span className="rounded bg-amber-50 px-1.5 py-0.5 text-[11px] text-amber-800">
                          aktiv
                        </span>
                      ) : null}
                      <span className="text-[11px] text-[var(--muted)]">
                        Phase {t.integration_phase} · {t.preferred_runtime}
                      </span>
                    </div>
                    <p className="mt-1 text-sm text-[var(--muted)]">{t.description}</p>
                    <p className="mt-1 font-mono text-[11px] text-[var(--muted)]">
                      {t.message || "—"}
                      {t.version ? ` · v${t.version}` : ""}
                    </p>
                  </div>
                  <div className="text-xs text-[var(--muted)]">
                    {(t.capabilities || []).join(", ")}
                  </div>
                </li>
              ))}
            </ul>
          )}
        </section>
      ) : (
        <div className="grid gap-6 lg:grid-cols-[300px_1fr]">
          <section className="space-y-6">
            <div className="rounded-md border border-[var(--line)] bg-[var(--panel)] p-5 shadow-sm">
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
                    rows={2}
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
            </div>

            <div className="rounded-md border border-[var(--line)] bg-[var(--panel)] p-5 shadow-sm">
              <div className="mb-3 flex items-baseline justify-between gap-3">
                <h2 className="text-sm font-semibold tracking-wide text-[var(--ink)] uppercase">
                  Projekte
                </h2>
                <span className="text-xs text-[var(--muted)]">{projects.length}</span>
              </div>
              {projects.length === 0 ? (
                <p className="text-sm text-[var(--muted)]">Noch keine Projekte.</p>
              ) : (
                <ul className="divide-y divide-[var(--line)]">
                  {projects.map((p) => (
                    <li key={p.id} className="py-2.5 first:pt-0 last:pb-0">
                      <button
                        type="button"
                        onClick={() => void onSelectProject(p.id)}
                        className={`w-full rounded px-2 py-1.5 text-left text-sm ${
                          selectedId === p.id
                            ? "bg-teal-50 font-medium text-[var(--ink)]"
                            : "hover:bg-gray-50"
                        }`}
                      >
                        {p.name}
                      </button>
                      <div className="mt-1 flex justify-end">
                        <button
                          type="button"
                          disabled={busy}
                          onClick={() => void onDelete(p.id)}
                          className="rounded border border-[var(--line)] px-2 py-1 text-[11px] text-[var(--danger)] hover:bg-red-50 disabled:opacity-50"
                        >
                          Löschen
                        </button>
                      </div>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </section>

          <section className="space-y-6">
            <div className="rounded-md border border-[var(--line)] bg-[var(--panel)] p-5 shadow-sm">
              {!selected ? (
                <p className="text-sm text-[var(--muted)]">
                  Wähle links ein Projekt, um Scope zu verwalten und Scans zu starten (echte Tools,
                  keine Fake-Findings).
                </p>
              ) : (
                <>
                  <div className="mb-4 border-b border-[var(--line)] pb-3">
                    <h2 className="text-sm font-semibold tracking-wide text-[var(--ink)] uppercase">
                      Scope — {selected.name}
                    </h2>
                    <p className="mt-1 font-mono text-[11px] text-[var(--muted)]">{selected.id}</p>
                  </div>

                  <form
                    className="mb-5 grid gap-3 md:grid-cols-[140px_1fr_auto_auto]"
                    onSubmit={onAddScope}
                  >
                    <label className="block text-sm">
                      <span className="mb-1 block text-[var(--muted)]">Typ</span>
                      <select
                        value={scopeType}
                        onChange={(e) => setScopeType(e.target.value as ScopeEntryType)}
                        className="w-full rounded border border-[var(--line)] px-2 py-2"
                      >
                        {SCOPE_TYPES.map((t) => (
                          <option key={t} value={t}>
                            {t}
                          </option>
                        ))}
                      </select>
                    </label>
                    <label className="block text-sm md:col-span-1">
                      <span className="mb-1 block text-[var(--muted)]">Wert</span>
                      <input
                        value={scopeValue}
                        onChange={(e) => setScopeValue(e.target.value)}
                        required
                        className="w-full rounded border border-[var(--line)] px-3 py-2 font-mono text-sm outline-none focus:border-[var(--accent)]"
                        placeholder="z. B. 10.0.0.0/24 oder https://app.example.com"
                      />
                    </label>
                    <div className="flex items-end">
                      <button
                        type="button"
                        disabled={busy || !scopeValue.trim()}
                        onClick={() => void onValidateScope()}
                        className="w-full rounded border border-[var(--line)] px-3 py-2 text-sm hover:bg-gray-50 disabled:opacity-50"
                      >
                        Validieren
                      </button>
                    </div>
                    <div className="flex items-end">
                      <button
                        type="submit"
                        disabled={busy || connection !== "online"}
                        className="w-full rounded bg-[var(--accent)] px-3 py-2 text-sm font-medium text-[var(--accent-ink)] disabled:opacity-50"
                      >
                        Hinzufügen
                      </button>
                    </div>
                  </form>

                  {validateResult ? (
                    <div
                      className={`mb-4 rounded border px-3 py-2 text-sm ${
                        validateResult.allowed
                          ? "border-green-200 bg-green-50 text-[var(--ok)]"
                          : "border-red-200 bg-red-50 text-[var(--danger)]"
                      }`}
                    >
                      <div className="font-medium">
                        {validateResult.allowed ? "Erlaubt" : "Abgelehnt"} —{" "}
                        {validateResult.reason}
                      </div>
                      <div className="mt-0.5 text-[var(--muted)]">{validateResult.message}</div>
                    </div>
                  ) : null}

                  {scopeEntries.length === 0 ? (
                    <p className="text-sm text-[var(--muted)]">Noch keine Scope-Einträge.</p>
                  ) : (
                    <ul className="divide-y divide-[var(--line)]">
                      {scopeEntries.map((e) => (
                        <li
                          key={e.id}
                          className="flex flex-wrap items-start justify-between gap-3 py-3 first:pt-0 last:pb-0"
                        >
                          <div>
                            <div className="flex flex-wrap items-center gap-2">
                              <span className="rounded bg-gray-100 px-1.5 py-0.5 font-mono text-[11px]">
                                {e.type}
                              </span>
                              <span className="text-xs text-[var(--muted)]">{e.status}</span>
                            </div>
                            <div className="mt-1 font-mono text-sm text-[var(--ink)] break-all">
                              {e.value}
                            </div>
                          </div>
                          <button
                            type="button"
                            disabled={busy}
                            onClick={() => void onDeleteScope(e.id)}
                            className="rounded border border-[var(--line)] px-3 py-1.5 text-xs text-[var(--danger)] hover:bg-red-50 disabled:opacity-50"
                          >
                            Entfernen
                          </button>
                        </li>
                      ))}
                    </ul>
                  )}
                </>
              )}
            </div>

            {selected ? (
              <div className="rounded-md border border-[var(--line)] bg-[var(--panel)] p-5 shadow-sm">
                <h2 className="text-sm font-semibold tracking-wide text-[var(--ink)] uppercase">
                  Scan starten
                </h2>
                <p className="mt-1 text-sm text-[var(--muted)]">
                  Scope + Active-Gate + ProcessManager. Installierte Tools (inkl. Schemathesis,
                  ZAP, Nuclei) schreiben echte Findings — fehlende Binaries enden als failed,
                  ohne Fake-Results. Schemathesis und ZAP deep/active brauchen Active-Gate.
                </p>
                <div className="mt-4 flex flex-wrap items-end gap-3">
                  <label className="block text-sm">
                    <span className="mb-1 block text-[var(--muted)]">Scanner</span>
                    <select
                      value={selectedScanner}
                      onChange={(e) => setSelectedScanner(e.target.value)}
                      className="min-w-[200px] rounded border border-[var(--line)] px-2 py-2"
                    >
                      {(tools.some((t) => t.status === "installed")
                        ? tools.filter((t) => t.status === "installed")
                        : tools
                      ).map((t) => (
                        <option key={t.scanner_id} value={t.scanner_id}>
                          {t.display_name} ({t.status})
                        </option>
                      ))}
                    </select>
                  </label>
                  <button
                    type="button"
                    disabled={busy || connection !== "online" || !tools.length}
                    onClick={() => void onStartScan()}
                    className="rounded bg-[var(--accent)] px-4 py-2 text-sm font-medium text-[var(--accent-ink)] disabled:opacity-50"
                  >
                    Scan starten
                  </button>
                </div>
                {scans.length === 0 ? (
                  <p className="mt-4 text-sm text-[var(--muted)]">Noch keine Scans.</p>
                ) : (
                  <ul className="mt-4 divide-y divide-[var(--line)]">
                    {scans.slice(0, 5).map((s) => (
                      <li key={s.id} className="py-2 text-sm">
                        <div className="flex flex-wrap gap-2">
                          <span className="font-mono text-[11px] text-[var(--muted)]">
                            {s.id.slice(0, 8)}
                          </span>
                          <span>{s.status}</span>
                          <span className="text-[var(--muted)]">
                            {(s.tasks || []).map((t) => t.scanner_id).join(", ")}
                          </span>
                        </div>
                        {(s.tasks || []).map((t) =>
                          t.log_path ? (
                            <div
                              key={t.id}
                              className="mt-1 font-mono text-[11px] text-[var(--muted)] break-all"
                            >
                              {t.scanner_id}: {t.log_path}
                            </div>
                          ) : null,
                        )}
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            ) : null}
          </section>
        </div>
      )}
    </div>
  );
}
