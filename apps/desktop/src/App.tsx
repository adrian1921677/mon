import { FormEvent, useCallback, useEffect, useMemo, useState } from "react";
import {
  ApiError,
  createClient,
  SETTING_ACTIVE_TESTS,
  type AssetRead,
  type DashboardRead,
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
import { NAV_ITEMS, isScanSurface, type NavItem, type ViewId } from "./nav";
import { DashboardView } from "./views/DashboardView";
import { FindingsView } from "./views/FindingsView";
import { ReportsView } from "./views/ReportsView";

type ConnectionState = "checking" | "online" | "offline";

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

function scanProgress(scan: ScanRead): number {
  const tasks = scan.tasks || [];
  if (!tasks.length) return scan.status === "completed" ? 100 : 0;
  const done = tasks.filter((t) =>
    ["completed", "failed", "cancelled", "interrupted"].includes(t.status),
  ).length;
  return Math.round((done / tasks.length) * 100);
}

export default function App() {
  const [backend, setBackend] = useState<BackendInfo | null>(null);
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [connection, setConnection] = useState<ConnectionState>("checking");
  const [view, setView] = useState<ViewId>("dashboard");
  const [projects, setProjects] = useState<ProjectRead[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [scopeEntries, setScopeEntries] = useState<ScopeEntryRead[]>([]);
  const [assets, setAssets] = useState<AssetRead[]>([]);
  const [tools, setTools] = useState<ToolLiveRead[]>([]);
  const [scans, setScans] = useState<ScanRead[]>([]);
  const [dashboard, setDashboard] = useState<DashboardRead | null>(null);
  const [findingsTotal, setFindingsTotal] = useState(0);
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

  const activeNav: NavItem | undefined = NAV_ITEMS.find((n) => n.id === view);
  const capabilityFilter = activeNav?.scanCapability;

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

  const refreshProjectExtras = useCallback(
    async (projectId: string) => {
      try {
        setDashboard(await client.getDashboard(projectId));
      } catch {
        setDashboard(null);
      }
      try {
        setAssets(await client.listAssets(projectId));
      } catch {
        setAssets([]);
      }
      try {
        const findings = await client.listFindings(projectId, { limit: 1 });
        setFindingsTotal(findings.total);
      } catch {
        setFindingsTotal(0);
      }
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
        setDashboard(null);
        setAssets([]);
        setFindingsTotal(0);
      } else if (selectedId) {
        await refreshScope(selectedId);
        await refreshScans(selectedId);
        await refreshProjectExtras(selectedId);
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
        /* tools optional */
      }
    } catch (err) {
      setConnection("offline");
      setHealth(null);
      setError(err instanceof Error ? err.message : String(err));
    }
  }, [client, refreshProjectExtras, refreshScope, refreshScans, refreshTools, selectedId]);

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
        setDashboard(null);
        setAssets([]);
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
      await refreshProjectExtras(id);
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
      await refreshProjectExtras(selectedId);
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
      if (selectedId) await refreshProjectExtras(selectedId);
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
      await refreshProjectExtras(selectedId);
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

  const filteredTools = useMemo(() => {
    if (!capabilityFilter) return tools;
    return tools.filter((t) => (t.capabilities || []).includes(capabilityFilter));
  }, [tools, capabilityFilter]);

  const scannerChoices = (
    filteredTools.some((t) => t.status === "installed")
      ? filteredTools.filter((t) => t.status === "installed")
      : filteredTools.length
        ? filteredTools
        : tools
  );

  function renderScanManager(title: string, hint: string) {
    return (
      <div className="space-y-4">
        <div>
          <h2 className="text-sm font-semibold tracking-wide text-[var(--ink)] uppercase">
            {title}
          </h2>
          <p className="mt-1 text-sm text-[var(--muted)]">{hint}</p>
        </div>
        {!selected ? (
          <p className="text-sm text-[var(--muted)]">Projekt wählen, um Scans zu starten.</p>
        ) : (
          <div className="rounded-md border border-[var(--line)] bg-[var(--panel)] p-5 shadow-sm">
            <div className="flex flex-wrap items-end gap-3">
              <label className="block text-sm">
                <span className="mb-1 block text-[var(--muted)]">Scanner</span>
                <select
                  value={selectedScanner}
                  onChange={(e) => setSelectedScanner(e.target.value)}
                  className="min-w-[220px] rounded border border-[var(--line)] px-2 py-2"
                >
                  {scannerChoices.map((t) => (
                    <option key={t.scanner_id} value={t.scanner_id}>
                      {t.display_name} ({t.status})
                    </option>
                  ))}
                </select>
              </label>
              <button
                type="button"
                disabled={busy || connection !== "online" || !scannerChoices.length}
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
                {scans.map((s) => {
                  const pct = scanProgress(s);
                  const live = s.status === "running" || s.status === "pending";
                  return (
                    <li key={s.id} className="py-3 text-sm">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="font-mono text-[11px] text-[var(--muted)]">
                          {s.id.slice(0, 8)}
                        </span>
                        <span className={live ? "text-[var(--warn)]" : ""}>{s.status}</span>
                        <span className="text-[var(--muted)]">
                          {(s.tasks || []).map((t) => t.scanner_id).join(", ")}
                        </span>
                        <span className="ml-auto font-mono text-[11px] tabular-nums">
                          {pct}%
                        </span>
                      </div>
                      <div className="mt-2 h-1.5 overflow-hidden rounded bg-gray-100">
                        <div
                          className="h-full rounded bg-[var(--accent)] transition-all"
                          style={{ width: `${pct}%` }}
                        />
                      </div>
                      {(s.tasks || []).map((t) => (
                        <div
                          key={t.id}
                          className="mt-1 flex flex-wrap gap-2 font-mono text-[11px] text-[var(--muted)]"
                        >
                          <span>
                            {t.scanner_id}: {t.status}
                            {t.exit_code != null ? ` (exit ${t.exit_code})` : ""}
                          </span>
                          {t.log_path ? (
                            <span className="break-all">{t.log_path}</span>
                          ) : null}
                        </div>
                      ))}
                    </li>
                  );
                })}
              </ul>
            )}
          </div>
        )}
      </div>
    );
  }

  function renderMain() {
    if (view === "dashboard") {
      return (
        <DashboardView
          dashboard={dashboard}
          projectName={selected?.name ?? null}
          onOpenFindings={() => setView("findings")}
          onOpenScans={() => setView("scans")}
        />
      );
    }
    if (view === "findings") {
      return (
        <FindingsView
          client={client}
          projectId={selectedId}
          projectName={selected?.name ?? null}
          onError={setError}
        />
      );
    }
    if (view === "reports") {
      return (
        <ReportsView
          client={client}
          projectId={selectedId}
          projectName={selected?.name ?? null}
          scans={scans}
          findingsCount={findingsTotal}
          onError={setError}
        />
      );
    }
    if (view === "inventory") {
      return (
        <div className="space-y-4">
          <h2 className="text-sm font-semibold tracking-wide uppercase">
            Asset Inventory {selected ? `— ${selected.name}` : ""}
          </h2>
          {!selected ? (
            <p className="text-sm text-[var(--muted)]">Projekt wählen.</p>
          ) : assets.length === 0 ? (
            <p className="text-sm text-[var(--muted)]">
              Noch keine Assets. Scope-Einträge erzeugen Asset-Zeilen automatisch.
            </p>
          ) : (
            <ul className="divide-y divide-[var(--line)] rounded-md border border-[var(--line)] bg-[var(--panel)]">
              {assets.map((a) => (
                <li key={a.id} className="px-4 py-3 text-sm">
                  <span className="rounded bg-gray-100 px-1.5 py-0.5 font-mono text-[11px]">
                    {a.type}
                  </span>
                  <div className="mt-1 font-mono break-all">{a.identifier}</div>
                  <div className="text-[11px] text-[var(--muted)]">
                    last_seen: {a.last_seen_at || "—"}
                  </div>
                </li>
              ))}
            </ul>
          )}
        </div>
      );
    }
    if (view === "tools") {
      return (
        <section className="rounded-md border border-[var(--line)] bg-[var(--panel)] p-5 shadow-sm">
          <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
            <div>
              <h2 className="text-sm font-semibold tracking-wide uppercase">Tool Manager</h2>
              <p className="mt-1 text-sm text-[var(--muted)]">
                Live-Verfügbarkeit der Scanner. Fehlende Binaries → kein Fake-Finding.
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
          <ul className="divide-y divide-[var(--line)]">
            {tools.map((t) => (
              <li
                key={t.scanner_id}
                className="flex flex-wrap items-start justify-between gap-3 py-3"
              >
                <div>
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-medium">{t.display_name}</span>
                    <span className="font-mono text-[11px] text-[var(--muted)]">
                      {t.scanner_id}
                    </span>
                    <span style={{ color: statusTone(t.status) }} className="text-[11px]">
                      {t.status}
                    </span>
                  </div>
                  <p className="mt-1 text-sm text-[var(--muted)]">{t.description}</p>
                </div>
                <div className="text-xs text-[var(--muted)]">
                  {(t.capabilities || []).join(", ")}
                </div>
              </li>
            ))}
          </ul>
        </section>
      );
    }
    if (view === "settings") {
      return (
        <section className="max-w-lg space-y-4 rounded-md border border-[var(--line)] bg-[var(--panel)] p-5 shadow-sm">
          <h2 className="text-sm font-semibold tracking-wide uppercase">Settings</h2>
          <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-2 text-sm">
            <dt className="text-[var(--muted)]">Backend</dt>
            <dd className="font-mono">{backend?.baseUrl ?? "—"}</dd>
            <dt className="text-[var(--muted)]">Version</dt>
            <dd>{health?.version ?? "—"}</dd>
            <dt className="text-[var(--muted)]">Aktive Tests</dt>
            <dd>{activeTests ? "freigegeben" : "gesperrt"}</dd>
          </dl>
          <button
            type="button"
            disabled={busy || connection !== "online"}
            onClick={() => void onToggleActiveTests()}
            className="rounded border border-[var(--line)] px-3 py-2 text-sm hover:bg-gray-50 disabled:opacity-50"
          >
            {activeTests ? "Aktive Tests sperren" : "Aktive Tests freigeben"}
          </button>
        </section>
      );
    }
    if (isScanSurface(view)) {
      const labels: Record<string, string> = {
        scans: "Scan Manager",
        network: "Network Security",
        web: "Web Security",
        code: "Code Security",
        api: "API Security",
        host: "Host Security",
      };
      return renderScanManager(
        labels[view] || "Scans",
        capabilityFilter
          ? `Scanner mit Capability „${capabilityFilter}“ — gleiche Pipeline wie Scan Manager, echte Findings nur aus Tool-Output.`
          : "Live-Fortschritt aus Task-Status. Keine simulierten Results.",
      );
    }

    // projects (default)
    return (
      <div className="grid gap-6 lg:grid-cols-[280px_1fr]">
        <section className="space-y-6">
          <div className="rounded-md border border-[var(--line)] bg-[var(--panel)] p-5 shadow-sm">
            <h2 className="text-sm font-semibold tracking-wide uppercase">Neues Projekt</h2>
            <form className="mt-4 space-y-3" onSubmit={onCreate}>
              <label className="block text-sm">
                <span className="mb-1 block text-[var(--muted)]">Name</span>
                <input
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  required
                  maxLength={255}
                  className="w-full rounded border border-[var(--line)] px-3 py-2 outline-none focus:border-[var(--accent)]"
                />
              </label>
              <label className="block text-sm">
                <span className="mb-1 block text-[var(--muted)]">Beschreibung</span>
                <textarea
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  rows={2}
                  className="w-full resize-y rounded border border-[var(--line)] px-3 py-2"
                />
              </label>
              <button
                type="submit"
                disabled={busy || connection !== "online"}
                className="rounded bg-[var(--accent)] px-4 py-2 text-sm font-medium text-[var(--accent-ink)] disabled:opacity-50"
              >
                Anlegen
              </button>
            </form>
          </div>
          <div className="rounded-md border border-[var(--line)] bg-[var(--panel)] p-5 shadow-sm">
            <h2 className="mb-3 text-sm font-semibold tracking-wide uppercase">
              Projekte ({projects.length})
            </h2>
            <ul className="divide-y divide-[var(--line)]">
              {projects.map((p) => (
                <li key={p.id} className="py-2">
                  <button
                    type="button"
                    onClick={() => void onSelectProject(p.id)}
                    className={`w-full rounded px-2 py-1.5 text-left text-sm ${
                      selectedId === p.id ? "bg-teal-50 font-medium" : "hover:bg-gray-50"
                    }`}
                  >
                    {p.name}
                  </button>
                  <div className="mt-1 flex justify-end">
                    <button
                      type="button"
                      disabled={busy}
                      onClick={() => void onDelete(p.id)}
                      className="rounded border border-[var(--line)] px-2 py-1 text-[11px] text-[var(--danger)] disabled:opacity-50"
                    >
                      Löschen
                    </button>
                  </div>
                </li>
              ))}
            </ul>
          </div>
        </section>

        <section className="rounded-md border border-[var(--line)] bg-[var(--panel)] p-5 shadow-sm">
          {!selected ? (
            <p className="text-sm text-[var(--muted)]">Projekt wählen für Scope-Verwaltung.</p>
          ) : (
            <>
              <h2 className="text-sm font-semibold tracking-wide uppercase">
                Scope — {selected.name}
              </h2>
              <form
                className="mt-4 mb-5 grid gap-3 md:grid-cols-[140px_1fr_auto_auto]"
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
                <label className="block text-sm">
                  <span className="mb-1 block text-[var(--muted)]">Wert</span>
                  <input
                    value={scopeValue}
                    onChange={(e) => setScopeValue(e.target.value)}
                    required
                    className="w-full rounded border border-[var(--line)] px-3 py-2 font-mono text-sm"
                  />
                </label>
                <div className="flex items-end">
                  <button
                    type="button"
                    disabled={busy || !scopeValue.trim()}
                    onClick={() => void onValidateScope()}
                    className="w-full rounded border border-[var(--line)] px-3 py-2 text-sm disabled:opacity-50"
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
                  {validateResult.allowed ? "Erlaubt" : "Abgelehnt"} — {validateResult.reason}
                </div>
              ) : null}
              <ul className="divide-y divide-[var(--line)]">
                {scopeEntries.map((e) => (
                  <li key={e.id} className="flex justify-between gap-3 py-3 text-sm">
                    <div>
                      <span className="font-mono text-[11px]">{e.type}</span>
                      <div className="font-mono break-all">{e.value}</div>
                    </div>
                    <button
                      type="button"
                      disabled={busy}
                      onClick={() => void onDeleteScope(e.id)}
                      className="rounded border border-[var(--line)] px-2 py-1 text-xs text-[var(--danger)] disabled:opacity-50"
                    >
                      Entfernen
                    </button>
                  </li>
                ))}
              </ul>
            </>
          )}
        </section>
      </div>
    );
  }

  const groups: Array<{ key: NavItem["group"]; label: string }> = [
    { key: "overview", label: "Übersicht" },
    { key: "security", label: "Security" },
    { key: "ops", label: "Betrieb" },
  ];

  return (
    <div className="min-h-screen md:flex">
      <aside className="w-full shrink-0 border-b border-[var(--line)] bg-[var(--panel)]/90 px-4 py-5 backdrop-blur md:w-60 md:border-r md:border-b-0">
        <div className="mb-5">
          <p className="text-[10px] font-semibold tracking-[0.18em] text-[var(--muted)] uppercase">
            Local Security Platform
          </p>
          <h1 className="mt-1 text-2xl font-semibold tracking-tight">Hck</h1>
          <p className="mt-1 text-xs text-[var(--muted)]">Phase 8 · Findings & Reports</p>
        </div>
        <nav className="space-y-4">
          {groups.map((g) => (
            <div key={g.key}>
              <div className="mb-1 text-[10px] font-semibold tracking-wide text-[var(--muted)] uppercase">
                {g.label}
              </div>
              <ul className="space-y-0.5">
                {NAV_ITEMS.filter((n) => n.group === g.key).map((n) => (
                  <li key={n.id}>
                    <button
                      type="button"
                      onClick={() => setView(n.id)}
                      className={`w-full rounded px-2 py-1.5 text-left text-sm ${
                        view === n.id
                          ? "bg-[var(--accent)] text-[var(--accent-ink)]"
                          : "hover:bg-gray-50"
                      }`}
                    >
                      {n.label}
                    </button>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </nav>
      </aside>

      <div className="min-w-0 flex-1 px-5 py-5 md:px-8">
        <header className="mb-6 flex flex-wrap items-start justify-between gap-4 border-b border-[var(--line)] pb-4">
          <div>
            <label className="text-sm">
              <span className="mb-1 block text-xs text-[var(--muted)]">Aktives Projekt</span>
              <select
                value={selectedId ?? ""}
                onChange={(e) => {
                  const id = e.target.value;
                  if (id) void onSelectProject(id);
                  else setSelectedId(null);
                }}
                className="min-w-[220px] rounded border border-[var(--line)] px-2 py-1.5 text-sm"
              >
                <option value="">— keines —</option>
                {projects.map((p) => (
                  <option key={p.id} value={p.id}>
                    {p.name}
                  </option>
                ))}
              </select>
            </label>
          </div>
          <div className="rounded-md border border-[var(--line)] bg-[var(--panel)] px-4 py-3 text-xs shadow-sm">
            <div className="flex items-center gap-2 text-sm font-medium">
              <span
                className="inline-block h-2.5 w-2.5 rounded-full"
                style={{ background: statusColor }}
              />
              {statusLabel}
            </div>
            <div className="mt-1 text-[var(--muted)]">
              {backend?.baseUrl ?? "http://127.0.0.1:8765"} · v{health?.version ?? "—"} ·{" "}
              {installedCount}/{tools.length || "—"} Tools
            </div>
            <button
              type="button"
              onClick={() => void refresh()}
              className="mt-2 rounded border border-[var(--line)] px-2 py-1 hover:bg-gray-50"
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
                Backend: <code className="font-mono">cd backend && python -m app.main</code>
              </span>
            ) : null}
          </div>
        ) : null}

        {renderMain()}
      </div>
    </div>
  );
}
