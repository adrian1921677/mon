import type { DashboardRead } from "../api/client";

interface Props {
  dashboard: DashboardRead | null;
  projectName: string | null;
  onOpenFindings: () => void;
  onOpenScans: () => void;
}

function sevColor(sev: string): string {
  if (sev === "critical" || sev === "high") return "var(--danger)";
  if (sev === "medium") return "var(--warn)";
  return "var(--muted)";
}

export function DashboardView({ dashboard, projectName, onOpenFindings, onOpenScans }: Props) {
  if (!projectName) {
    return (
      <p className="text-sm text-[var(--muted)]">
        Wähle ein Projekt, um das Dashboard mit echten DB-Daten zu sehen.
      </p>
    );
  }
  if (!dashboard) {
    return <p className="text-sm text-[var(--muted)]">Dashboard wird geladen…</p>;
  }

  const bySev = dashboard.finding_counts.by_severity || {};
  const maxTrend = Math.max(1, ...dashboard.trend.map((t) => t.new_findings));

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-sm font-semibold tracking-wide text-[var(--ink)] uppercase">
          Dashboard — {projectName}
        </h2>
        <p className="mt-1 text-sm text-[var(--muted)]">
          Nur persistierte Assets, Scans und Findings — keine Simulation.
        </p>
      </div>

      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        {[
          { label: "Assets", value: dashboard.asset_count },
          { label: "Findings", value: dashboard.finding_counts.total },
          {
            label: "Laufende Scans",
            value: dashboard.running_scans.length,
            action: onOpenScans,
          },
          {
            label: "Scanner installiert",
            value: `${dashboard.scanners.installed}/${dashboard.scanners.total}`,
          },
        ].map((card) => (
          <button
            key={card.label}
            type="button"
            onClick={card.action}
            disabled={!card.action}
            className="rounded-md border border-[var(--line)] bg-[var(--panel)] px-4 py-3 text-left shadow-sm disabled:cursor-default"
          >
            <div className="text-xs text-[var(--muted)] uppercase tracking-wide">{card.label}</div>
            <div className="mt-1 text-2xl font-semibold tabular-nums">{card.value}</div>
          </button>
        ))}
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        <section className="rounded-md border border-[var(--line)] bg-[var(--panel)] p-4 shadow-sm">
          <h3 className="text-xs font-semibold uppercase tracking-wide text-[var(--muted)]">
            Severity
          </h3>
          <ul className="mt-3 space-y-2">
            {Object.entries(bySev).map(([sev, count]) => (
              <li key={sev} className="flex items-center justify-between text-sm">
                <span style={{ color: sevColor(sev) }}>{sev}</span>
                <span className="font-mono tabular-nums">{count as number}</span>
              </li>
            ))}
          </ul>
          <button
            type="button"
            onClick={onOpenFindings}
            className="mt-4 text-xs font-medium text-[var(--accent)] hover:underline"
          >
            Alle Findings öffnen →
          </button>
        </section>

        <section className="rounded-md border border-[var(--line)] bg-[var(--panel)] p-4 shadow-sm">
          <h3 className="text-xs font-semibold uppercase tracking-wide text-[var(--muted)]">
            Trend (14 Tage, neue Findings)
          </h3>
          <div className="mt-3 flex h-28 items-end gap-1">
            {dashboard.trend.map((t) => (
              <div key={t.date} className="flex flex-1 flex-col items-center justify-end gap-1">
                <div
                  className="w-full rounded-sm bg-[var(--accent)]/70"
                  style={{ height: `${Math.max(4, (t.new_findings / maxTrend) * 100)}%` }}
                  title={`${t.date}: ${t.new_findings}`}
                />
              </div>
            ))}
          </div>
        </section>
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        <section className="rounded-md border border-[var(--line)] bg-[var(--panel)] p-4 shadow-sm">
          <h3 className="text-xs font-semibold uppercase tracking-wide text-[var(--muted)]">
            Kritische Findings (open)
          </h3>
          {dashboard.critical_findings.length === 0 ? (
            <p className="mt-3 text-sm text-[var(--muted)]">Keine kritischen Open-Findings.</p>
          ) : (
            <ul className="mt-3 divide-y divide-[var(--line)]">
              {dashboard.critical_findings.map((f) => (
                <li key={f.id} className="py-2 text-sm">
                  <div className="font-medium">{f.title}</div>
                  <div className="font-mono text-[11px] text-[var(--muted)]">
                    {f.scanner_id} · {f.fingerprint.slice(0, 12)}…
                  </div>
                </li>
              ))}
            </ul>
          )}
        </section>

        <section className="rounded-md border border-[var(--line)] bg-[var(--panel)] p-4 shadow-sm">
          <h3 className="text-xs font-semibold uppercase tracking-wide text-[var(--muted)]">
            Letzte Aktivitäten
          </h3>
          {dashboard.recent_activities.length === 0 ? (
            <p className="mt-3 text-sm text-[var(--muted)]">Noch keine Aktivitäten.</p>
          ) : (
            <ul className="mt-3 divide-y divide-[var(--line)]">
              {dashboard.recent_activities.slice(0, 8).map((a) => (
                <li key={`${a.kind}-${a.id}`} className="flex justify-between gap-3 py-2 text-sm">
                  <span>{a.summary}</span>
                  <span className="shrink-0 font-mono text-[11px] text-[var(--muted)]">
                    {a.at ? new Date(a.at).toLocaleString() : "—"}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </section>
      </div>

      <section className="rounded-md border border-[var(--line)] bg-[var(--panel)] p-4 shadow-sm">
        <h3 className="text-xs font-semibold uppercase tracking-wide text-[var(--muted)]">
          Scanner-Verfügbarkeit
        </h3>
        <ul className="mt-3 grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
          {dashboard.scanners.items.map((s) => (
            <li
              key={s.scanner_id}
              className="rounded border border-[var(--line)] px-3 py-2 text-sm"
            >
              <div className="font-medium">{s.display_name}</div>
              <div className="text-[11px] text-[var(--muted)]">
                {s.status}
                {s.version ? ` · v${s.version}` : ""} · Phase {s.integration_phase}
              </div>
            </li>
          ))}
        </ul>
      </section>
    </div>
  );
}
