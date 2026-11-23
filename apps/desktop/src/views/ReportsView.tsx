import { useState } from "react";
import type { HckApiClient, ScanCompareResult, ScanRead } from "../api/client";

interface Props {
  client: HckApiClient;
  projectId: string | null;
  projectName: string | null;
  scans: ScanRead[];
  findingsCount: number;
  onError: (msg: string | null) => void;
}

function triggerDownload(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

export function ReportsView({
  client,
  projectId,
  projectName,
  scans,
  findingsCount,
  onError,
}: Props) {
  const [busy, setBusy] = useState(false);
  const [baseline, setBaseline] = useState("");
  const [candidate, setCandidate] = useState("");
  const [compare, setCompare] = useState<ScanCompareResult | null>(null);
  const [findingId, setFindingId] = useState("");

  async function exportProject(format: "json" | "pdf") {
    if (!projectId) return;
    setBusy(true);
    onError(null);
    try {
      const file = await client.downloadReport(projectId, "project", format);
      triggerDownload(file.blob, file.filename);
    } catch (err) {
      onError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  async function exportFinding(format: "json" | "pdf") {
    if (!projectId || !findingId.trim()) return;
    setBusy(true);
    onError(null);
    try {
      const file = await client.downloadReport(
        projectId,
        { findingId: findingId.trim() },
        format,
      );
      triggerDownload(file.blob, file.filename);
    } catch (err) {
      onError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  async function runCompare() {
    if (!projectId || !baseline || !candidate) return;
    setBusy(true);
    onError(null);
    try {
      const result = await client.compareScans(projectId, {
        baseline_scan_id: baseline,
        candidate_scan_id: candidate,
      });
      setCompare(result);
    } catch (err) {
      onError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  if (!projectId) {
    return <p className="text-sm text-[var(--muted)]">Wähle ein Projekt für Reports.</p>;
  }

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-sm font-semibold tracking-wide text-[var(--ink)] uppercase">
          Reports — {projectName}
        </h2>
        <p className="mt-1 text-sm text-[var(--muted)]">
          Export aus DB-Daten · aktuell {findingsCount} Findings · {scans.length} Scans
        </p>
      </div>

      <section className="rounded-md border border-[var(--line)] bg-[var(--panel)] p-4 shadow-sm">
        <h3 className="text-xs font-semibold uppercase tracking-wide text-[var(--muted)]">
          Projektbericht
        </h3>
        <div className="mt-3 flex flex-wrap gap-2">
          <button
            type="button"
            disabled={busy}
            onClick={() => void exportProject("json")}
            className="rounded bg-[var(--accent)] px-3 py-2 text-sm font-medium text-[var(--accent-ink)] disabled:opacity-50"
          >
            JSON exportieren
          </button>
          <button
            type="button"
            disabled={busy}
            onClick={() => void exportProject("pdf")}
            className="rounded border border-[var(--line)] px-3 py-2 text-sm hover:bg-gray-50 disabled:opacity-50"
          >
            PDF exportieren
          </button>
        </div>
      </section>

      <section className="rounded-md border border-[var(--line)] bg-[var(--panel)] p-4 shadow-sm">
        <h3 className="text-xs font-semibold uppercase tracking-wide text-[var(--muted)]">
          Finding-Bericht
        </h3>
        <div className="mt-3 flex flex-wrap items-end gap-2">
          <label className="text-sm">
            <span className="mb-1 block text-[var(--muted)]">Finding-ID</span>
            <input
              value={findingId}
              onChange={(e) => setFindingId(e.target.value)}
              className="min-w-[280px] rounded border border-[var(--line)] px-2 py-1.5 font-mono text-xs"
              placeholder="UUID aus Findings-View"
            />
          </label>
          <button
            type="button"
            disabled={busy || !findingId.trim()}
            onClick={() => void exportFinding("json")}
            className="rounded border border-[var(--line)] px-3 py-2 text-sm disabled:opacity-50"
          >
            JSON
          </button>
          <button
            type="button"
            disabled={busy || !findingId.trim()}
            onClick={() => void exportFinding("pdf")}
            className="rounded border border-[var(--line)] px-3 py-2 text-sm disabled:opacity-50"
          >
            PDF
          </button>
        </div>
      </section>

      <section className="rounded-md border border-[var(--line)] bg-[var(--panel)] p-4 shadow-sm">
        <h3 className="text-xs font-semibold uppercase tracking-wide text-[var(--muted)]">
          Scan-Vergleich / Verlauf
        </h3>
        <div className="mt-3 flex flex-wrap items-end gap-3">
          <label className="text-sm">
            <span className="mb-1 block text-[var(--muted)]">Baseline</span>
            <select
              value={baseline}
              onChange={(e) => setBaseline(e.target.value)}
              className="min-w-[200px] rounded border border-[var(--line)] px-2 py-1.5"
            >
              <option value="">—</option>
              {scans.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.id.slice(0, 8)} · {s.status}
                </option>
              ))}
            </select>
          </label>
          <label className="text-sm">
            <span className="mb-1 block text-[var(--muted)]">Candidate</span>
            <select
              value={candidate}
              onChange={(e) => setCandidate(e.target.value)}
              className="min-w-[200px] rounded border border-[var(--line)] px-2 py-1.5"
            >
              <option value="">—</option>
              {scans.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.id.slice(0, 8)} · {s.status}
                </option>
              ))}
            </select>
          </label>
          <button
            type="button"
            disabled={busy || !baseline || !candidate}
            onClick={() => void runCompare()}
            className="rounded bg-[var(--accent)] px-3 py-2 text-sm font-medium text-[var(--accent-ink)] disabled:opacity-50"
          >
            Vergleichen
          </button>
        </div>

        {compare ? (
          <div className="mt-4 space-y-3 text-sm">
            <div className="flex flex-wrap gap-4">
              <span>Neu: {compare.summary.new}</span>
              <span>Behoben: {compare.summary.resolved}</span>
              <span>Persistent: {compare.summary.persistent}</span>
            </div>
            <div className="grid gap-3 md:grid-cols-3">
              {(
                [
                  ["Neu", compare.new_findings],
                  ["Behoben", compare.resolved_findings],
                  ["Persistent", compare.persistent_findings],
                ] as const
              ).map(([label, list]) => (
                <div key={label} className="rounded border border-[var(--line)] p-2">
                  <div className="text-xs font-semibold uppercase text-[var(--muted)]">{label}</div>
                  <ul className="mt-1 space-y-1">
                    {list.length === 0 ? (
                      <li className="text-[var(--muted)]">—</li>
                    ) : (
                      list.map((f) => (
                        <li key={f.id} className="text-xs">
                          [{f.severity}] {f.title}
                        </li>
                      ))
                    )}
                  </ul>
                </div>
              ))}
            </div>
            <div>
              <div className="text-xs font-semibold uppercase text-[var(--muted)]">Verlauf</div>
              <ul className="mt-1 max-h-40 overflow-auto font-mono text-[11px] text-[var(--muted)]">
                {compare.history.map((h) => (
                  <li key={h.id}>
                    {h.created_at} · {h.id.slice(0, 8)} · {h.status}
                  </li>
                ))}
              </ul>
            </div>
          </div>
        ) : null}
      </section>
    </div>
  );
}
