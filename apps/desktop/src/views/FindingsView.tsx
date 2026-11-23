import { useEffect, useState } from "react";
import type {
  FindingRead,
  FindingStatus,
  HckApiClient,
} from "../api/client";

interface Props {
  client: HckApiClient;
  projectId: string | null;
  projectName: string | null;
  onError: (msg: string | null) => void;
}

const STATUSES: FindingStatus[] = ["open", "fixed", "false_positive"];

function sevTone(sev: string): string {
  if (sev === "critical" || sev === "high") return "text-[var(--danger)]";
  if (sev === "medium") return "text-[var(--warn)]";
  return "text-[var(--muted)]";
}

export function FindingsView({ client, projectId, projectName, onError }: Props) {
  const [items, setItems] = useState<FindingRead[]>([]);
  const [total, setTotal] = useState(0);
  const [selected, setSelected] = useState<FindingRead | null>(null);
  const [statusFilter, setStatusFilter] = useState<FindingStatus | "">("");
  const [busy, setBusy] = useState(false);

  async function refresh() {
    if (!projectId) {
      setItems([]);
      setTotal(0);
      setSelected(null);
      return;
    }
    onError(null);
    try {
      const res = await client.listFindings(projectId, {
        status: statusFilter || undefined,
        limit: 200,
      });
      setItems(res.items);
      setTotal(res.total);
      if (selected && !res.items.some((i) => i.id === selected.id)) {
        setSelected(null);
      }
    } catch (err) {
      onError(err instanceof Error ? err.message : String(err));
    }
  }

  useEffect(() => {
    void refresh();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [projectId, statusFilter]);

  async function openDetail(id: string) {
    if (!projectId) return;
    setBusy(true);
    onError(null);
    try {
      const detail = await client.getFinding(projectId, id);
      setSelected(detail);
    } catch (err) {
      onError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  async function setStatus(status: FindingStatus) {
    if (!projectId || !selected) return;
    setBusy(true);
    onError(null);
    try {
      const updated = await client.updateFinding(projectId, selected.id, { status });
      setSelected(updated);
      await refresh();
    } catch (err) {
      onError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  if (!projectId) {
    return (
      <p className="text-sm text-[var(--muted)]">Wähle ein Projekt für Findings.</p>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h2 className="text-sm font-semibold tracking-wide text-[var(--ink)] uppercase">
            Findings — {projectName}
          </h2>
          <p className="mt-1 text-sm text-[var(--muted)]">
            Dedup über Fingerprint · Occurrences sichtbar · {total} Einträge
          </p>
        </div>
        <label className="text-sm">
          <span className="mb-1 block text-[var(--muted)]">Status</span>
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value as FindingStatus | "")}
            className="rounded border border-[var(--line)] px-2 py-1.5"
          >
            <option value="">alle</option>
            {STATUSES.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
        </label>
      </div>

      <div className="grid gap-4 lg:grid-cols-[1fr_1.1fr]">
        <ul className="divide-y divide-[var(--line)] rounded-md border border-[var(--line)] bg-[var(--panel)] shadow-sm">
          {items.length === 0 ? (
            <li className="px-4 py-6 text-sm text-[var(--muted)]">
              Keine Findings in der DB (keine Fake-Daten).
            </li>
          ) : (
            items.map((f) => (
              <li key={f.id}>
                <button
                  type="button"
                  onClick={() => void openDetail(f.id)}
                  className={`w-full px-4 py-3 text-left text-sm hover:bg-gray-50 ${
                    selected?.id === f.id ? "bg-teal-50" : ""
                  }`}
                >
                  <div className="flex flex-wrap items-center gap-2">
                    <span className={`font-medium ${sevTone(f.severity)}`}>{f.severity}</span>
                    <span className="rounded bg-gray-100 px-1.5 py-0.5 text-[11px]">{f.status}</span>
                    <span className="text-[11px] text-[var(--muted)]">
                      occ×{f.occurrence_count}
                    </span>
                  </div>
                  <div className="mt-1 font-medium text-[var(--ink)]">{f.title}</div>
                  <div className="mt-0.5 font-mono text-[11px] text-[var(--muted)]">
                    {f.scanner_id} · {f.fingerprint.slice(0, 16)}…
                  </div>
                </button>
              </li>
            ))
          )}
        </ul>

        <section className="rounded-md border border-[var(--line)] bg-[var(--panel)] p-4 shadow-sm">
          {!selected ? (
            <p className="text-sm text-[var(--muted)]">Finding auswählen für Details.</p>
          ) : (
            <div className="space-y-3 text-sm">
              <h3 className="text-base font-semibold">{selected.title}</h3>
              <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-xs">
                <dt className="text-[var(--muted)]">Severity</dt>
                <dd className={sevTone(selected.severity)}>{selected.severity}</dd>
                <dt className="text-[var(--muted)]">Confidence</dt>
                <dd>{selected.confidence}</dd>
                <dt className="text-[var(--muted)]">Status</dt>
                <dd>{selected.status}</dd>
                <dt className="text-[var(--muted)]">Fingerprint</dt>
                <dd className="break-all font-mono">{selected.fingerprint}</dd>
                <dt className="text-[var(--muted)]">Scanner</dt>
                <dd>{selected.scanner_id}</dd>
                <dt className="text-[var(--muted)]">Category</dt>
                <dd>{selected.category}</dd>
              </dl>
              <div>
                <div className="text-xs text-[var(--muted)]">Description</div>
                <p className="mt-0.5">{selected.description || "—"}</p>
              </div>
              <div>
                <div className="text-xs text-[var(--muted)]">Remediation</div>
                <p className="mt-0.5">{selected.remediation || "—"}</p>
              </div>
              <div className="flex flex-wrap gap-2">
                {STATUSES.map((s) => (
                  <button
                    key={s}
                    type="button"
                    disabled={busy || selected.status === s}
                    onClick={() => void setStatus(s)}
                    className="rounded border border-[var(--line)] px-2 py-1 text-xs hover:bg-gray-50 disabled:opacity-50"
                  >
                    {s}
                  </button>
                ))}
              </div>
              <div>
                <div className="text-xs font-semibold uppercase tracking-wide text-[var(--muted)]">
                  Evidence
                </div>
                <ul className="mt-1 space-y-1">
                  {(selected.evidence || []).length === 0 ? (
                    <li className="text-[var(--muted)]">Keine Evidence.</li>
                  ) : (
                    selected.evidence.map((e) => (
                      <li key={e.id} className="font-mono text-[11px] break-all">
                        [{e.kind}] {e.path_or_blob_ref}
                      </li>
                    ))
                  )}
                </ul>
              </div>
              <div>
                <div className="text-xs font-semibold uppercase tracking-wide text-[var(--muted)]">
                  Occurrences (Dedup)
                </div>
                <ul className="mt-1 space-y-1">
                  {(selected.occurrences || []).map((o) => (
                    <li key={o.id} className="font-mono text-[11px] text-[var(--muted)]">
                      {o.seen_at} · scan={o.scan_id?.slice(0, 8) || "—"} · {o.raw_ref || "—"}
                    </li>
                  ))}
                </ul>
              </div>
            </div>
          )}
        </section>
      </div>
    </div>
  );
}
