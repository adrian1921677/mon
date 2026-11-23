/**
 * Typed API client generated from OpenAPI (`openapi.json` → `schema.d.ts`).
 * Regenerate: `npm run generate:api` (requires running backend or committed openapi.json).
 */

import type { components, paths } from "./schema";

export type HealthResponse = components["schemas"]["HealthResponse"];
export type ProjectRead = components["schemas"]["ProjectRead"];
export type ProjectCreate = components["schemas"]["ProjectCreate"];
export type ProjectUpdate = components["schemas"]["ProjectUpdate"];
export type SettingRead = components["schemas"]["SettingRead"];
export type AuditEventRead = components["schemas"]["AuditEventRead"];

/** Phase-2 scope types (kept explicit so UI works before OpenAPI regen). */
export type ScopeEntryType =
  | "ip"
  | "cidr"
  | "domain"
  | "url"
  | "api_spec"
  | "path";
export type ScopeEntryStatus = "pending" | "verified" | "rejected";

export interface ScopeEntryRead {
  id: string;
  project_id: string;
  type: ScopeEntryType;
  value: string;
  meta_json: unknown;
  verified_at: string | null;
  status: ScopeEntryStatus;
  created_at: string;
}

export interface ScopeEntryCreate {
  type: ScopeEntryType;
  value: string;
  meta_json?: Record<string, unknown>;
}

export interface ScopeValidateRequest {
  mode: "entry" | "target" | "redirect" | "ssrf" | "active_gate";
  type: ScopeEntryType;
  value: string;
  meta_json?: Record<string, unknown>;
  redirect_location?: string | null;
  resolve_dns?: boolean;
}

export interface ScopeValidateResponse {
  allowed: boolean;
  reason: string;
  message: string;
  resolved_ips: string[];
  meta: Record<string, unknown>;
}

/** Phase-3 Tool Manager / scan stub types. */
export interface ToolLiveRead {
  scanner_id: string;
  display_name: string;
  description: string;
  capabilities: string[];
  preferred_runtime: string;
  is_active: boolean;
  is_test_only: boolean;
  integration_phase: number;
  status: string;
  version: string | null;
  path_or_runtime: string;
  message: string;
  binary_path: string | null;
  checked_at: string | null;
  persisted: boolean;
  meta: Record<string, unknown>;
}

export interface ScanTaskRead {
  id: string;
  scan_id: string;
  scanner_id: string;
  status: string;
  pid: number | null;
  handle_ref: string | null;
  exit_code: number | null;
  log_path: string | null;
  created_at: string;
}

export interface ScanRead {
  id: string;
  project_id: string;
  profile_id: string | null;
  status: string;
  started_at: string | null;
  finished_at: string | null;
  scope_snapshot_json: unknown;
  created_at: string;
  tasks: ScanTaskRead[];
}

export type FindingStatus = "open" | "fixed" | "false_positive";
export type FindingConfidence = "unknown" | "low" | "medium" | "high";
export type FindingSeverity = "info" | "low" | "medium" | "high" | "critical";

export interface FindingOccurrenceRead {
  id: string;
  finding_id: string;
  scan_id: string | null;
  asset_id: string | null;
  raw_ref: string | null;
  seen_at: string;
}

export interface EvidenceRead {
  id: string;
  finding_id: string;
  kind: string;
  path_or_blob_ref: string;
  created_at: string;
}

export interface FindingRead {
  id: string;
  project_id: string;
  fingerprint: string;
  title: string;
  severity: FindingSeverity;
  category: string;
  scanner_id: string;
  status: FindingStatus;
  confidence: FindingConfidence;
  remediation: string | null;
  description: string | null;
  first_seen_at: string;
  last_seen_at: string;
  occurrence_count: number;
  occurrences: FindingOccurrenceRead[];
  evidence: EvidenceRead[];
}

export interface FindingListResponse {
  items: FindingRead[];
  total: number;
  limit: number;
  offset: number;
}

export interface AssetRead {
  id: string;
  project_id: string;
  type: string;
  identifier: string;
  last_seen_at: string | null;
  labels_json: unknown;
  created_at: string;
}

export interface DashboardRead {
  project_id: string;
  asset_count: number;
  finding_counts: {
    total: number;
    by_severity: Record<string, number>;
    by_status: Record<string, number>;
  };
  critical_findings: Array<{
    id: string;
    title: string;
    severity: string;
    status: string;
    scanner_id: string;
    fingerprint: string;
    last_seen_at: string | null;
  }>;
  running_scans: Array<{
    id: string;
    status: string;
    started_at: string | null;
    created_at: string | null;
  }>;
  trend: Array<{ date: string; new_findings: number }>;
  scanners: {
    installed: number;
    total: number;
    items: Array<{
      scanner_id: string;
      display_name: string;
      status: string;
      version: string | null;
      preferred_runtime: string;
      integration_phase: number;
    }>;
  };
  recent_activities: Array<{
    kind: string;
    id: string;
    status: string;
    at: string | null;
    summary: string;
  }>;
  generated_at: string;
}

export interface ScanCompareResult {
  project_id: string;
  baseline_scan_id: string;
  candidate_scan_id: string;
  summary: {
    baseline_count: number;
    candidate_count: number;
    new: number;
    resolved: number;
    persistent: number;
  };
  new_findings: Array<{
    id: string;
    fingerprint: string;
    title: string;
    severity: string;
    status: string;
    scanner_id: string;
  }>;
  resolved_findings: Array<{
    id: string;
    fingerprint: string;
    title: string;
    severity: string;
    status: string;
    scanner_id: string;
  }>;
  persistent_findings: Array<{
    id: string;
    fingerprint: string;
    title: string;
    severity: string;
    status: string;
    scanner_id: string;
  }>;
  history: Array<{
    id: string;
    status: string;
    created_at: string | null;
    started_at: string | null;
    finished_at: string | null;
  }>;
}

export const DEFAULT_BASE_URL = "http://127.0.0.1:8765";
export const SETTING_ACTIVE_TESTS = "security.active_tests_enabled";

type HealthPath = paths["/health"]["get"];
type ProjectsListPath = paths["/api/v1/projects"]["get"];
type ProjectsCreatePath = paths["/api/v1/projects"]["post"];

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly body: unknown,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

export class HckApiClient {
  constructor(private readonly baseUrl: string = DEFAULT_BASE_URL) {}

  get base(): string {
    return this.baseUrl.replace(/\/$/, "");
  }

  private async request<T>(path: string, init?: RequestInit): Promise<T> {
    const response = await fetch(`${this.base}${path}`, {
      ...init,
      headers: {
        Accept: "application/json",
        ...(init?.body ? { "Content-Type": "application/json" } : {}),
        ...init?.headers,
      },
    });

    if (response.status === 204) {
      return undefined as T;
    }

    const text = await response.text();
    const data = text ? (JSON.parse(text) as unknown) : null;

    if (!response.ok) {
      throw new ApiError(
        `API ${response.status} ${path}`,
        response.status,
        data,
      );
    }
    return data as T;
  }

  health(): Promise<HealthResponse> {
    type Ok = HealthPath["responses"]["200"]["content"]["application/json"];
    return this.request<Ok>("/health");
  }

  listProjects(): Promise<ProjectRead[]> {
    type Ok = ProjectsListPath["responses"]["200"]["content"]["application/json"];
    return this.request<Ok>("/api/v1/projects");
  }

  createProject(body: ProjectCreate): Promise<ProjectRead> {
    type Ok = ProjectsCreatePath["responses"]["201"]["content"]["application/json"];
    return this.request<Ok>("/api/v1/projects", {
      method: "POST",
      body: JSON.stringify(body),
    });
  }

  getProject(id: string): Promise<ProjectRead> {
    return this.request<ProjectRead>(`/api/v1/projects/${encodeURIComponent(id)}`);
  }

  updateProject(id: string, body: ProjectUpdate): Promise<ProjectRead> {
    return this.request<ProjectRead>(`/api/v1/projects/${encodeURIComponent(id)}`, {
      method: "PATCH",
      body: JSON.stringify(body),
    });
  }

  deleteProject(id: string): Promise<void> {
    return this.request<void>(`/api/v1/projects/${encodeURIComponent(id)}`, {
      method: "DELETE",
    });
  }

  listSettings(): Promise<SettingRead[]> {
    return this.request<SettingRead[]>("/api/v1/settings");
  }

  upsertSetting(key: string, value_json: unknown): Promise<SettingRead> {
    return this.request<SettingRead>(`/api/v1/settings/${encodeURIComponent(key)}`, {
      method: "PUT",
      body: JSON.stringify({ value_json }),
    });
  }

  listAuditEvents(projectId?: string, limit = 50): Promise<AuditEventRead[]> {
    const params = new URLSearchParams({ limit: String(limit) });
    if (projectId) params.set("project_id", projectId);
    return this.request<AuditEventRead[]>(`/api/v1/audit-events?${params}`);
  }

  listScope(projectId: string): Promise<ScopeEntryRead[]> {
    return this.request<ScopeEntryRead[]>(
      `/api/v1/projects/${encodeURIComponent(projectId)}/scope`,
    );
  }

  createScope(projectId: string, body: ScopeEntryCreate): Promise<ScopeEntryRead> {
    return this.request<ScopeEntryRead>(
      `/api/v1/projects/${encodeURIComponent(projectId)}/scope`,
      { method: "POST", body: JSON.stringify(body) },
    );
  }

  deleteScope(projectId: string, entryId: string): Promise<void> {
    return this.request<void>(
      `/api/v1/projects/${encodeURIComponent(projectId)}/scope/${encodeURIComponent(entryId)}`,
      { method: "DELETE" },
    );
  }

  validateScope(
    projectId: string,
    body: ScopeValidateRequest,
  ): Promise<ScopeValidateResponse> {
    return this.request<ScopeValidateResponse>(
      `/api/v1/projects/${encodeURIComponent(projectId)}/scope/validate`,
      { method: "POST", body: JSON.stringify(body) },
    );
  }

  listTools(persist = false): Promise<ToolLiveRead[]> {
    const params = new URLSearchParams();
    if (persist) params.set("persist", "true");
    const q = params.toString();
    return this.request<ToolLiveRead[]>(`/api/v1/tools${q ? `?${q}` : ""}`);
  }

  refreshTools(): Promise<unknown[]> {
    return this.request<unknown[]>("/api/v1/tools/refresh", { method: "POST" });
  }

  listScans(projectId: string): Promise<ScanRead[]> {
    return this.request<ScanRead[]>(
      `/api/v1/projects/${encodeURIComponent(projectId)}/scans`,
    );
  }

  createScan(
    projectId: string,
    body: { scanner_ids: string[]; depth?: string },
  ): Promise<ScanRead> {
    return this.request<ScanRead>(
      `/api/v1/projects/${encodeURIComponent(projectId)}/scans`,
      { method: "POST", body: JSON.stringify(body) },
    );
  }

  getScan(projectId: string, scanId: string): Promise<ScanRead> {
    return this.request<ScanRead>(
      `/api/v1/projects/${encodeURIComponent(projectId)}/scans/${encodeURIComponent(scanId)}`,
    );
  }

  listFindings(
    projectId: string,
    params?: {
      status?: FindingStatus;
      severity?: FindingSeverity;
      scanner_id?: string;
      q?: string;
      limit?: number;
      offset?: number;
    },
  ): Promise<FindingListResponse> {
    const q = new URLSearchParams();
    if (params?.status) q.set("status", params.status);
    if (params?.severity) q.set("severity", params.severity);
    if (params?.scanner_id) q.set("scanner_id", params.scanner_id);
    if (params?.q) q.set("q", params.q);
    if (params?.limit != null) q.set("limit", String(params.limit));
    if (params?.offset != null) q.set("offset", String(params.offset));
    const qs = q.toString();
    return this.request<FindingListResponse>(
      `/api/v1/projects/${encodeURIComponent(projectId)}/findings${qs ? `?${qs}` : ""}`,
    );
  }

  getFinding(projectId: string, findingId: string): Promise<FindingRead> {
    return this.request<FindingRead>(
      `/api/v1/projects/${encodeURIComponent(projectId)}/findings/${encodeURIComponent(findingId)}`,
    );
  }

  updateFinding(
    projectId: string,
    findingId: string,
    body: {
      status?: FindingStatus;
      confidence?: FindingConfidence;
      remediation?: string | null;
      description?: string | null;
    },
  ): Promise<FindingRead> {
    return this.request<FindingRead>(
      `/api/v1/projects/${encodeURIComponent(projectId)}/findings/${encodeURIComponent(findingId)}`,
      { method: "PATCH", body: JSON.stringify(body) },
    );
  }

  getDashboard(projectId: string): Promise<DashboardRead> {
    return this.request<DashboardRead>(
      `/api/v1/projects/${encodeURIComponent(projectId)}/dashboard`,
    );
  }

  listAssets(projectId: string): Promise<AssetRead[]> {
    return this.request<AssetRead[]>(
      `/api/v1/projects/${encodeURIComponent(projectId)}/assets`,
    );
  }

  async downloadReport(
    projectId: string,
    kind: "project" | { findingId: string },
    format: "json" | "pdf",
  ): Promise<{ blob: Blob; filename: string; contentType: string }> {
    const path =
      typeof kind === "string"
        ? `/api/v1/projects/${encodeURIComponent(projectId)}/reports/project?format=${format}`
        : `/api/v1/projects/${encodeURIComponent(projectId)}/reports/findings/${encodeURIComponent(kind.findingId)}?format=${format}`;
    const response = await fetch(`${this.base}${path}`, { headers: { Accept: "*/*" } });
    if (!response.ok) {
      const text = await response.text();
      let data: unknown = text;
      try {
        data = text ? JSON.parse(text) : null;
      } catch {
        /* keep text */
      }
      throw new ApiError(`API ${response.status} ${path}`, response.status, data);
    }
    const blob = await response.blob();
    const cd = response.headers.get("Content-Disposition") || "";
    const match = /filename="?([^"]+)"?/.exec(cd);
    const filename =
      match?.[1] ||
      (typeof kind === "string"
        ? `hck-project.${format}`
        : `hck-finding.${format}`);
    return {
      blob,
      filename,
      contentType: response.headers.get("Content-Type") || blob.type,
    };
  }

  compareScans(
    projectId: string,
    body: { baseline_scan_id: string; candidate_scan_id: string },
  ): Promise<ScanCompareResult> {
    return this.request<ScanCompareResult>(
      `/api/v1/projects/${encodeURIComponent(projectId)}/reports/compare`,
      { method: "POST", body: JSON.stringify(body) },
    );
  }
}

export function createClient(baseUrl?: string): HckApiClient {
  return new HckApiClient(baseUrl ?? DEFAULT_BASE_URL);
}
