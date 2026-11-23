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
}

export function createClient(baseUrl?: string): HckApiClient {
  return new HckApiClient(baseUrl ?? DEFAULT_BASE_URL);
}
