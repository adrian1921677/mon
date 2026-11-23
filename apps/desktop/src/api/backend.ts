/** Tauri commands for local backend process supervision. */

import { invoke } from "@tauri-apps/api/core";

export type BackendInfo = {
  running: boolean;
  host: string;
  port: number;
  baseUrl: string;
  pid: number | null;
  needsSetup?: boolean;
  lastError?: string | null;
  pythonPath?: string | null;
  logPath?: string | null;
  dataDir?: string | null;
  backendDir?: string | null;
};

export async function getBackendInfo(): Promise<BackendInfo> {
  return invoke<BackendInfo>("get_backend_info");
}

export async function startBackend(): Promise<BackendInfo> {
  return invoke<BackendInfo>("start_backend");
}

export async function stopBackend(): Promise<BackendInfo> {
  return invoke<BackendInfo>("stop_backend");
}

/** Create/repair AppData venv and start the backend (first-run). */
export async function setupBackend(): Promise<BackendInfo> {
  return invoke<BackendInfo>("setup_backend");
}

/** Reveal backend.log in the system file manager. */
export async function revealBackendLog(): Promise<string> {
  return invoke<string>("reveal_backend_log");
}

/** Detect whether we are inside a Tauri webview. */
export function isTauriRuntime(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}
