/** Tauri commands for local backend process supervision. */

import { invoke } from "@tauri-apps/api/core";

export type BackendInfo = {
  running: boolean;
  host: string;
  port: number;
  baseUrl: string;
  pid: number | null;
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

/** Detect whether we are inside a Tauri webview. */
export function isTauriRuntime(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}
