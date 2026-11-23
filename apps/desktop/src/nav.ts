export type ViewId =
  | "dashboard"
  | "projects"
  | "inventory"
  | "network"
  | "web"
  | "code"
  | "api"
  | "host"
  | "scans"
  | "findings"
  | "reports"
  | "tools"
  | "settings";

export interface NavItem {
  id: ViewId;
  label: string;
  group: "overview" | "security" | "ops";
  /** Security tabs that reuse Scan Manager with a capability filter. */
  scanCapability?: string;
}

export const NAV_ITEMS: NavItem[] = [
  { id: "dashboard", label: "Dashboard", group: "overview" },
  { id: "projects", label: "Projekte & Scope", group: "overview" },
  { id: "inventory", label: "Asset Inventory", group: "overview" },
  { id: "network", label: "Network Security", group: "security", scanCapability: "network" },
  { id: "web", label: "Web Security", group: "security", scanCapability: "web" },
  { id: "code", label: "Code Security", group: "security", scanCapability: "code" },
  { id: "api", label: "API Security", group: "security", scanCapability: "api" },
  { id: "host", label: "Host Security", group: "security", scanCapability: "host" },
  { id: "scans", label: "Scan Manager", group: "ops" },
  { id: "findings", label: "Findings", group: "ops" },
  { id: "reports", label: "Reports", group: "ops" },
  { id: "tools", label: "Tool Manager", group: "ops" },
  { id: "settings", label: "Settings", group: "ops" },
];

export function isScanSurface(view: ViewId): boolean {
  return (
    view === "scans" ||
    view === "network" ||
    view === "web" ||
    view === "code" ||
    view === "api" ||
    view === "host"
  );
}
