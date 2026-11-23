#!/usr/bin/env bash
# Hck Linux Security Audit — read-only checks (no exploits / no package mutation).
# Usage: bash linux_host_audit.sh --out /path/to/out.json
set -eu

OUT=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --out) OUT="${2:-}"; shift 2 ;;
    *) shift ;;
  esac
done

TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT

host_name="$(hostname 2>/dev/null || echo unknown)"
os_line="$(uname -a 2>/dev/null || echo unknown)"

# Emit JSON via Python for safe escaping (python3 usually present on WSL/Linux).
export HCK_AUDIT_HOST="$host_name"
export HCK_AUDIT_OS="$os_line"

python3 - <<'PY' >"$TMP"
import json, os, stat, subprocess
from pathlib import Path

checks = []

def add(cid, title, status, severity, detail):
    checks.append({
        "id": cid,
        "title": title,
        "status": status,
        "severity": severity,
        "detail": detail,
    })

def run(cmd):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=15, check=False)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except Exception as exc:  # noqa: BLE001
        return 99, str(exc)

# 1) World-writable sensitive files
for path in ("/etc/passwd", "/etc/shadow", "/etc/sudoers"):
    p = Path(path)
    if not p.exists():
        add(f"perm.{p.name}", f"Permissions {path}", "info", "info", "missing")
        continue
    mode = p.stat().st_mode
    if mode & stat.S_IWOTH:
        add(f"perm.{p.name}", f"Permissions {path}", "fail", "critical", "world-writable")
    elif path.endswith("shadow") and (mode & (stat.S_IROTH | stat.S_IRGRP)):
        add(f"perm.{p.name}", f"Permissions {path}", "fail", "high", "group/other readable")
    else:
        add(f"perm.{p.name}", f"Permissions {path}", "pass", "info", oct(stat.S_IMODE(mode)))

# 2) SSH PermitRootLogin / PasswordAuthentication (sshd_config)
sshd = Path("/etc/ssh/sshd_config")
if sshd.is_file():
    text = sshd.read_text(encoding="utf-8", errors="replace")
    def effective(key, default=""):
        val = default
        for line in text.splitlines():
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            parts = s.split(None, 1)
            if len(parts) == 2 and parts[0].lower() == key.lower():
                val = parts[1].strip()
        return val
    root = effective("PermitRootLogin", "prohibit-password")
    if root.lower() in {"yes", "without-password"}:
        add("ssh.permit_root", "SSH PermitRootLogin", "fail", "high", f"value={root}")
    else:
        add("ssh.permit_root", "SSH PermitRootLogin", "pass", "info", f"value={root}")
    pw = effective("PasswordAuthentication", "yes")
    if pw.lower() == "yes":
        add("ssh.password_auth", "SSH PasswordAuthentication", "warn", "medium", "password auth enabled")
    else:
        add("ssh.password_auth", "SSH PasswordAuthentication", "pass", "info", f"value={pw}")
else:
    add("ssh.config", "SSH sshd_config", "info", "info", "not present")

# 3) Firewall presence (ufw / firewalld / nft) — status only
code, out = run(["ufw", "status"])
if code == 0 and "Status: active" in out:
    add("fw.ufw", "UFW firewall", "pass", "info", "active")
elif code == 0 and "Status: inactive" in out:
    add("fw.ufw", "UFW firewall", "fail", "medium", "inactive")
else:
    code2, out2 = run(["systemctl", "is-active", "firewalld"])
    if code2 == 0 and "active" in out2:
        add("fw.firewalld", "firewalld", "pass", "info", "active")
    else:
        code3, _ = run(["nft", "list", "ruleset"])
        if code3 == 0:
            add("fw.nft", "nftables ruleset", "info", "info", "nft available (ruleset readable)")
        else:
            add("fw", "Host firewall", "warn", "medium", "no active ufw/firewalld detected")

# 4) Unattended upgrades package present?
if Path("/etc/apt/apt.conf.d/20auto-upgrades").is_file() or Path("/etc/apt/apt.conf.d/50unattended-upgrades").is_file():
    add("updates.unattended", "Unattended upgrades config", "pass", "info", "config present")
else:
    add("updates.unattended", "Unattended upgrades config", "warn", "low", "no common unattended-upgrades config found")

# 5) Listening sockets summary (ss) — informational count
code, out = run(["ss", "-tuln"])
if code == 0:
    lines = [ln for ln in out.splitlines() if "LISTEN" in ln or "UNCONN" in ln]
    add("net.listen", "Listening sockets (ss)", "info", "info", f"count={len(lines)}")
else:
    add("net.listen", "Listening sockets", "warn", "low", "ss unavailable")

# 6) Core dump pattern / ASLR
aslr = Path("/proc/sys/kernel/randomize_va_space")
if aslr.is_file():
    val = aslr.read_text(encoding="utf-8", errors="replace").strip()
    if val == "2":
        add("kernel.aslr", "Kernel ASLR", "pass", "info", f"randomize_va_space={val}")
    elif val == "0":
        add("kernel.aslr", "Kernel ASLR", "fail", "high", "ASLR disabled")
    else:
        add("kernel.aslr", "Kernel ASLR", "warn", "medium", f"randomize_va_space={val}")

print(json.dumps({
    "scanner": "linux_host_audit",
    "host": os.environ.get("HCK_AUDIT_HOST", ""),
    "os": os.environ.get("HCK_AUDIT_OS", ""),
    "checks": checks,
}, indent=2))
PY

if [ -n "$OUT" ]; then
  cp "$TMP" "$OUT"
fi
cat "$TMP"
