"""
Greenbone / OpenVAS GMP runner — invoked as ``python -m app.scanners.runners.gvm_scan``.

Uses ``gvm-cli`` (from gvm-tools) with argv lists only — never ``shell=True``.
Writes an OpenVAS/Greenbone XML report to ``--out``.

Connection (env):
  HCK_GVM_SOCKET   Unix socket path (default: /run/gvmd/gvmd.sock)
  HCK_GVM_USERNAME GMP username (default: admin)
  HCK_GVM_PASSWORD GMP password (required for live scans)
  HCK_GVM_TLS      if ``1``, use TLS to HCK_GVM_HOST:HCK_GVM_PORT instead of socket
  HCK_GVM_HOST / HCK_GVM_PORT  TLS endpoint (default 127.0.0.1:9390)
  HCK_GREENBONE_DOCKER_EXEC  optional container name — prefix commands with
                             ``docker exec <name>``

Exit codes: 0 success (report written), 2 usage/config error, 3 tool missing,
            4 GMP/scan failure.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import time
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path


def _die(code: int, msg: str) -> None:
    print(msg, file=sys.stderr)
    raise SystemExit(code)


def _which_gvm_cli() -> str | None:
    return shutil.which("gvm-cli") or shutil.which("gvm-script")


def _docker_prefix() -> list[str]:
    name = (os.environ.get("HCK_GREENBONE_DOCKER_EXEC") or "").strip()
    if not name:
        return []
    docker = shutil.which("docker")
    if not docker:
        _die(3, "HCK_GREENBONE_DOCKER_EXEC set but docker not on PATH")
    return [docker, "exec", "-i", name]


def _gvm_base_argv() -> list[str]:
    prefix = _docker_prefix()
    binary = _which_gvm_cli()
    if not binary and not prefix:
        _die(
            3,
            "gvm-cli / gvm-script not found on PATH. Install gvm-tools "
            "(pip install gvm-tools) or run Greenbone Community Edition via Docker "
            "and set HCK_GREENBONE_DOCKER_EXEC. See scanners/docs/greenbone.md.",
        )
    if prefix and not binary:
        # Inside container the binary is typically gvm-cli on PATH.
        binary = "gvm-cli"
    elif not binary:
        _die(3, "gvm-cli not found")

    user = os.environ.get("HCK_GVM_USERNAME", "admin")
    password = os.environ.get("HCK_GVM_PASSWORD", "")
    if not password:
        _die(
            2,
            "HCK_GVM_PASSWORD is required for GMP authentication "
            "(never invent findings without a live Greenbone connection).",
        )

    argv: list[str] = [*prefix, binary, "--gmp-username", user, "--gmp-password", password]
    if (os.environ.get("HCK_GVM_TLS") or "").strip() in {"1", "true", "yes"}:
        host = os.environ.get("HCK_GVM_HOST", "127.0.0.1")
        port = os.environ.get("HCK_GVM_PORT", "9390")
        argv.extend(["tls", "--hostname", host, "--port", port])
    else:
        sock = os.environ.get("HCK_GVM_SOCKET", "/run/gvmd/gvmd.sock")
        argv.extend(["socket", "--socketpath", sock])
    return argv


def _run_xml(base: list[str], xml_body: str, *, timeout: float) -> str:
    argv = [*base, "--xml", xml_body]
    try:
        proc = subprocess.run(
            argv,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
        )
    except subprocess.TimeoutExpired as exc:
        _die(4, f"gvm-cli timed out: {exc}")
    out = (proc.stdout or "") + (proc.stderr or "")
    if proc.returncode != 0:
        _die(4, f"gvm-cli failed (exit={proc.returncode}): {out[:2000]}")
    return proc.stdout or ""


def _attr_id(xml_text: str, tag: str) -> str | None:
    try:
        root = ET.fromstring(xml_text.strip() or "<empty/>")
    except ET.ParseError:
        return None
    el = root if root.tag == tag else root.find(tag)
    if el is None:
        # Some responses wrap status on the command element itself.
        if root.tag.endswith(tag) or tag in root.tag:
            return root.get("id")
        for child in root.iter():
            if child.tag == tag or child.tag.endswith(tag):
                cid = child.get("id")
                if cid:
                    return cid
        return root.get("id")
    return el.get("id")


def _first_id(xml_text: str, xpath_tag: str) -> str | None:
    try:
        root = ET.fromstring(xml_text.strip() or "<empty/>")
    except ET.ParseError:
        return None
    for el in root.iter():
        if el.tag == xpath_tag or el.tag.endswith(xpath_tag):
            cid = el.get("id")
            if cid:
                return cid
    return None


def _scan_config_id(base: list[str], depth: str) -> str:
    # Prefer named configs; fall back to first available.
    preferred = {
        "quick": ("Discovery", "Host Discovery"),
        "standard": ("Full and fast", "Base"),
        "deep": ("Full and very deep ultimate", "Full and fast"),
    }.get(depth, ("Full and fast", "Base"))

    raw = _run_xml(base, "<get_configs/>", timeout=60.0)
    try:
        root = ET.fromstring(raw.strip() or "<empty/>")
    except ET.ParseError as exc:
        _die(4, f"get_configs parse error: {exc}")

    configs: list[tuple[str, str]] = []
    for el in root.iter():
        if el.tag in {"config", "get_configs_response"} or el.tag.endswith("config"):
            cid = el.get("id")
            name_el = el.find("name")
            name = (name_el.text or "").strip() if name_el is not None else ""
            if cid and name:
                configs.append((cid, name))

    for want in preferred:
        for cid, name in configs:
            if name.lower() == want.lower():
                return cid
    if configs:
        return configs[0][0]
    _die(4, "no scan configs returned by gvmd")


def _wait_task(base: list[str], task_id: str, *, timeout: float) -> str:
    """Poll until Done; return report id."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        raw = _run_xml(
            base,
            f'<get_tasks task_id="{task_id}" details="1"/>',
            timeout=60.0,
        )
        try:
            root = ET.fromstring(raw.strip() or "<empty/>")
        except ET.ParseError:
            time.sleep(5.0)
            continue
        status = ""
        report_id = ""
        for el in root.iter():
            if el.tag == "status" or el.tag.endswith("status"):
                if el.text:
                    status = el.text.strip()
            if el.tag == "report" or el.tag.endswith("report"):
                rid = el.get("id")
                if rid:
                    report_id = rid
        if status.lower() in {"done", "stopped"} and report_id:
            return report_id
        if status.lower() in {"interrupted", "internal error"}:
            _die(4, f"task {task_id} ended with status={status}")
        time.sleep(5.0)
    _die(4, f"task {task_id} timed out waiting for Done")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Hck Greenbone GMP scan runner")
    parser.add_argument("--targets", required=True, help="Comma-separated hosts/CIDRs")
    parser.add_argument("--out", required=True, help="Output XML report path")
    parser.add_argument("--depth", default="standard", choices=("quick", "standard", "deep"))
    parser.add_argument("--poll-timeout", type=float, default=0.0, help="Seconds (0=auto)")
    args = parser.parse_args(argv)

    targets = [t.strip() for t in args.targets.split(",") if t.strip()]
    if not targets:
        _die(2, "no targets")

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    base = _gvm_base_argv()

    # Connectivity smoke
    _run_xml(base, "<get_version/>", timeout=30.0)

    config_id = _scan_config_id(base, args.depth)
    name = f"hck-{uuid.uuid4().hex[:12]}"
    hosts = ",".join(targets)

    create_target = _run_xml(
        base,
        f"<create_target><name>{name}</name><hosts>{hosts}</hosts></create_target>",
        timeout=60.0,
    )
    target_id = _attr_id(create_target, "create_target_response") or _first_id(
        create_target, "create_target_response"
    )
    if not target_id:
        # Response may be <create_target_response id="..."/>
        try:
            root = ET.fromstring(create_target.strip())
            target_id = root.get("id")
        except ET.ParseError:
            target_id = None
    if not target_id:
        _die(4, f"could not create target: {create_target[:1000]}")

    create_task = _run_xml(
        base,
        (
            f"<create_task><name>{name}</name>"
            f'<config id="{config_id}"/>'
            f'<target id="{target_id}"/>'
            f"</create_task>"
        ),
        timeout=60.0,
    )
    try:
        task_root = ET.fromstring(create_task.strip())
        task_id = task_root.get("id")
    except ET.ParseError:
        task_id = None
    if not task_id:
        _die(4, f"could not create task: {create_task[:1000]}")

    _run_xml(base, f'<start_task task_id="{task_id}"/>', timeout=60.0)

    poll = args.poll_timeout
    if poll <= 0:
        poll = 300.0 if args.depth == "quick" else 1800.0 if args.depth == "deep" else 900.0

    report_id = _wait_task(base, task_id, timeout=poll)

    # XML report format id is well-known for "XML" in Greenbone.
    # Prefer get_reports with details; filter format via report_format if needed.
    report_xml = _run_xml(
        base,
        f'<get_reports report_id="{report_id}" details="1" filter="apply_overrides=0 levels=hmlg"/>',
        timeout=120.0,
    )
    if "<report" not in report_xml and "<get_reports_response" not in report_xml:
        _die(4, "empty or unexpected report response")

    out_path.write_text(report_xml, encoding="utf-8")
    print(f"wrote report to {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
