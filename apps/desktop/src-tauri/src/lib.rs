//! Tauri shell: spawns and supervises the local FastAPI backend.
//!
//! After an NSIS/MSI install there is no bundled CPython. The shell looks for
//! `HCK_PYTHON`, an AppData venv (`python-venv`), then system `py`/`python`.
//! If dependencies are missing it can bootstrap the AppData venv from the
//! bundled backend sources (`setup_backend` / auto on first start).

use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

use serde::Serialize;
use tauri::{AppHandle, Manager, State};

const DEFAULT_HOST: &str = "127.0.0.1";
const DEFAULT_PORT: u16 = 8765;
const READY_TIMEOUT: Duration = Duration::from_secs(12);
const READY_POLL: Duration = Duration::from_millis(250);
const VENV_DIR_NAME: &str = "python-venv";
const READY_MARKER: &str = ".hck-backend-ready";

struct BackendState {
    child: Mutex<Option<Child>>,
    port: u16,
    last_error: Mutex<Option<String>>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct BackendInfo {
    running: bool,
    host: String,
    port: u16,
    base_url: String,
    pid: Option<u32>,
    /// True when no usable interpreter/venv with deps was found.
    needs_setup: bool,
    /// Last spawn/setup error (if any).
    last_error: Option<String>,
    /// Resolved Python path used for the last successful spawn attempt.
    python_path: Option<String>,
    /// Absolute path to `backend.log` (AppData).
    log_path: Option<String>,
    /// Absolute path to AppData directory.
    data_dir: Option<String>,
    /// Bundled or discovered backend package directory.
    backend_dir: Option<String>,
}

fn backend_base_url(port: u16) -> String {
    format!("http://{DEFAULT_HOST}:{port}")
}

fn set_last_error(state: &BackendState, msg: Option<String>) {
    if let Ok(mut guard) = state.last_error.lock() {
        *guard = msg;
    }
}

fn take_last_error(state: &BackendState) -> Option<String> {
    state
        .last_error
        .lock()
        .ok()
        .and_then(|g| g.clone())
}

fn app_data_dir(app: &AppHandle) -> Result<PathBuf, String> {
    app.path()
        .app_data_dir()
        .map_err(|e| format!("app data dir: {e}"))
}

fn log_path_for(data_dir: &Path) -> PathBuf {
    data_dir.join("backend.log")
}

fn venv_python_path(data_dir: &Path) -> PathBuf {
    if cfg!(windows) {
        data_dir.join(VENV_DIR_NAME).join("Scripts").join("python.exe")
    } else {
        data_dir.join(VENV_DIR_NAME).join("bin").join("python")
    }
}

fn venv_ready(data_dir: &Path) -> bool {
    let py = venv_python_path(data_dir);
    py.exists() && data_dir.join(VENV_DIR_NAME).join(READY_MARKER).exists()
}

/// Locate the Python backend package directory (`…/backend` containing `app/main.py`).
fn resolve_backend_dir(app: &AppHandle) -> Result<PathBuf, String> {
    let resource = app
        .path()
        .resource_dir()
        .map_err(|e| format!("resource dir: {e}"))?;

    let mut candidates: Vec<PathBuf> = vec![
        // Dev: monorepo root (src-tauri → desktop → apps → repo)
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../backend"),
        // Packaged: bundled under $RESOURCE/backend
        resource.join("backend"),
        resource.join("resources").join("backend"),
        // Fallback: cwd-relative (scripts / portable layout)
        PathBuf::from("backend"),
        PathBuf::from("../backend"),
    ];

    // Next to the running executable (NSIS currentUser → %LOCALAPPDATA%\Hck\).
    if let Ok(exe) = std::env::current_exe() {
        if let Some(exe_dir) = exe.parent() {
            candidates.push(exe_dir.join("backend"));
            candidates.push(exe_dir.join("resources").join("backend"));
            if let Some(parent) = exe_dir.parent() {
                candidates.push(parent.join("backend"));
            }
        }
    }

    // Common Windows install roots (setup script / MSI).
    if cfg!(windows) {
        if let Ok(local) = std::env::var("LOCALAPPDATA") {
            candidates.push(PathBuf::from(&local).join("Hck").join("backend"));
            candidates.push(
                PathBuf::from(&local)
                    .join("Programs")
                    .join("Hck")
                    .join("backend"),
            );
        }
        if let Ok(pf) = std::env::var("ProgramFiles") {
            candidates.push(PathBuf::from(pf).join("Hck").join("backend"));
        }
    }

    for candidate in candidates {
        if candidate.join("app").join("main.py").exists() {
            return candidate.canonicalize().map_err(|e| e.to_string());
        }
    }
    Err(
        "Backend-Verzeichnis nicht gefunden. Erwartet `backend/app/main.py` \
         (Dev: Repo-Root; Installer: Ressourcenordner neben Hck.exe). \
         Siehe README / setup-backend.ps1 -Portable."
            .into(),
    )
}

fn apply_no_window(command: &mut Command) {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        command.creation_flags(CREATE_NO_WINDOW);
    }
    let _ = command;
}

fn run_capturing(command: &mut Command) -> Result<(i32, String), String> {
    apply_no_window(command);
    command.stdin(Stdio::null());
    command.stdout(Stdio::piped());
    command.stderr(Stdio::piped());
    let output = command
        .output()
        .map_err(|e| format!("Befehl fehlgeschlagen: {e}"))?;
    let mut text = String::new();
    text.push_str(&String::from_utf8_lossy(&output.stdout));
    if !output.stderr.is_empty() {
        if !text.is_empty() {
            text.push('\n');
        }
        text.push_str(&String::from_utf8_lossy(&output.stderr));
    }
    let code = output.status.code().unwrap_or(-1);
    Ok((code, text.trim().to_string()))
}

fn python_module_ok(python: &Path, module: &str) -> bool {
    let mut cmd = Command::new(python);
    cmd.args(["-c", &format!("import {module}")]);
    matches!(run_capturing(&mut cmd), Ok((0, _)))
}

fn resolve_system_python() -> Option<PathBuf> {
    // Prefer the Windows launcher, then `python` / `python3`.
    let probes: &[&[&str]] = if cfg!(windows) {
        &[&["py", "-3"], &["python"], &["python3"]]
    } else {
        &[&["python3"], &["python"]]
    };

    for parts in probes {
        let (bin, args) = parts.split_first()?;
        let mut cmd = Command::new(bin);
        cmd.args(args);
        cmd.args(["-c", "import sys; print(sys.executable)"]);
        if let Ok((0, out)) = run_capturing(&mut cmd) {
            let path = PathBuf::from(out.lines().next().unwrap_or("").trim());
            if path.exists() {
                return Some(path);
            }
        }
    }
    None
}

/// Prefer explicit HCK_PYTHON, then ready AppData venv, then backend/.venv, then system Python.
fn resolve_python(app: &AppHandle, backend_dir: &Path) -> Result<PathBuf, String> {
    if let Ok(explicit) = std::env::var("HCK_PYTHON") {
        let path = PathBuf::from(&explicit);
        if path.exists() {
            return Ok(path);
        }
        return Err(format!("HCK_PYTHON gesetzt, aber nicht gefunden: {explicit}"));
    }

    let mut candidates: Vec<PathBuf> = Vec::new();

    if let Ok(data_dir) = app_data_dir(app) {
        candidates.push(venv_python_path(&data_dir));
        if cfg!(windows) {
            candidates.push(data_dir.join(".venv/Scripts/python.exe"));
        } else {
            candidates.push(data_dir.join(".venv/bin/python"));
        }
    }

    if cfg!(windows) {
        candidates.push(backend_dir.join(".venv/Scripts/python.exe"));
        candidates.push(backend_dir.join("python/python.exe"));
        candidates.push(backend_dir.join("runtime/python.exe"));
    } else {
        candidates.push(backend_dir.join(".venv/bin/python"));
        candidates.push(backend_dir.join("python/bin/python"));
        candidates.push(backend_dir.join("runtime/bin/python"));
    }

    for path in candidates {
        if path.exists() {
            return Ok(path);
        }
    }

    resolve_system_python().ok_or_else(|| {
        "Kein Python gefunden. Installiere Python 3.11+ von https://www.python.org/downloads/ \
         (Haken „Add to PATH“) und starte Hck erneut — oder führe setup-backend.ps1 -Portable aus."
            .into()
    })
}

fn open_log_file(data_dir: &Path) -> Option<std::fs::File> {
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path_for(data_dir))
        .ok()
}

fn append_setup_log(data_dir: &Path, message: &str) {
    if let Ok(mut f) = OpenOptions::new()
        .create(true)
        .append(true)
        .open(data_dir.join("backend-setup.log"))
    {
        use std::io::Write;
        let _ = writeln!(f, "{message}");
    }
}

fn tail_log(path: &Path, max_bytes: u64) -> String {
    let Ok(mut f) = std::fs::File::open(path) else {
        return String::new();
    };
    let Ok(meta) = f.metadata() else {
        return String::new();
    };
    let len = meta.len();
    let start = len.saturating_sub(max_bytes);
    if f.seek(SeekFrom::Start(start)).is_err() {
        return String::new();
    }
    let mut buf = String::new();
    let _ = f.read_to_string(&mut buf);
    buf.trim().to_string()
}

fn port_open(port: u16) -> bool {
    use std::net::SocketAddr;
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    TcpStream::connect_timeout(&addr, Duration::from_millis(200)).is_ok()
}

/// Create AppData venv and install the bundled backend (non-editable).
fn bootstrap_appdata_venv(app: &AppHandle, backend_dir: &Path) -> Result<PathBuf, String> {
    let data_dir = app_data_dir(app)?;
    std::fs::create_dir_all(&data_dir).map_err(|e| e.to_string())?;

    let venv_dir = data_dir.join(VENV_DIR_NAME);
    let venv_py = venv_python_path(&data_dir);

    let system_py = resolve_system_python().ok_or_else(|| {
        "Python 3.11+ fehlt. Bitte von https://www.python.org/downloads/ installieren \
         („Add python.exe to PATH“), danach in der App „Backend einrichten“ erneut klicken."
            .to_string()
    })?;

    append_setup_log(
        &data_dir,
        &format!(
            "=== bootstrap start ===\nsystem_python={}\nbackend={}\nvenv={}",
            system_py.display(),
            backend_dir.display(),
            venv_dir.display()
        ),
    );

    if !venv_py.exists() {
        append_setup_log(&data_dir, "creating venv…");
        let mut cmd = Command::new(&system_py);
        cmd.args(["-m", "venv"]).arg(&venv_dir);
        let (code, out) = run_capturing(&mut cmd)?;
        append_setup_log(&data_dir, &out);
        if code != 0 || !venv_py.exists() {
            return Err(format!(
                "venv-Erstellung fehlgeschlagen (exit {code}). Log: {}",
                data_dir.join("backend-setup.log").display()
            ));
        }
    }

    append_setup_log(&data_dir, "pip install backend…");
    let mut upgrade = Command::new(&venv_py);
    upgrade.args(["-m", "pip", "install", "--upgrade", "pip"]);
    let (code, out) = run_capturing(&mut upgrade)?;
    append_setup_log(&data_dir, &out);
    if code != 0 {
        return Err(format!("pip upgrade fehlgeschlagen (exit {code})"));
    }

    // Non-editable: works with read-only install dirs and survives AppData venv moves.
    let mut install = Command::new(&venv_py);
    install.args(["-m", "pip", "install"]).arg(backend_dir);
    let (code, out) = run_capturing(&mut install)?;
    append_setup_log(&data_dir, &out);
    if code != 0 {
        return Err(format!(
            "pip install des Backends fehlgeschlagen (exit {code}). \
             Details: {}",
            data_dir.join("backend-setup.log").display()
        ));
    }

    if !python_module_ok(&venv_py, "uvicorn") {
        return Err(
            "uvicorn nach pip install nicht importierbar — siehe backend-setup.log.".into(),
        );
    }

    // Best-effort migrations; desktop also bootstraps via create_all.
    let mut alembic = Command::new(&venv_py);
    alembic
        .current_dir(backend_dir)
        .env("HCK_DATA_DIR", &data_dir)
        .args(["-m", "alembic", "upgrade", "head"]);
    match run_capturing(&mut alembic) {
        Ok((code, out)) => {
            append_setup_log(&data_dir, &format!("alembic exit={code}\n{out}"));
        }
        Err(e) => append_setup_log(&data_dir, &format!("alembic error: {e}")),
    }

    let marker = venv_dir.join(READY_MARKER);
    std::fs::write(&marker, format!("ready\nbackend={}\n", backend_dir.display()))
        .map_err(|e| e.to_string())?;
    append_setup_log(&data_dir, "=== bootstrap ok ===");

    Ok(venv_py)
}

/// Resolve a Python that can already import uvicorn. Does **not** run pip
/// (that would block the UI on first launch). Use `setup_backend` / the
/// in-app button for first-run bootstrap.
fn ensure_python_ready(app: &AppHandle, backend_dir: &Path) -> Result<PathBuf, String> {
    let data_dir = app_data_dir(app)?;
    if venv_python_path(&data_dir).exists() {
        let py = venv_python_path(&data_dir);
        if python_module_ok(&py, "uvicorn") {
            // Heal missing marker from older setups.
            let marker = data_dir.join(VENV_DIR_NAME).join(READY_MARKER);
            if !marker.exists() {
                let _ = std::fs::write(&marker, "ready\n");
            }
            return Ok(py);
        }
    }

    let python = resolve_python(app, backend_dir)?;
    if python_module_ok(&python, "uvicorn") {
        return Ok(python);
    }

    Err(
        "Python gefunden, aber Backend-Abhängigkeiten fehlen (uvicorn). \
         In der App „Backend einrichten“ klicken oder `setup-backend.ps1 -Portable` ausführen."
            .into(),
    )
}

fn snapshot_info(app: &AppHandle, state: &BackendState) -> BackendInfo {
    let mut guard = state.child.lock().expect("backend mutex");
    let mut pid = None;
    let mut running = false;
    if let Some(child) = guard.as_mut() {
        match child.try_wait() {
            Ok(None) => {
                running = true;
                pid = Some(child.id());
            }
            Ok(Some(_)) | Err(_) => {
                *guard = None;
            }
        }
    }
    drop(guard);

    let data_dir = app_data_dir(app).ok();
    let backend_dir = resolve_backend_dir(app).ok();
    // Lightweight: do not spawn Python on every UI poll.
    let needs_setup = match &data_dir {
        Some(dd) if venv_ready(dd) => false,
        Some(dd) if venv_python_path(dd).exists() => false,
        _ => {
            // No AppData venv yet — still ok if HCK_PYTHON / backend/.venv exists.
            backend_dir
                .as_ref()
                .map(|bd| resolve_python(app, bd).is_err())
                .unwrap_or(true)
                || take_last_error(state).is_some()
        }
    };

    let python_path = data_dir
        .as_ref()
        .map(|d| venv_python_path(d))
        .filter(|p| p.exists())
        .or_else(|| {
            backend_dir
                .as_ref()
                .and_then(|bd| resolve_python(app, bd).ok())
        })
        .map(|p| p.display().to_string());

    BackendInfo {
        running,
        host: DEFAULT_HOST.to_string(),
        port: state.port,
        base_url: backend_base_url(state.port),
        pid,
        needs_setup: needs_setup && !running && !port_open(state.port),
        last_error: take_last_error(state),
        python_path,
        log_path: data_dir
            .as_ref()
            .map(|d| log_path_for(d).display().to_string()),
        data_dir: data_dir.map(|d| d.display().to_string()),
        backend_dir: backend_dir.map(|d| d.display().to_string()),
    }
}

fn wait_until_ready(child: &mut Child, port: u16, log_path: &Path) -> Result<(), String> {
    let deadline = Instant::now() + READY_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let tail = tail_log(log_path, 4000);
                return Err(format!(
                    "Backend-Prozess beendet sich sofort (exit {status}). {}\n{}",
                    if tail.is_empty() {
                        "Kein Log — oft fehlt Python/venv (setup-backend / „Backend einrichten“)."
                            .to_string()
                    } else {
                        format!("Log-Auszug:\n{tail}")
                    },
                    format!("Vollständiges Log: {}", log_path.display())
                ));
            }
            Ok(None) => {
                if port_open(port) {
                    return Ok(());
                }
            }
            Err(e) => return Err(format!("Prozessstatus: {e}")),
        }
        if Instant::now() >= deadline {
            // Still alive but port not open yet — leave it running; UI will keep polling.
            return Ok(());
        }
        thread::sleep(READY_POLL);
    }
}

fn spawn_backend_process(app: &AppHandle, state: &BackendState) -> Result<BackendInfo, String> {
    let current = snapshot_info(app, state);
    if current.running {
        return Ok(current);
    }

    // Another instance may already serve the port.
    if port_open(state.port) {
        set_last_error(state, None);
        return Ok(BackendInfo {
            running: true,
            host: DEFAULT_HOST.to_string(),
            port: state.port,
            base_url: backend_base_url(state.port),
            pid: None,
            needs_setup: false,
            last_error: None,
            python_path: current.python_path,
            log_path: current.log_path,
            data_dir: current.data_dir,
            backend_dir: current.backend_dir,
        });
    }

    let backend_dir = resolve_backend_dir(app)?;
    let port = state.port;
    let data_dir = app_data_dir(app)?;
    std::fs::create_dir_all(&data_dir).map_err(|e| e.to_string())?;
    let log_file = log_path_for(&data_dir);

    let python = ensure_python_ready(app, &backend_dir).map_err(|e| {
        set_last_error(state, Some(e.clone()));
        e
    })?;

    let mut command = Command::new(&python);
    command
        .current_dir(&backend_dir)
        .env("HCK_HOST", DEFAULT_HOST)
        .env("HCK_PORT", port.to_string())
        .env("HCK_DATA_DIR", &data_dir)
        .env("PYTHONUNBUFFERED", "1")
        .env("PYTHONPATH", &backend_dir)
        .arg("-m")
        .arg("uvicorn")
        .arg("app.main:app")
        .arg("--host")
        .arg(DEFAULT_HOST)
        .arg("--port")
        .arg(port.to_string())
        .stdin(Stdio::null());

    if let Some(log) = open_log_file(&data_dir) {
        let log_err = log.try_clone().ok();
        command.stdout(Stdio::from(log));
        if let Some(err_file) = log_err {
            command.stderr(Stdio::from(err_file));
        } else {
            command.stderr(Stdio::null());
        }
    } else {
        command.stdout(Stdio::null()).stderr(Stdio::null());
    }

    apply_no_window(&mut command);

    let mut child = command.spawn().map_err(|e| {
        let msg = format!(
            "Backend-Start fehlgeschlagen: {e}. \
             Windows: in der App „Backend einrichten“ oder `setup-backend.ps1 -Portable`. \
             Log: {}",
            log_file.display()
        );
        set_last_error(state, Some(msg.clone()));
        msg
    })?;

    if let Err(err) = wait_until_ready(&mut child, port, &log_file) {
        let _ = child.kill();
        let _ = child.wait();
        set_last_error(state, Some(err.clone()));
        return Err(err);
    }

    {
        let mut guard = state.child.lock().expect("backend mutex");
        *guard = Some(child);
    }
    set_last_error(state, None);

    let mut info = snapshot_info(app, state);
    info.python_path = Some(python.display().to_string());
    info.needs_setup = false;
    Ok(info)
}

#[tauri::command]
fn get_backend_info(app: AppHandle, state: State<'_, BackendState>) -> BackendInfo {
    snapshot_info(&app, &state)
}

#[tauri::command]
fn start_backend(app: AppHandle, state: State<'_, BackendState>) -> Result<BackendInfo, String> {
    spawn_backend_process(&app, &state)
}

#[tauri::command]
fn stop_backend(app: AppHandle, state: State<'_, BackendState>) -> Result<BackendInfo, String> {
    {
        let mut guard = state.child.lock().expect("backend mutex");
        if let Some(mut child) = guard.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
    Ok(snapshot_info(&app, &state))
}

/// Create/repair the AppData venv and install backend deps (first-run / recovery).
#[tauri::command]
fn setup_backend(app: AppHandle, state: State<'_, BackendState>) -> Result<BackendInfo, String> {
    let backend_dir = resolve_backend_dir(&app)?;
    bootstrap_appdata_venv(&app, &backend_dir).map_err(|e| {
        set_last_error(&state, Some(e.clone()));
        e
    })?;
    spawn_backend_process(&app, &state)
}

#[tauri::command]
fn reveal_backend_log(app: AppHandle) -> Result<String, String> {
    let data_dir = app_data_dir(&app)?;
    std::fs::create_dir_all(&data_dir).map_err(|e| e.to_string())?;
    let log = log_path_for(&data_dir);
    if !log.exists() {
        std::fs::write(&log, "").map_err(|e| e.to_string())?;
    }
    // opener plugin: reveal folder containing the log
    use tauri_plugin_opener::OpenerExt;
    app.opener()
        .reveal_item_in_dir(&log)
        .map_err(|e| format!("Ordner öffnen fehlgeschlagen: {e}"))?;
    Ok(log.display().to_string())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .manage(BackendState {
            child: Mutex::new(None),
            port: DEFAULT_PORT,
            last_error: Mutex::new(None),
        })
        .invoke_handler(tauri::generate_handler![
            get_backend_info,
            start_backend,
            stop_backend,
            setup_backend,
            reveal_backend_log
        ])
        .setup(|app| {
            let handle = app.handle().clone();
            let state = handle.state::<BackendState>();
            if let Err(err) = spawn_backend_process(&handle, &state) {
                eprintln!("[hck] backend auto-start: {err}");
                set_last_error(&state, Some(err));
            }
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn venv_python_path_layout() {
        let base = PathBuf::from("/tmp/hck-data");
        let p = venv_python_path(&base);
        if cfg!(windows) {
            assert!(p.ends_with("python-venv/Scripts/python.exe") || p.ends_with(r"python-venv\Scripts\python.exe"));
        } else {
            assert!(p.ends_with("python-venv/bin/python"));
        }
    }

    #[test]
    fn log_path_name() {
        let p = log_path_for(Path::new("/data"));
        assert!(p.ends_with("backend.log"));
    }

    #[test]
    fn backend_url_format() {
        assert_eq!(backend_base_url(8765), "http://127.0.0.1:8765");
    }
}
