//! Tauri shell: spawns and supervises the local FastAPI backend.

use std::fs::OpenOptions;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;

use serde::Serialize;
use tauri::{AppHandle, Manager, State};

const DEFAULT_HOST: &str = "127.0.0.1";
const DEFAULT_PORT: u16 = 8765;

struct BackendState {
    child: Mutex<Option<Child>>,
    port: u16,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct BackendInfo {
    running: bool,
    host: String,
    port: u16,
    base_url: String,
    pid: Option<u32>,
}

fn backend_base_url(port: u16) -> String {
    format!("http://{DEFAULT_HOST}:{port}")
}

fn snapshot_info(state: &BackendState) -> BackendInfo {
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
    BackendInfo {
        running,
        host: DEFAULT_HOST.to_string(),
        port: state.port,
        base_url: backend_base_url(state.port),
        pid,
    }
}

/// Locate the Python backend package directory (`…/backend` containing `app/main.py`).
fn resolve_backend_dir(app: &AppHandle) -> Result<PathBuf, String> {
    let resource = app
        .path()
        .resource_dir()
        .map_err(|e| format!("resource dir: {e}"))?;

    let candidates = [
        // Dev: monorepo layout next to apps/desktop/src-tauri
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../backend"),
        // Packaged: bundled under $RESOURCE/backend
        resource.join("backend"),
        // Fallback: cwd-relative (scripts / portable layout)
        PathBuf::from("backend"),
        PathBuf::from("../backend"),
    ];

    for candidate in candidates {
        if candidate.join("app").join("main.py").exists() {
            return candidate.canonicalize().map_err(|e| e.to_string());
        }
    }
    Err(
        "Backend-Verzeichnis nicht gefunden. Erwartet `backend/app/main.py` \
         (Dev: Repo-Root; Installer: Ressourcenordner). Siehe README / scripts/windows/setup-backend.ps1."
            .into(),
    )
}

fn python_fallback() -> Command {
    if cfg!(windows) {
        let mut c = Command::new("py");
        c.arg("-3");
        c
    } else {
        Command::new("python3")
    }
}

/// Prefer explicit HCK_PYTHON, then portable/app-data venv, then backend/.venv, then system Python.
fn resolve_python(app: &AppHandle, backend_dir: &PathBuf) -> Result<Command, String> {
    if let Ok(explicit) = std::env::var("HCK_PYTHON") {
        let path = PathBuf::from(&explicit);
        if path.exists() {
            return Ok(Command::new(path));
        }
        return Err(format!("HCK_PYTHON gesetzt, aber nicht gefunden: {explicit}"));
    }

    let mut candidates: Vec<PathBuf> = Vec::new();

    if let Ok(data_dir) = app.path().app_data_dir() {
        if cfg!(windows) {
            candidates.push(data_dir.join("python-venv/Scripts/python.exe"));
            candidates.push(data_dir.join(".venv/Scripts/python.exe"));
        } else {
            candidates.push(data_dir.join("python-venv/bin/python"));
            candidates.push(data_dir.join(".venv/bin/python"));
        }
    }

    if cfg!(windows) {
        candidates.push(backend_dir.join(".venv/Scripts/python.exe"));
        // Portable embeddable layout next to backend
        candidates.push(backend_dir.join("python/python.exe"));
        candidates.push(backend_dir.join("runtime/python.exe"));
    } else {
        candidates.push(backend_dir.join(".venv/bin/python"));
        candidates.push(backend_dir.join("python/bin/python"));
        candidates.push(backend_dir.join("runtime/bin/python"));
    }

    for path in candidates {
        if path.exists() {
            return Ok(Command::new(path));
        }
    }

    Ok(python_fallback())
}

fn open_log_file(data_dir: &PathBuf) -> Option<std::fs::File> {
    let log_path = data_dir.join("backend.log");
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)
        .ok()
}

fn spawn_backend_process(app: &AppHandle, state: &BackendState) -> Result<BackendInfo, String> {
    let current = snapshot_info(state);
    if current.running {
        return Ok(current);
    }

    let backend_dir = resolve_backend_dir(app)?;
    let port = state.port;
    let data_dir = app
        .path()
        .app_data_dir()
        .map_err(|e| format!("app data dir: {e}"))?;
    std::fs::create_dir_all(&data_dir).map_err(|e| e.to_string())?;

    let mut command = resolve_python(app, &backend_dir)?;

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

    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        command.creation_flags(CREATE_NO_WINDOW);
    }

    let child = command.spawn().map_err(|e| {
        format!(
            "Backend-Start fehlgeschlagen: {e}. \
             Windows: `scripts/windows/setup-backend.ps1` ausführen oder HCK_PYTHON setzen. \
             Log: {}",
            data_dir.join("backend.log").display()
        )
    })?;

    {
        let mut guard = state.child.lock().expect("backend mutex");
        *guard = Some(child);
    }

    Ok(snapshot_info(state))
}

#[tauri::command]
fn get_backend_info(state: State<'_, BackendState>) -> BackendInfo {
    snapshot_info(&state)
}

#[tauri::command]
fn start_backend(app: AppHandle, state: State<'_, BackendState>) -> Result<BackendInfo, String> {
    spawn_backend_process(&app, &state)
}

#[tauri::command]
fn stop_backend(state: State<'_, BackendState>) -> Result<BackendInfo, String> {
    {
        let mut guard = state.child.lock().expect("backend mutex");
        if let Some(mut child) = guard.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
    Ok(snapshot_info(&state))
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .manage(BackendState {
            child: Mutex::new(None),
            port: DEFAULT_PORT,
        })
        .invoke_handler(tauri::generate_handler![
            get_backend_info,
            start_backend,
            stop_backend
        ])
        .setup(|app| {
            let handle = app.handle().clone();
            let state = handle.state::<BackendState>();
            if let Err(err) = spawn_backend_process(&handle, &state) {
                eprintln!("[hck] backend auto-start: {err}");
            }
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
