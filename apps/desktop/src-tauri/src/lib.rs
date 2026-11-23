//! Tauri shell: spawns and supervises the local FastAPI backend.

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

fn resolve_backend_dir(app: &AppHandle) -> Result<PathBuf, String> {
    let resource = app
        .path()
        .resource_dir()
        .map_err(|e| format!("resource dir: {e}"))?;

    let candidates = [
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../backend"),
        resource.join("backend"),
        PathBuf::from("backend"),
    ];

    for candidate in candidates {
        if candidate.join("app").join("main.py").exists() {
            return candidate.canonicalize().map_err(|e| e.to_string());
        }
    }
    Err("Backend-Verzeichnis nicht gefunden (erwartet apps/../backend)".into())
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

    let venv_python = if cfg!(windows) {
        backend_dir.join(".venv/Scripts/python.exe")
    } else {
        backend_dir.join(".venv/bin/python")
    };

    let mut command = if venv_python.exists() {
        Command::new(venv_python)
    } else {
        python_fallback()
    };

    command
        .current_dir(&backend_dir)
        .env("HCK_HOST", DEFAULT_HOST)
        .env("HCK_PORT", port.to_string())
        .env("HCK_DATA_DIR", &data_dir)
        .arg("-m")
        .arg("uvicorn")
        .arg("app.main:app")
        .arg("--host")
        .arg(DEFAULT_HOST)
        .arg("--port")
        .arg(port.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    let child = command
        .spawn()
        .map_err(|e| format!("Backend-Start fehlgeschlagen: {e}"))?;

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
