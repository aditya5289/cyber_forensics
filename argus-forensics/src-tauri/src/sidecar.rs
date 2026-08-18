//! Spawn and monitor the embedded Python ARGUS sidecar.

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::Duration;
use tauri::{AppHandle, Manager, State};
use uuid::Uuid;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ReadyEvent {
    pub event: String,
    pub port: u16,
    pub token: String,
    pub url: String,
    pub version: String,
    pub build: String,
}

pub struct SidecarState {
    pub child: Mutex<Option<Child>>,
    pub ready: Mutex<Option<ReadyEvent>>,
}

impl SidecarState {
    pub fn new() -> Self {
        Self {
            child: Mutex::new(None),
            ready: Mutex::new(None),
        }
    }
}

/// Resolve the Python interpreter and argus_app.py for dev vs bundled builds.
fn resolve_sidecar_paths(app: &AppHandle) -> (PathBuf, PathBuf, PathBuf) {
    let resource_dir = app
        .path()
        .resource_dir()
        .unwrap_or_else(|_| PathBuf::from("."));

    // Production bundle: resources/python/python.exe + resources/argus_app.py
    let bundled_python = resource_dir.join("python").join("python.exe");
    let bundled_script = resource_dir.join("argus_app.py");

    if bundled_python.is_file() && bundled_script.is_file() {
        let workspace = default_workspace();
        return (bundled_python, bundled_script, workspace);
    }

    // Development: use system Python beside the repo root.
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let repo_root = manifest_dir.parent().unwrap_or(&manifest_dir).to_path_buf();
    let dev_script = repo_root.join("argus_app.py");

    let python = which_python();
    let workspace = default_workspace();

    (python, dev_script, workspace)
}

fn which_python() -> PathBuf {
    for candidate in ["python", "python3", "py"] {
        if let Ok(output) = Command::new(candidate)
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
        {
            if output.success() {
                return PathBuf::from(candidate);
            }
        }
    }
    PathBuf::from("python")
}

fn default_workspace() -> PathBuf {
    std::env::var("USERPROFILE")
        .map(|home| PathBuf::from(home).join("ARGUS"))
        .unwrap_or_else(|_| PathBuf::from("~/ARGUS"))
}

fn read_ready_line(reader: &mut BufReader<impl std::io::Read>) -> Option<ReadyEvent> {
    let mut line = String::new();
    loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => return None,
            Ok(_) => {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                if let Ok(evt) = serde_json::from_str::<ReadyEvent>(trimmed) {
                    if evt.event == "ready" {
                        return Some(evt);
                    }
                }
            }
            Err(_) => return None,
        }
    }
}

/// Start the Python sidecar and wait for its ready JSON line on stdout.
pub fn start_sidecar(app: &AppHandle) -> Result<ReadyEvent, String> {
    let (python, script, workspace) = resolve_sidecar_paths(app);

    if !script.is_file() {
        return Err(format!(
            "ARGUS sidecar script not found: {}",
            script.display()
        ));
    }

    let token = Uuid::new_v4().simple().to_string();

    let mut child = Command::new(&python)
        .arg(&script)
        .arg("--no-browser")
        .arg("--quiet")
        .arg("--ready-json")
        .arg("--port")
        .arg("0")
        .arg("--token")
        .arg(&token)
        .arg("--workspace")
        .arg(&workspace)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .current_dir(script.parent().unwrap_or(Path::new(".")))
        .spawn()
        .map_err(|e| {
            format!(
                "Failed to start Python sidecar ({}): {e}. \
                 Install Python 3.10+ or bundle an embeddable runtime.",
                python.display()
            )
        })?;

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "Sidecar stdout not captured".to_string())?;

    let mut reader = BufReader::new(stdout);
    let deadline = std::time::Instant::now() + Duration::from_secs(45);
    let ready = loop {
        if let Some(evt) = read_ready_line(&mut reader) {
            break evt;
        }
        if child.try_wait().ok().flatten().is_some() {
            return Err("Python sidecar exited before becoming ready".into());
        }
        if std::time::Instant::now() > deadline {
            let _ = child.kill();
            return Err("Timed out waiting for ARGUS sidecar (45s)".into());
        }
        std::thread::sleep(Duration::from_millis(100));
    };

    let state = app.state::<SidecarState>();
    *state.child.lock().unwrap() = Some(child);
    *state.ready.lock().unwrap() = Some(ready.clone());

    Ok(ready)
}

/// Gracefully stop the sidecar process tree.
pub fn stop_sidecar(state: &SidecarState) {
    let mut guard = state.child.lock().unwrap();
    if let Some(mut child) = guard.take() {
        #[cfg(windows)]
        {
            let id = child.id();
            let _ = std::process::Command::new("taskkill")
                .args(["/PID", &id.to_string(), "/T", "/F"])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status();
        }
        let _ = child.kill();
        let _ = child.wait();
    }
}

#[tauri::command]
pub fn sidecar_info(state: State<'_, SidecarState>) -> Option<ReadyEvent> {
    state.ready.lock().unwrap().clone()
}
