mod sidecar;
mod tray;

use sidecar::{start_sidecar, stop_sidecar, SidecarState};
use tauri::{Emitter, Manager, RunEvent};

fn navigate_main(app: &tauri::AppHandle, url: &str) -> Result<(), String> {
    let window = app
        .get_webview_window("main")
        .ok_or_else(|| "Main window not found".to_string())?;
    let parsed: url::Url = url
        .parse()
        .map_err(|e| format!("Invalid sidecar URL: {e}"))?;
    window
        .navigate(parsed)
        .map_err(|e| format!("Failed to navigate WebView: {e}"))?;
    window.show().map_err(|e| e.to_string())?;
    window.set_focus().map_err(|e| e.to_string())?;
    Ok(())
}

fn focus_main(app: &tauri::AppHandle) {
    if let Some(win) = app.get_webview_window("main") {
        let _ = win.show();
        let _ = win.set_focus();
        let _ = win.unminimize();
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let builder = tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .manage(SidecarState::new())
        .invoke_handler(tauri::generate_handler![sidecar::sidecar_info])
        .setup(|app| {
            tray::install_tray(app.handle())?;
            let handle = app.handle().clone();
            let ready = start_sidecar(&handle)?;
            navigate_main(&handle, &ready.url)?;
            Ok(())
        });

    #[cfg(desktop)]
    let builder = builder.plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
        focus_main(app);
    }));

    builder
        .build(tauri::generate_context!())
        .expect("error while building tauri application")
        .run(|app_handle, event| {
            match event {
                RunEvent::Exit => {
                    let state = app_handle.state::<SidecarState>();
                    stop_sidecar(&state);
                }
                RunEvent::WindowEvent {
                    label,
                    event: tauri::WindowEvent::CloseRequested { api, .. },
                    ..
                } if label == "main" => {
                    // Minimize to tray instead of killing an active extraction.
                    if let Some(win) = app_handle.get_webview_window("main") {
                        api.prevent_close();
                        let _ = win.hide();
                        let _ = app_handle.emit("tray-hide", ());
                    }
                }
                _ => {}
            }
        });
}
